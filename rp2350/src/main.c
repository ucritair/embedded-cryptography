#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/uart.h"
#include "TinyFrame.h"
#include "tf_port.h"
#include "ipc.h"

#include "pico/cyw43_arch.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/netif.h"

// Global variables for WiFi credentials
static char wifi_ssid[MAX_SSID_LEN + 1];
static char wifi_password[MAX_PASSWORD_LEN + 1];
static bool wifi_credentials_set = false;

typedef enum {
    APP_STATE_WAIT_CREDENTIALS,
    APP_STATE_CONNECTING_WIFI,
    APP_STATE_WIFI_CONNECTED,
    APP_STATE_WIFI_CONNECTED_IDLE,
} app_state_t;

static app_state_t app_state = APP_STATE_WAIT_CREDENTIALS;

static bool connect_to_wifi(void)
{
    printf("Connecting to Wi-Fi...\n");
    if (cyw43_arch_wifi_connect_timeout_ms(wifi_ssid, wifi_password, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("failed to connect to Wi-Fi.\n");
        return false;
    } else {
        printf("Connected to Wi-Fi.\n");
        return true;
    }
}

// TinyFrame instance
static TinyFrame *tf;

/**
 * Listener for the firmware version query
 */
TF_Result firmware_version_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received firmware version query.\n");
    static msg_payload_version_response_t response;
    response.version = (FIRMWARE_VERSION_MAJOR << 24) | (FIRMWARE_VERSION_MINOR << 16) | FIRMWARE_VERSION_PATCH;

    msg->data = (const uint8_t *)&response;
    msg->len = sizeof(response);
    TF_Respond(tf, msg);
    return TF_STAY;
}

/**
 * Listener for the protocol version query
 */
TF_Result protocol_version_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received protocol version query.\n");
    static msg_payload_version_response_t response;
    response.version = (PROTOCOL_VERSION_MAJOR << 24) | (PROTOCOL_VERSION_MINOR << 16) | PROTOCOL_VERSION_PATCH;

    msg->data = (const uint8_t *)&response;
    msg->len = sizeof(response);
    TF_Respond(tf, msg);
    return TF_STAY;
}

/**
 * Listener for setting WiFi credentials (type MSG_TYPE_SET_WIFI_CREDENTIALS)
 */
TF_Result set_wifi_credentials_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received WiFi credentials. Attempting to connect (this will block)...\n");

    if (msg->len == sizeof(msg_payload_set_wifi_credentials_t)) {
        // Copy credentials from payload
        msg_payload_set_wifi_credentials_t *credentials = (msg_payload_set_wifi_credentials_t *)msg->data;
        strncpy(wifi_ssid, credentials->ssid, MAX_SSID_LEN);
        wifi_ssid[MAX_SSID_LEN] = '\0';
        strncpy(wifi_password, credentials->password, MAX_PASSWORD_LEN);
        wifi_password[MAX_PASSWORD_LEN] = '\0';

        // Perform the blocking connection attempt
        if (connect_to_wifi()) {
            // On success, update state and send ACK
            app_state = APP_STATE_WIFI_CONNECTED_IDLE;
            TF_Respond(tf, msg); // ACK indicates success
        } else {
            // On failure, do not send an ACK. The host will time out.
            app_state = APP_STATE_WAIT_CREDENTIALS; // Go back to waiting
        }
    } else {
        printf("Received WiFi credentials with invalid payload size: %u\n", msg->len);
    }
    return TF_STAY;
}

/**
 * Listener for sensor data (type MSG_TYPE_SENSOR_DATA)
 */
TF_Result sensor_data_listener(TinyFrame *tf, TF_Msg *msg)
{
    if (msg->len == sizeof(msg_payload_sensor_data_t)) {
        msg_payload_sensor_data_t *payload = (msg_payload_sensor_data_t *)msg->data;
        printf("Received sensor data with value: %u\n", payload->sensor_value);
        
        // Acknowledge the message
        TF_Respond(tf, msg);
    } else {
        printf("Received sensor data with invalid payload size: %u\n", msg->len);
    }
    return TF_STAY;
}

#include "hardware/xip_cache.h"
#include "hardware/regs/addressmap.h"
#include "hardware/regs/qmi.h"
#include "hardware/regs/xip.h"
#include "hardware/structs/xip_ctrl.h"
#include "hardware/structs/qmi.h"
#include "hardware/structs/xip_ctrl.h"

#include "pico/multicore.h"

// Base address of the PSRAM/Flash mapped in XIP (cached)
// 0x15000000 for uncached
#define PSRAM_BASE_ADDRESS   0x11000000
#define UCPSRAM_BASE_ADDRESS 0x15000000

// Size of the PSRAM (8 MB = 8 * 1024 * 1024 bytes)
#define PSRAM_SIZE_BYTES (8 * 1024 * 1024)


// last address of PSRAM
#define PSRAM_TOP (PSRAM_BASE_ADDRESS + (PSRAM_SIZE_BYTES - 1))


// PSRA alternate stack size (1MB)
#define PSRAM_STACK_SIZE (1 * 1024 * 1024)

// PSRAM alternate stack bottom address
#define PSRAM_STACK_BOT (PSRAM_TOP + 1) - PSRAM_STACK_SIZE

// RP2350B pin 58 is GPIO 47
// GPIO 47 as CS
#define PSRAM_CS_PIN 47

uint8_t* psram = (uint8_t*)PSRAM_BASE_ADDRESS;
uint8_t* uc_psram = (uint8_t*)UCPSRAM_BASE_ADDRESS;

void init_psram()
{
	gpio_set_function(PSRAM_CS_PIN, GPIO_FUNC_XIP_CS1); // Set GPIO 47 as CS pin
	xip_ctrl_hw->ctrl |= XIP_CTRL_WRITABLE_M1_BITS;     // Configure XIP controller for writable M1 region
}

void core1_battery_e2e ()
{
	battery_e2e();

	printf(">>> CORE1 DONE, SPINNING <<<\n");
	while ( true )
	{
		sleep_ms(1000);
	}
}

void do_crypto_ops(void) {
	printf("Doing Crypto on Core 1. [PSRAM_STACK_BOT: 0x%x] [PSRAM_STACK_SIZE: 0x%x]...\n", PSRAM_STACK_BOT, PSRAM_STACK_SIZE);
	multicore_reset_core1();

	// FIXME: we are only doing this to quickly change the stack location to PSRAM
	//	instead implement a stack pointer and restore so this can be run on core0 and free up core1
	multicore_launch_core1_with_stack(core1_battery_e2e, (uint32_t *)PSRAM_STACK_BOT, PSRAM_STACK_SIZE);
}

int main() {
    stdio_init_all();
    tf_port_init();

    printf("Hello, Pico!\n");

    // Add a delay to allow for UART connection
    for (int i = 0; i < 5; i++) {
        printf("Waiting for UART...\n");
        sleep_ms(1000);
    }
 
    printf("Querying Rust library version...\n");
    printf("battery_api_version(): 0x%X\n", battery_api_version());

    init_psram();
    griffon_heap_init(PSRAM_BASE_ADDRESS, PSRAM_SIZE_BYTES);

    if (cyw43_arch_init()) {
        printf("failed to initialise cyw43_arch\n");
        return 1;
    }

    cyw43_arch_enable_sta_mode();

    // Initialize TinyFrame
    tf = TF_Init(TF_MASTER);
    TF_AddTypeListener(tf, MSG_TYPE_FIRMWARE_VERSION_QUERY, firmware_version_listener);
    TF_AddTypeListener(tf, MSG_TYPE_PROTOCOL_VERSION_QUERY, protocol_version_listener);
    TF_AddTypeListener(tf, MSG_TYPE_SET_WIFI_CREDENTIALS, set_wifi_credentials_listener);
    TF_AddTypeListener(tf, MSG_TYPE_SENSOR_DATA, sensor_data_listener);

    int i = 0;
    while (true) {
        // TinyFrame processing
        while (uart_is_readable(uart0)) {
            uint8_t ch = uart_getc(uart0);
            TF_Accept(tf, &ch, 1);
        }

        switch (app_state) {
            case APP_STATE_WAIT_CREDENTIALS:
                // Do nothing, the listener now handles connection triggering.
                break;

            case APP_STATE_CONNECTING_WIFI:
                // This state is no longer used.
                break;

            case APP_STATE_WIFI_CONNECTED:
                // no-op for now..
                break;
        }

        if (i == 0) {
            printf("Running Crypto Test \n");
            do_crypto_ops();
            i = 1;
        }
    }

    cyw43_arch_deinit(); // De-initialize CYW43 on exit
    return 0;
}