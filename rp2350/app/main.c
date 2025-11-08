#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "pico/stdlib.h"
#include "hardware/uart.h"
#include "TinyFrame.h"
#include "tf_port.h"
#include "ipc.h"

#include "pico/cyw43_arch.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/netif.h"

#include "FreeRTOS.h"
#include "task.h"

#include "httpss_client.h"
#include "lwip/apps/sntp.h"
#include <time.h>

// Global variables for WiFi credentials
static char wifi_ssid[MAX_SSID_LEN + 1];
static char wifi_password[MAX_PASSWORD_LEN + 1];

// Time synchronization state
static uint64_t sntp_sync_time_us = 0;
static time_t sntp_sync_time_sec = 0;


typedef enum {
    APP_STATE_WAIT_CREDENTIALS,
    APP_STATE_CONNECTING_WIFI,
    APP_STATE_WIFI_CONNECTED,
    APP_STATE_WIFI_CONNECTED_IDLE,
} app_state_t;

static app_state_t app_state = APP_STATE_WAIT_CREDENTIALS;

void sntp_init_func(void)
{
    printf("Initializing SNTP...\n");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_init();
    printf("SNTP initialized.\n");
}

// Callback function called by SNTP client when time is synchronized
void sntp_set_system_time(u32_t sec)
{
    if (sec > 0) {
        sntp_sync_time_sec = sec;
        sntp_sync_time_us = time_us_64();
        
        char buf[32];
        time_t now = sntp_sync_time_sec;
        struct tm* utc = gmtime(&now);
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", utc);
        printf("SNTP time synchronized: %s\n", buf);
    }
}

// Override for the C library's time function
int _gettimeofday(struct timeval *tv, void *tz) {
    if (sntp_sync_time_sec > 0) {
        // Time has been synchronized
        uint64_t current_us = time_us_64();
        uint64_t elapsed_us = current_us - sntp_sync_time_us;
        tv->tv_sec = sntp_sync_time_sec + (elapsed_us / 1000000);
        tv->tv_usec = (elapsed_us % 1000000);
    } else {
        // Time not synchronized yet, return 0 or a boot-based time
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }
    return 0;
}


// Task priorities
#define MAIN_TASK_PRIORITY      ( tskIDLE_PRIORITY + 1UL )
#define CRYPTO_TASK_PRIORITY    ( tskIDLE_PRIORITY + 2UL )

// Task stack sizes
#define MAIN_TASK_STACK_SIZE 1024
#define CRYPTO_TASK_STACK_SIZE 2048

static bool connect_to_wifi(uint8_t auth_mode)
{
    // Map our simple auth mode to CYW43 auth constants
    uint32_t cyw43_auth;
    switch (auth_mode) {
        case WIFI_AUTH_OPEN:
            cyw43_auth = CYW43_AUTH_OPEN;
            break;
        case WIFI_AUTH_WPA:
            cyw43_auth = CYW43_AUTH_WPA_TKIP_PSK;
            break;
        case WIFI_AUTH_WPA2:
            cyw43_auth = CYW43_AUTH_WPA2_AES_PSK;
            break;
        case WIFI_AUTH_WPA_WPA2:
            cyw43_auth = CYW43_AUTH_WPA2_MIXED_PSK;
            break;
        default:
            printf("Unknown auth mode: %u, defaulting to WPA2\n", auth_mode);
            cyw43_auth = CYW43_AUTH_WPA2_AES_PSK;
            break;
    }

    printf("Connecting to Wi-Fi (SSID: %s, Auth: %u)...\n", wifi_ssid, auth_mode);
    if (cyw43_arch_wifi_connect_timeout_ms(wifi_ssid, wifi_password, cyw43_auth, 30000)) {
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
 * Listener for WiFi connect request (type MSG_TYPE_WIFI_CONNECT)
 */
TF_Result wifi_connect_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received WiFi connect request. Attempting to connect (this will block)...\n");

    if (msg->len == sizeof(msg_payload_wifi_connect_t)) {
        // Copy credentials from payload
        msg_payload_wifi_connect_t *credentials = (msg_payload_wifi_connect_t *)msg->data;
        strncpy(wifi_ssid, credentials->ssid, MAX_SSID_LEN);
        wifi_ssid[MAX_SSID_LEN] = '\0';
        strncpy(wifi_password, credentials->password, MAX_PASSWORD_LEN);
        wifi_password[MAX_PASSWORD_LEN] = '\0';

        // Perform the blocking connection attempt with specified auth mode
        if (connect_to_wifi(credentials->auth_mode)) {
            // On success, update state and send ACK
            app_state = APP_STATE_WIFI_CONNECTED_IDLE;
            TF_Respond(tf, msg); // ACK indicates success
        } else {
            // On failure, do not send an ACK. The host will time out.
            app_state = APP_STATE_WAIT_CREDENTIALS; // Go back to waiting
        }
    } else {
        printf("Received WiFi connect with invalid payload size: %u (expected %u)\n",
               msg->len, sizeof(msg_payload_wifi_connect_t));
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

// WiFi scan state
static msg_payload_wifi_scan_response_t scan_results = {0};
static volatile bool scan_in_progress = false;

/**
 * WiFi scan callback - called for each AP found
 */
static int scan_result_callback(void *env, const cyw43_ev_scan_result_t *result)
{
    if (!result || scan_results.count >= MAX_SCAN_RESULTS) {
        return 0;
    }

    // Check if this BSSID already exists (deduplicate by MAC address)
    for (int i = 0; i < scan_results.count; i++) {
        if (memcmp(scan_results.aps[i].bssid, result->bssid, 6) == 0) {
            // Already have this AP, update RSSI if stronger
            if (result->rssi > scan_results.aps[i].rssi) {
                scan_results.aps[i].rssi = result->rssi;
            }
            return 0;
        }
    }

    // New AP - add it
    wifi_ap_record_t *ap = &scan_results.aps[scan_results.count];

    // Copy SSID
    size_t ssid_len = result->ssid_len;
    if (ssid_len > MAX_SSID_LEN - 1) ssid_len = MAX_SSID_LEN - 1;
    memcpy(ap->ssid, result->ssid, ssid_len);
    ap->ssid[ssid_len] = '\0';

    // Copy BSSID
    memcpy(ap->bssid, result->bssid, 6);

    // RSSI
    ap->rssi = result->rssi;

    // Channel
    ap->channel = result->channel;

    // Auth mode (simplified mapping)
    if (result->auth_mode == 0) {
        ap->auth_mode = 0; // Open
    } else if (result->auth_mode & 0x00400000) {
        ap->auth_mode = 3; // WPA2
    } else if (result->auth_mode & 0x00200000) {
        ap->auth_mode = 2; // WPA
    } else {
        ap->auth_mode = 1; // WEP or other
    }

    scan_results.count++;
    printf("  Found: %s [%02X:%02X:%02X:%02X:%02X:%02X] (RSSI: %d dBm, Ch: %d)\n",
           ap->ssid,
           ap->bssid[0], ap->bssid[1], ap->bssid[2],
           ap->bssid[3], ap->bssid[4], ap->bssid[5],
           ap->rssi, ap->channel);

    return 0;
}

/**
 * Listener for WiFi scan request (type MSG_TYPE_WIFI_SCAN_REQUEST)
 */
TF_Result wifi_scan_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received WiFi scan request\n");

    if (scan_in_progress) {
        printf("Scan already in progress\n");
        // Send empty response
        scan_results.count = 0;
        msg->data = (const uint8_t *)&scan_results;
        msg->len = sizeof(scan_results);
        TF_Respond(tf, msg);
        return TF_STAY;
    }

    // Reset scan results
    memset(&scan_results, 0, sizeof(scan_results));
    scan_in_progress = true;

    // Perform WiFi scan with extended options
    printf("Starting WiFi scan (this may take 10-15 seconds)...\n");
    cyw43_wifi_scan_options_t scan_options = {
        .scan_type = 0,  // Active scan
    };
    int err = cyw43_wifi_scan(&cyw43_state, &scan_options, NULL, scan_result_callback);

    if (err == 0) {
        // Wait for scan to complete (allow longer time for thorough scan)
        // Typical scan: ~1-2 seconds per channel, ~13 channels = up to 26 seconds
        int timeout = 200; // 20 seconds timeout
        int elapsed = 0;
        while (cyw43_wifi_scan_active(&cyw43_state) && timeout > 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            timeout--;
            elapsed++;
            if (elapsed % 10 == 0) {
                printf("  Scanning... (%d seconds elapsed)\n", elapsed / 10);
            }
        }

        if (timeout == 0) {
            printf("WiFi scan timed out after 20 seconds\n");
        } else {
            printf("WiFi scan complete in %d seconds. Found %d unique APs\n", elapsed / 10, scan_results.count);
        }
    } else {
        printf("WiFi scan failed with error: %d\n", err);
        scan_results.count = 0;
    }

    scan_in_progress = false;

    // Send response
    msg->data = (const uint8_t *)&scan_results;
    msg->len = sizeof(scan_results);
    TF_Respond(tf, msg);

    return TF_STAY;
}

/**
 * Listener for reboot to bootloader request (type MSG_TYPE_REBOOT_TO_BOOTLOADER)
 */
TF_Result reboot_to_bootloader_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received reboot to bootloader request\n");

    // Send ACK first
    TF_Respond(tf, msg);

    // Give time for ACK to be sent
    vTaskDelay(pdMS_TO_TICKS(100));

    printf("Rebooting into USB bootloader mode...\n");

    // For RP2350, use the ROM function directly
    // This is equivalent to holding BOOTSEL during reset
    rom_reset_usb_boot_extra(0, 0, 0);

    // Should never reach here
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

// rust FFI
#include "include/battery.h"
#include "battery_e2e.h"

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

void main_task(__unused void *params) {
    stdio_init_all();
    tf_port_init();

    printf("Hello, Pico!\n");

    // Add a delay to allow for UART connection
    for (int i = 0; i < 5; i++) {
        printf("Waiting for UART...\n");
        vTaskDelay(1000);
    }
 
    printf("Querying Rust library version...\n");
    printf("battery_api_version(): 0x%X\n", battery_api_version());

    init_psram();
    rust_heap_init(PSRAM_BASE_ADDRESS, PSRAM_SIZE_BYTES);

    if (cyw43_arch_init()) {
        printf("failed to initialise cyw43_arch\n");
        return;
    }

    cyw43_arch_enable_sta_mode();

    // Initialize TinyFrame
    tf = TF_Init(TF_MASTER);
    TF_AddTypeListener(tf, MSG_TYPE_FIRMWARE_VERSION_QUERY, firmware_version_listener);
    TF_AddTypeListener(tf, MSG_TYPE_PROTOCOL_VERSION_QUERY, protocol_version_listener);
    TF_AddTypeListener(tf, MSG_TYPE_WIFI_CONNECT, wifi_connect_listener);
    TF_AddTypeListener(tf, MSG_TYPE_SENSOR_DATA, sensor_data_listener);
    TF_AddTypeListener(tf, MSG_TYPE_WIFI_SCAN_REQUEST, wifi_scan_listener);
    TF_AddTypeListener(tf, MSG_TYPE_REBOOT_TO_BOOTLOADER, reboot_to_bootloader_listener);

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

        vTaskDelay(1);
    }
}

int main(void) {
    // Start the main thread
    xTaskCreate(main_task, "MainThread", MAIN_TASK_STACK_SIZE, NULL, MAIN_TASK_PRIORITY, NULL);
    vTaskStartScheduler();

    return 0;
}
