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


int main() {
    stdio_init_all();
    tf_port_init();

    printf("Hello, Pico!\n");

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
    }

    cyw43_arch_deinit(); // De-initialize CYW43 on exit
    return 0;
}