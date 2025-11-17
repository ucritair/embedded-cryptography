#ifndef IPC_H
#define IPC_H

#include <stdint.h>

// --- Protocol Version ---
#define PROTOCOL_VERSION_MAJOR 1
#define PROTOCOL_VERSION_MINOR 0
#define PROTOCOL_VERSION_PATCH 0

// --- Firmware Version ---
// These are now defined by the build system

// --- Message Types ---
// Sent from Host to Device
typedef enum {
    MSG_TYPE_PROTOCOL_VERSION_QUERY = 0x00, // Special, fixed command for protocol discovery
    MSG_TYPE_SENSOR_DATA = 0x70,


    MSG_TYPE_WIFI_CONNECT = 0x51,
    MSG_TYPE_FIRMWARE_VERSION_QUERY = 0x5F,
    MSG_TYPE_WIFI_SCAN_REQUEST = 0x52,
    MSG_TYPE_REBOOT_TO_BOOTLOADER = 0x53,
    MSG_TYPE_ZKP_AUTHENTICATE = 0x54,
    MSG_TYPE_ZKP_SECRET_GET = 0x56,
    MSG_TYPE_ZKP_SECRET_SET = 0x57,
} host_to_device_msg_type_t;

// Sent from Device to Host
typedef enum {
    MSG_TYPE_PROTOCOL_VERSION_RESPONSE = 0x00,
    MSG_TYPE_SENSOR_DATA_ACK = 0x70, // DO NOT CHANGE-- Special, fixed command for protocol discovery

    MSG_TYPE_WIFI_CONNECT_ACK = 0x51,
    MSG_TYPE_FIRMWARE_VERSION_RESPONSE = 0x5F,
    MSG_TYPE_WIFI_SCAN_RESPONSE = 0x52,
    MSG_TYPE_REBOOT_TO_BOOTLOADER_ACK = 0x53,
    MSG_TYPE_ZKP_AUTHENTICATE_RESPONSE = 0x54,
    MSG_TYPE_ZKP_AUTH_STATUS = 0x55,  // Unsolicited status updates during auth
    MSG_TYPE_ZKP_SECRET_GET_RESPONSE = 0x56,
    MSG_TYPE_ZKP_SECRET_SET_ACK = 0x57,
} device_to_host_msg_type_t;

// --- Message Payloads ---

// Payload for version responses
typedef struct __attribute__((__packed__)) {
    uint32_t version;
} msg_payload_version_response_t;

// Payload for sensor data
#define NUM_SENSORS 5

typedef struct __attribute__((__packed__)) {
    uint32_t sensor_values[NUM_SENSORS];  // Array of 5 sensor values
} msg_payload_sensor_data_t;

// Payload for WiFi connect
#define MAX_SSID_LEN 32
#define MAX_PASSWORD_LEN 64

// WiFi auth modes (matches wifi_ap_record_t auth_mode)
#define WIFI_AUTH_OPEN          0
#define WIFI_AUTH_WEP           1
#define WIFI_AUTH_WPA           2
#define WIFI_AUTH_WPA2          3
#define WIFI_AUTH_WPA_WPA2      4

typedef struct __attribute__((__packed__)) {
    char ssid[MAX_SSID_LEN];
    char password[MAX_PASSWORD_LEN];
    uint8_t auth_mode;  // See WIFI_AUTH_* constants above
} msg_payload_wifi_connect_t;

// Payload for WiFi scan results
#define MAX_SCAN_RESULTS 10

typedef struct __attribute__((__packed__)) {
    char ssid[MAX_SSID_LEN];
    uint8_t bssid[6];
    int8_t rssi;           // Signal strength in dBm
    uint8_t channel;
    uint8_t auth_mode;     // 0=Open, 1=WEP, 2=WPA, 3=WPA2, 4=WPA/WPA2
} wifi_ap_record_t;

typedef struct __attribute__((__packed__)) {
    uint8_t count;         // Number of APs found (up to MAX_SCAN_RESULTS)
    wifi_ap_record_t aps[MAX_SCAN_RESULTS];
} msg_payload_wifi_scan_response_t;

// Payload for ZKP authentication request
// Empty payload - device uses hardcoded secret and server hostname
typedef struct __attribute__((__packed__)) {
    // No fields - command is stateless
} msg_payload_zkp_authenticate_request_t;

// Payload for ZKP authentication response
#define MAX_ACCESS_TOKEN_LEN 512
#define MAX_TIMESTAMP_LEN 32
#define MAX_ZKP_SECRET_LEN 256

typedef struct __attribute__((__packed__)) {
    uint8_t success;       // 1 if authentication successful, 0 if failed
    char access_token[MAX_ACCESS_TOKEN_LEN];
    char expires_at[MAX_TIMESTAMP_LEN];
} msg_payload_zkp_authenticate_response_t;

// Payload for ZKP secret set (host -> device)
typedef struct __attribute__((__packed__)) {
    char secret_b64[MAX_ZKP_SECRET_LEN];  // Base64-encoded secret
} msg_payload_zkp_secret_set_t;

// Payload for ZKP secret get response (device -> host)
typedef struct __attribute__((__packed__)) {
    char secret_b64[MAX_ZKP_SECRET_LEN];  // Base64-encoded secret
} msg_payload_zkp_secret_get_response_t;

// Payload for ZKP authentication status updates (unsolicited)
#define MAX_STATUS_MESSAGE_LEN 128

// Stage definitions
#define ZKP_STAGE_NONCE 1
#define ZKP_STAGE_PARENT 2
#define ZKP_STAGE_WITNESS 3
#define ZKP_STAGE_PROOF 4
#define ZKP_STAGE_VERIFY 5

typedef struct __attribute__((__packed__)) {
    uint8_t stage;         // Current stage (1=nonce, 2=parent, 3=witness, 4=proof, 5=verify)
    uint8_t progress;      // Progress percentage (0-100)
    char message[MAX_STATUS_MESSAGE_LEN];  // Human-readable status message
} msg_payload_zkp_auth_status_t;


#endif // IPC_H
