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
} host_to_device_msg_type_t;

// Sent from Device to Host
typedef enum {
    MSG_TYPE_PROTOCOL_VERSION_RESPONSE = 0x00,
    MSG_TYPE_SENSOR_DATA_ACK = 0x70, // DO NOT CHANGE-- Special, fixed command for protocol discovery

    MSG_TYPE_WIFI_CONNECT_ACK = 0x51,
    MSG_TYPE_FIRMWARE_VERSION_RESPONSE = 0x5F,
    MSG_TYPE_WIFI_SCAN_RESPONSE = 0x52,
    MSG_TYPE_REBOOT_TO_BOOTLOADER_ACK = 0x53,
} device_to_host_msg_type_t;

// --- Message Payloads ---

// Payload for version responses
typedef struct __attribute__((__packed__)) {
    uint32_t version;
} msg_payload_version_response_t;

// Payload for sensor data
typedef struct __attribute__((__packed__)) {
    uint32_t sensor_value;
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


#endif // IPC_H
