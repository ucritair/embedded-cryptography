#ifndef IPC_H
#define IPC_H

#include <stdint.h>

// --- Protocol Version ---
#define PROTOCOL_VERSION_MAJOR 1
#define PROTOCOL_VERSION_MINOR 0
#define PROTOCOL_VERSION_PATCH 0

// --- Firmware Version ---
#define FIRMWARE_VERSION_MAJOR 1
#define FIRMWARE_VERSION_MINOR 0
#define FIRMWARE_VERSION_PATCH 0

// --- Message Types ---
// Sent from Host to Device
typedef enum {
    MSG_TYPE_PROTOCOL_VERSION_QUERY = 0x00, // Special, fixed command for protocol discovery
    MSG_TYPE_SENSOR_DATA = 0x70,


    MSG_TYPE_SET_WIFI_CREDENTIALS = 0x51,
    MSG_TYPE_FIRMWARE_VERSION_QUERY = 0x5F,
} host_to_device_msg_type_t;

// Sent from Device to Host
typedef enum {
    MSG_TYPE_PROTOCOL_VERSION_RESPONSE = 0x00,
    MSG_TYPE_SENSOR_DATA_ACK = 0x70, // DO NOT CHANGE-- Special, fixed command for protocol discovery

    MSG_TYPE_SET_WIFI_CREDENTIALS_ACK = 0x51,
    MSG_TYPE_FIRMWARE_VERSION_RESPONSE = 0x5F,
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

// Payload for setting WiFi credentials
#define MAX_SSID_LEN 32
#define MAX_PASSWORD_LEN 64

typedef struct __attribute__((__packed__)) {
    char ssid[MAX_SSID_LEN];
    char password[MAX_PASSWORD_LEN];
} msg_payload_set_wifi_credentials_t;


#endif // IPC_H
