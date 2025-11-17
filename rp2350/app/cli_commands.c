#include "FreeRTOS.h"
#include "task.h"
#include "FreeRTOS_CLI.h"
#include "pico/stdlib.h"
#include <string.h>
#include <stdlib.h>
#include "TinyFrame.h"
#include "ipc.h"

extern char g_zkp_secret_b64[];
extern TinyFrame *tf;

static BaseType_t prvHelpCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString);
static BaseType_t prvStatusCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString);
static BaseType_t prvGetSecretCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString);
static BaseType_t prvSetSecretCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString);
static BaseType_t prvWifiConnectCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString);
static BaseType_t prvZkpAuthCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString);
static BaseType_t prvSensorDataCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString);

static const CLI_Command_Definition_t xHelpCommand = {
    "help", "help: Lists all commands\r\n", prvHelpCommand, 0
};

static const CLI_Command_Definition_t xStatusCommand = {
    "status", "status: Show system status\r\n", prvStatusCommand, 0
};

static const CLI_Command_Definition_t xGetSecretCommand = {
    "get_secret", "get_secret: Show current ZKP secret\r\n", prvGetSecretCommand, 0
};

static const CLI_Command_Definition_t xSetSecretCommand = {
    "set_secret", "set_secret <base64_secret>: Set ZKP secret\r\n", prvSetSecretCommand, 1
};

static const CLI_Command_Definition_t xWifiConnectCommand = {
    "wifi_connect", "wifi_connect <ssid> <password>: Connect to WiFi\r\n", prvWifiConnectCommand, 2
};

static const CLI_Command_Definition_t xZkpAuthCommand = {
    "zkp_auth", "zkp_auth: Perform ZKP authentication\r\n", prvZkpAuthCommand, 0
};

static const CLI_Command_Definition_t xSensorDataCommand = {
    "sensor_data", "sensor_data <val1> <val2> <val3> <val4> <val5>: Send sensor data\r\n", prvSensorDataCommand, 5
};

static BaseType_t prvHelpCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString) {
    (void)pcCommandString;
    strncpy(pcWriteBuffer, "Commands: help, status, get_secret, set_secret, wifi_connect, zkp_auth, sensor_data\r\n", xWriteBufferLen);
    return pdFALSE;
}

static BaseType_t prvStatusCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString) {
    (void)pcCommandString;
    snprintf(pcWriteBuffer, xWriteBufferLen, "System OK - Free heap: %u bytes\r\n", 
             (unsigned int)xPortGetFreeHeapSize());
    return pdFALSE;
}

static BaseType_t prvGetSecretCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString) {
    (void)pcCommandString;
    snprintf(pcWriteBuffer, xWriteBufferLen, "Current secret: %s\r\n", g_zkp_secret_b64);
    return pdFALSE;
}

static BaseType_t prvSetSecretCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString) {
    const char *param;
    BaseType_t paramLen;
    
    param = FreeRTOS_CLIGetParameter(pcCommandString, 1, &paramLen);
    
    if (param == NULL || paramLen == 0) {
        strncpy(pcWriteBuffer, "Error: Missing secret parameter\r\n", xWriteBufferLen);
        return pdFALSE;
    }
    
    if (paramLen >= 256) {
        strncpy(pcWriteBuffer, "Error: Secret too long (max 255 chars)\r\n", xWriteBufferLen);
        return pdFALSE;
    }
    
    strncpy(g_zkp_secret_b64, param, paramLen);
    g_zkp_secret_b64[paramLen] = '\0';
    
    snprintf(pcWriteBuffer, xWriteBufferLen, "Secret updated: %s\r\n", g_zkp_secret_b64);
    return pdFALSE;
}

static BaseType_t prvWifiConnectCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString) {
    const char *ssid, *password;
    BaseType_t ssidLen, passwordLen;
    
    ssid = FreeRTOS_CLIGetParameter(pcCommandString, 1, &ssidLen);
    password = FreeRTOS_CLIGetParameter(pcCommandString, 2, &passwordLen);
    
    if (!ssid || !password || ssidLen == 0 || passwordLen == 0) {
        strncpy(pcWriteBuffer, "Error: Missing SSID or password\r\n", xWriteBufferLen);
        return pdFALSE;
    }
    
    msg_payload_wifi_connect_t wifi_credentials = {0};
    strncpy(wifi_credentials.ssid, ssid, ssidLen < MAX_SSID_LEN ? ssidLen : MAX_SSID_LEN);
    strncpy(wifi_credentials.password, password, passwordLen < MAX_PASSWORD_LEN ? passwordLen : MAX_PASSWORD_LEN);
    wifi_credentials.auth_mode = WIFI_AUTH_WPA2;
    
    TF_Msg connect_msg = {0};
    connect_msg.type = MSG_TYPE_WIFI_CONNECT;
    connect_msg.data = (const uint8_t*)&wifi_credentials;
    connect_msg.len = sizeof(wifi_credentials);
    
    printf("Connecting to WiFi: %.*s\r\n", ssidLen, ssid);
    
    // Call the existing listener directly
    extern TF_Result wifi_connect_listener(TinyFrame *tf, TF_Msg *msg);
    wifi_connect_listener(tf, &connect_msg);
    
    strncpy(pcWriteBuffer, "WiFi connection initiated\r\n", xWriteBufferLen);
    return pdFALSE;
}

static BaseType_t prvZkpAuthCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString) {
    (void)pcCommandString;
    
    TF_Msg zkp_msg = {0};
    zkp_msg.type = MSG_TYPE_ZKP_AUTHENTICATE;
    zkp_msg.data = NULL;
    zkp_msg.len = 0;
    
    printf("Starting ZKP authentication\r\n");
    
    // Call the existing listener directly
    extern TF_Result zkp_authenticate_listener(TinyFrame *tf, TF_Msg *msg);
    zkp_authenticate_listener(tf, &zkp_msg);
    
    strncpy(pcWriteBuffer, "ZKP authentication initiated\r\n", xWriteBufferLen);
    return pdFALSE;
}

static BaseType_t prvSensorDataCommand(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString) {
    msg_payload_sensor_data_t sensor_data = {0};
    
    // Parse 5 sensor values
    for (int i = 0; i < NUM_SENSORS; i++) {
        const char *param = FreeRTOS_CLIGetParameter(pcCommandString, i + 1, NULL);
        if (!param) {
            snprintf(pcWriteBuffer, xWriteBufferLen, "Error: Need %d sensor values\r\n", NUM_SENSORS);
            return pdFALSE;
        }
        sensor_data.sensor_values[i] = atoi(param);
    }
    
    TF_Msg sensor_msg = {0};
    sensor_msg.type = MSG_TYPE_SENSOR_DATA;
    sensor_msg.data = (const uint8_t*)&sensor_data;
    sensor_msg.len = sizeof(sensor_data);
    
    printf("Sending sensor data: [%u,%u,%u,%u,%u]\r\n", 
           sensor_data.sensor_values[0], sensor_data.sensor_values[1], 
           sensor_data.sensor_values[2], sensor_data.sensor_values[3], 
           sensor_data.sensor_values[4]);
    
    // Call the existing listener directly
    extern TF_Result sensor_data_listener(TinyFrame *tf, TF_Msg *msg);
    sensor_data_listener(tf, &sensor_msg);
    
    strncpy(pcWriteBuffer, "Sensor data sent\r\n", xWriteBufferLen);
    return pdFALSE;
}

void vRegisterCLICommands(void) {
    FreeRTOS_CLIRegisterCommand(&xHelpCommand);
    FreeRTOS_CLIRegisterCommand(&xStatusCommand);
    FreeRTOS_CLIRegisterCommand(&xGetSecretCommand);
    FreeRTOS_CLIRegisterCommand(&xSetSecretCommand);
    FreeRTOS_CLIRegisterCommand(&xWifiConnectCommand);
    FreeRTOS_CLIRegisterCommand(&xZkpAuthCommand);
    FreeRTOS_CLIRegisterCommand(&xSensorDataCommand);
}

void vCLITask(void *pvParameters) {
    char cRxedChar, cInputString[300], cOutputString[400];
    BaseType_t xInputIndex = 0, xReturned;
    
    (void)pvParameters;
    
    // Wait for USB to be ready
    vTaskDelay(pdMS_TO_TICKS(2000));
    
    printf("CLI Ready. Type 'help' for commands.\r\n> ");
    
    for(;;) {
        int c = getchar_timeout_us(1000);  // 1ms timeout instead of 0
        if(c != PICO_ERROR_TIMEOUT) {
            cRxedChar = (char)c;
            
            if(cRxedChar == '\n' || cRxedChar == '\r') {
                printf("\r\n");
                cInputString[xInputIndex] = '\0';
                
                if(xInputIndex > 0) {
                    do {
                        xReturned = FreeRTOS_CLIProcessCommand(cInputString, cOutputString, sizeof(cOutputString));
                        printf("%s", cOutputString);
                    } while(xReturned != pdFALSE);
                }
                
                xInputIndex = 0;
                printf("> ");
            } else if(cRxedChar == '\b' || cRxedChar == 127) {
                if(xInputIndex > 0) {
                    xInputIndex--;
                    printf("\b \b");
                }
            } else if(cRxedChar >= 32 && cRxedChar < 127 && xInputIndex < sizeof(cInputString) - 1) {
                cInputString[xInputIndex++] = cRxedChar;
                printf("%c", cRxedChar);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1));  // Small delay to prevent hogging CPU
    }
}
