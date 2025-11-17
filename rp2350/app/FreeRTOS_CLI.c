#include "FreeRTOS_CLI.h"
#include <string.h>

#define MAX_COMMANDS 10

static const CLI_Command_Definition_t *commands[MAX_COMMANDS];
static int command_count = 0;

BaseType_t FreeRTOS_CLIRegisterCommand(const CLI_Command_Definition_t *pxCommandToRegister) {
    if (command_count < MAX_COMMANDS) {
        commands[command_count++] = pxCommandToRegister;
        return pdPASS;
    }
    return pdFAIL;
}

BaseType_t FreeRTOS_CLIProcessCommand(const char *pcCommandInput, char *pcWriteBuffer, size_t xWriteBufferLen) {
    const char *cmd_start = pcCommandInput;
    while (*cmd_start == ' ') cmd_start++;
    
    for (int i = 0; i < command_count; i++) {
        size_t cmd_len = strlen(commands[i]->pcCommand);
        if (strncmp(cmd_start, commands[i]->pcCommand, cmd_len) == 0 &&
            (cmd_start[cmd_len] == ' ' || cmd_start[cmd_len] == '\0')) {
            return commands[i]->pxCommandInterpreter(pcWriteBuffer, xWriteBufferLen, pcCommandInput);
        }
    }
    
    strncpy(pcWriteBuffer, "Unknown command. Type 'help' for available commands.\r\n", xWriteBufferLen);
    return pdFALSE;
}

const char *FreeRTOS_CLIGetParameter(const char *pcCommandString, UBaseType_t uxWantedParameter, BaseType_t *pxParameterStringLength) {
    static const char *param_start = NULL;
    const char *p = pcCommandString;
    UBaseType_t param_count = 0;
    
    // Skip command name
    while (*p && *p != ' ') p++;
    while (*p == ' ') p++;
    
    // Find the requested parameter
    while (*p && param_count < uxWantedParameter) {
        if (param_count + 1 == uxWantedParameter) {
            param_start = p;
            break;
        }
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
        param_count++;
    }
    
    if (param_count + 1 != uxWantedParameter || !*p) {
        *pxParameterStringLength = 0;
        return NULL;
    }
    
    // Calculate parameter length
    const char *param_end = p;
    while (*param_end && *param_end != ' ') param_end++;
    
    *pxParameterStringLength = param_end - param_start;
    return param_start;
}
