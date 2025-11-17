#ifndef FREERTOS_CLI_H
#define FREERTOS_CLI_H

#include "FreeRTOS.h"

typedef struct {
    const char *pcCommand;
    const char *pcHelpString;
    BaseType_t (*pxCommandInterpreter)(char *pcWriteBuffer, size_t xWriteBufferLen, const char *pcCommandString);
    int8_t cExpectedNumberOfParameters;
} CLI_Command_Definition_t;

BaseType_t FreeRTOS_CLIRegisterCommand(const CLI_Command_Definition_t *pxCommandToRegister);
BaseType_t FreeRTOS_CLIProcessCommand(const char *pcCommandInput, char *pcWriteBuffer, size_t xWriteBufferLen);
const char *FreeRTOS_CLIGetParameter(const char *pcCommandString, UBaseType_t uxWantedParameter, BaseType_t *pxParameterStringLength);

#endif
