#ifndef HTTPSS_CLIENT_H
#define HTTPSS_CLIENT_H

#include "balvi_config.h"

void https_download_signature(void);
void balvi_api_health_check(const char* hostname);
void balvi_api_get_config(const char* hostname);
balvi_config_t* get_current_config(void);

#endif
