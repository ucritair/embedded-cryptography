#ifndef _LWIPOPTS_H
#define _LWIPOPTS_H

// Define NO_SYS to 0 for this project to enable RTOS features.
// This must be done BEFORE including the common opts file.
#define NO_SYS 0

// Set master heap size. Must be defined before including common opts.
// Reduced from 200KB to 64KB to conserve SRAM (large buffers use pbufs instead)
#define MEM_SIZE (64 * 1024)

// Generally you would define your own explicit list of lwIP options
// (see https://www.nongnu.org/lwip/2_1_x/group__lwip__opts.html)
//
// This example uses a common include to avoid repetition
#include "lwipopts_examples_common.h"

#if !NO_SYS
#define TCPIP_THREAD_STACKSIZE 1024
#define DEFAULT_THREAD_STACKSIZE 1024
#define DEFAULT_RAW_RECVMBOX_SIZE 8
#define TCPIP_MBOX_SIZE 8
#define LWIP_TIMEVAL_PRIVATE 0

// not necessary, can be done either way
#define LWIP_TCPIP_CORE_LOCKING_INPUT 1

// ping_thread sets socket receive timeout, so enable this feature
#define LWIP_SO_RCVTIMEO 1
#endif

#define LWIP_ALTCP 1

// If you don't want to use TLS (just a http request) you can avoid linking to mbedtls and remove the following
#define LWIP_ALTCP_TLS           1
#define LWIP_ALTCP_TLS_MBEDTLS   1
 
// Increase TCP window size for TLS to avoid stalling
// mbedTLS needs 16KB for RX decryption buffer, so TCP_WND should be>
#define TCP_MSS 1460
#define TCP_WND (16 * 1024)  // 16KB window
// Increased send buffer from ~11KB to ~93KB for large ZKP proof uploads
#define TCP_SND_BUF (64 * TCP_MSS)  // 64 * 1460 = ~93KB send buffer
#define PBUF_POOL_SIZE 48  // Increased pbuf pool for larger transfers
// MEMP_NUM_TCP_SEG must be >= TCP_SND_QUEUELEN which is (4*TCP_SND_BUF)/TCP_MSS = 256
#define MEMP_NUM_TCP_SEG 256  // More TCP segments for chunking large payloads

// Note bug in lwip with LWIP_ALTCP and LWIP_DEBUG
// https://savannah.nongnu.org/bugs/index.php?62159
//#define LWIP_DEBUG 1
#undef LWIP_DEBUG
#define ALTCP_MBEDTLS_DEBUG  LWIP_DBG_ON

#define LWIP_SNTP 1
#define SNTP_SERVER_DNS 1
#define MEMP_NUM_SYS_TIMEOUT 10

#define LWIP_DEBUG 1
#define SNTP_DEBUG LWIP_DBG_ON
#define SNTP_SET_SYSTEM_TIME sntp_set_system_time

#endif