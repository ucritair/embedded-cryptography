#include "pico/stdlib.h"
#include "hardware/uart.h"
#include "TinyFrame.h"

// --- Thread safety ---
void TF_ClaimTx(TinyFrame *tf)
{
    // your mutex lock implementation
}

void TF_ReleaseTx(TinyFrame *tf)
{
    // your mutex unlock implementation
}

// --- Platform-specific I/O ---
void TF_WriteImpl(TinyFrame *tf, const uint8_t *buff, uint32_t len)
{
    uart_write_blocking(uart0, buff, len);
}

void tf_port_init(void)
{
    // Initialize UART
    uart_init(uart0, 115200);
    gpio_set_function(0, GPIO_FUNC_UART);
    gpio_set_function(1, GPIO_FUNC_UART);
}
