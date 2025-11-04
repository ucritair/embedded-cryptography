#include <stdio.h>
#include "pico/stdlib.h"

#include "hardware/gpio.h"


#include "pico/flash.h"
#include "pico/stdlib.h"
//#include "pico/rand.h"
//#include "pico/time.h"
//#include "hardware/dma.h"
//#include "hardware/flash.h"
//#include "hardware/sync.h"
#include "hardware/xip_cache.h"
#include "hardware/regs/addressmap.h"
#include "hardware/regs/qmi.h"
#include "hardware/regs/xip.h"
#include "hardware/structs/xip_ctrl.h"
#include "hardware/structs/qmi.h"
#include "hardware/structs/xip_ctrl.h"

#include "pico/multicore.h"

#include "include/battery.h"
#include "include/battery_helpers.h"

// for clock_get_hz()
#include "hardware/clocks.h"



// Base address of the PSRAM/Flash mapped in XIP (cached)
// 0x15000000 for uncached
#define PSRAM_BASE_ADDRESS   0x11000000
#define UCPSRAM_BASE_ADDRESS 0x15000000

// Size of the PSRAM (8 MB = 8 * 1024 * 1024 bytes)
#define PSRAM_SIZE_BYTES (8 * 1024 * 1024)


// last address of PSRAM
#define PSRAM_TOP (PSRAM_BASE_ADDRESS + (PSRAM_SIZE_BYTES - 1))


// PSRA alternate stack size (1MB)
#define PSRAM_STACK_SIZE (1 * 1024 * 1024)

// PSRAM alternate stack bottom address
#define PSRAM_STACK_BOT (PSRAM_TOP + 1) - PSRAM_STACK_SIZE

// RP2350B pin 58 is GPIO 47
// GPIO 47 as CS
#define PSRAM_CS_PIN 47

uint8_t* psram = (uint8_t*)PSRAM_BASE_ADDRESS;

uint8_t* uc_psram = (uint8_t*)UCPSRAM_BASE_ADDRESS;

void init_psram()
{
	gpio_set_function(PSRAM_CS_PIN, GPIO_FUNC_XIP_CS1); // Set GPIO 47 as CS pin
	xip_ctrl_hw->ctrl |= XIP_CTRL_WRITABLE_M1_BITS;     // Configure XIP controller for writable M1 region
}

/*
__attribute__ ((used)) void testing ( void )
{

}
*/


/* from battery_e2e.c */
int battery_e2e ();


// wrapper
void core1_battery_e2e ()
{      
	int i = battery_e2e();

	printf("battery_e2e() ret: %i\n", i);

	printf(">>> CORE1 DONE, SPINNING <<<\n");
	while ( true )
	{
		sleep_ms(1000);
	}
}


// test with the alternate stack in PSRAM
void alt_stack_test ()
{
	printf("core1 reset... ");
	multicore_reset_core1();
	printf("ok\n");

	printf("launch function on core1. [PSRAM_STACK_BOT: 0x%x] [PSRAM_STACK_SIZE: 0x%x]...\n", PSRAM_STACK_BOT, PSRAM_STACK_SIZE);

	// FIXME: we are only doing this (launching on core1) to quickly change the stack location to PSRAM
	//      instead implement a stack pointer and restore so this can be run on core0 and free up core1
	multicore_launch_core1_with_stack(core1_battery_e2e, (uint32_t *)PSRAM_STACK_BOT, PSRAM_STACK_SIZE);

	/*
	printf("core0 done, spinning forever...\n");
	while ( true )
	{
		sleep_ms(1000);
	}
	*/
}


int main ()
{
	int i;

	stdio_init_all();

	// wait a bit on power up
	for ( i=4; i >= 0; i-- )
	{
		printf("%i ", i);
		sleep_ms(1000);
	}

	printf("\n");

	printf("[CLOCKS]\n");
	printf("========================================\n");
	printf("CLK_GPOUT0: %u\n", clock_get_hz(clk_gpout0));
	printf("CLK_GPOUT1: %u\n", clock_get_hz(clk_gpout1));
	printf("CLK_GPOUT2: %u\n", clock_get_hz(clk_gpout2));
	printf("CLK_GPOUT3: %u\n", clock_get_hz(clk_gpout3));
	printf("   CLK_REF: %u\n", clock_get_hz(clk_ref));
	printf("   CLK_SYS: %u\n", clock_get_hz(clk_sys));
	printf("  CLK_PERI: %u\n", clock_get_hz(clk_peri));
	printf("  CLK_HSTX: %u\n", clock_get_hz(clk_hstx));
	printf("   CLK_USB: %u\n", clock_get_hz(clk_usb));
	printf("   CLK_ADC: %u\n", clock_get_hz(clk_adc));
	printf("========================================\n");

	printf("battery_api_version(): 0x%X\n", battery_api_version());

/*
	printf("test write to PSRAM before init... ");

	uc_psram[0] = 0xAA;
	uc_psram[1] = 0xBB;
	uc_psram[2] = 0xCC;
	uc_psram[3] = 0xDD;

	printf("ok\n");

	printf("\n");

	for ( i=0; i <= 3; i++ )
	{
		printf("%i: 0x%02X\n", i, uc_psram[i]);
	}

	printf("\n");
*/

	printf("init_psram()... ");
	init_psram();
	printf("ok\n");

/*
	printf("test write to PSRAM after init... ");

	uc_psram[0] = 0xAA;
	uc_psram[1] = 0xBB;
	uc_psram[2] = 0xCC;
	uc_psram[3] = uc_psram[3] + 1;

	printf("ok\n");

	printf("\n");

	for ( i=0; i <= 3; i++ )
	{
		printf("%i: 0x%02X\n", i, uc_psram[i]);
	}

	printf("readout non cached\n");
	for ( i=0; i <= 3; i++ )
	{
		printf("%i: 0x%02X\n", i, psram[i]);
	}

	printf("clear 8388608 bytes... ");

	for ( i=0; i < 8388608; i++ )
	{
		psram[i] = 0;
	}

	printf("ok\n");
*/

/*
	for ( i=0; i <= 99; i++ )
	{
		printf("%02i: 0x%02X\n", i, psram[i]);
	}
*/

	printf("rust heap init... ");

	/// !!! FIXME: subtract stack at the top of PSRAM !!!
	rust_heap_init(PSRAM_BASE_ADDRESS, PSRAM_SIZE_BYTES);

	printf("ok\n");



	printf("running battery_e2e()...\n\n");

	// rust ffi test
	alt_stack_test();


	printf("done, spinning\n");

	while ( true )
	{
	    sleep_ms(1);
	}

	return 0;
}

