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

/* from battery_e2e.c */
int battery_e2e ();

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


int main()
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
	griffon_heap_init(PSRAM_BASE_ADDRESS, PSRAM_SIZE_BYTES);

	printf("ok\n");

/*
	printf("search for all 0x42s... ");
	for ( i=0; i < 8388608; i++ )
	{
		if ( psram[i] == 0x42 )
		{
			printf("[found 0x42 @ %i] ", i);
		}
	}
	printf(" ok\n");

	for ( i=0; i <= 99; i++ )
	{
		printf("%02i: 0x%02X\n", i, psram[i]);
	}

	printf("\n");
	printf("\n");
*/

	printf("running battery_e2e()...\n\n");

	// rust ffi test
	i = battery_e2e();

	printf("\nreturn: %i\n", i);
	



	printf("done, spinning\n");

	while ( true )
	{
	    sleep_ms(1);
	}

	return 0;
}

// FIXME: break this back out into the original e2e.c ?
// --- QUICK AND DIRTY, APPEND ---

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "battery.h"
#include "battery_helpers.h"

int real_battery_e2e ();

void core1_test ( void )
{
	printf("THIS IS A TEST FROM CORE1 IN THE PSRAM STACK\n");

	printf("core1 sleep forever...\n");

	while ( true )
	{
		sleep_ms(1000);
	}
}

void core1_battery_e2e ()
{
	real_battery_e2e();

	printf(">>> CORE1 DONE, SPINNING <<<\n");
	while ( true )
	{
		sleep_ms(1000);
	}
}

int battery_e2e ()
{
	printf("core1 reset... ");
	multicore_reset_core1();
	printf("ok\n");

	printf("launch function on core1. [PSRAM_STACK_BOT: 0x%x] [PSRAM_STACK_SIZE: 0x%x]...\n", PSRAM_STACK_BOT, PSRAM_STACK_SIZE);

	// FIXME: we are only doing this to quickly change the stack location to PSRAM
	//	instead implement a stack pointer and restore so this can be run on core0 and free up core1
	multicore_launch_core1_with_stack(core1_battery_e2e, (uint32_t *)PSRAM_STACK_BOT, PSRAM_STACK_SIZE);

	printf("core0 done, spinning forever...\n");

	while ( true )
	{
		sleep_ms(1000);
	}
}

// benchmarking
#define B_USE printf("+++ HEAP USE: %lu\n", griffon_heap_used());

#define B_START bench_start = time_us_64();
#define B_STOP  bench_stop = time_us_64() - bench_start;
#define B_SP(a) B_STOP B_USE printf("\n*** %s EXEC TIME: %llu us\n\n", a, bench_stop);


int real_battery_e2e () {
    printf("battery_e2e(): start\n");

B_USE

    // for griffon's execution time benchmark
    uint64_t bench_start;
    uint64_t bench_stop;

    //const char* mode = (argc > 1) ? argv[1] : "both"; // modes: "zkp", "tfhe", "both"
    const char* mode = "both";

    printf("MODE: %s\n", mode);


    // ZKP: generate public values (e.g., Merkle root)  and zk proof for a provided leaf & path
    // Use a compile-time constant to avoid VLA warnings
    enum { LEVELS = 32 }; // demo depth
    uint32_t leaf8_u32[8];
    uint32_t neighbors8_by_level_u32[LEVELS * 8];
    uint8_t sides[LEVELS];
    for (int i = 0; i < 8; i++) leaf8_u32[i] = 4; // demo leaf values
    for (size_t l = 0; l < LEVELS; l++) {
        for (int j = 0; j < 8; j++) neighbors8_by_level_u32[l*8 + j] = 3; // demo neighbors
        sides[l] = 0; // 0 = right, non-zero = left; require sides[0] == 0
    }
    uint8_t zkp_nonce[BATTERY_NONCE_LEN];
    memset(zkp_nonce, 0x11, sizeof zkp_nonce);

B_USE

    //mem_init();
    //memsnap_t m0; read_memsnap(&m0);
    printf("[info] Packing ZKP args...\n");
    unsigned char args_buf[1<<16];
    size_t args_len = 0;
B_START
    int rc = zkp_pack_args(leaf8_u32,
                           neighbors8_by_level_u32,
                           sides,
                           LEVELS,
                           args_buf,
                           sizeof args_buf,
                           &args_len);
B_SP("zkp_pack_args()")
    if (rc != BATTERY_OK) {
        fprintf(stderr, "zkp_pack_args failed: %s (%d)\n", battery_strerror(rc), rc);
        return 1;
    }

    if (strcmp(mode, "zkp") == 0 || strcmp(mode, "both") == 0) {
        printf("[info] Generating ZKP proof...\n");
        // Baseline before the heavy operation
        //memsnap_t base; read_memsnap(&base);
        unsigned char proof_buf[1<<19]; // 0.5 MiB demo buffer
        size_t proof_written = 0;
B_START
        rc = zkp_generate_proof(args_buf,
                                args_len,
                                zkp_nonce,
                                proof_buf,
                                sizeof proof_buf,
                                &proof_written);
B_SP("zkp_generate_proof()")
        if (rc != BATTERY_OK) {
            fprintf(stderr, "zkp_generate_proof failed: %s (%d)\n", battery_strerror(rc), rc);
            return 1;
        }
        printf("[info] ZKP proof length: %zu bytes\n", proof_written);
        //print_end_stats("zkp_generate_proof", &base);
        if (strcmp(mode, "zkp") == 0) return 0;
    }

    // TFHE: encrypt an AES-128 key under a TFHE public key
    printf("[info] TFHE params: TRLWE_N=%u\n", (unsigned)TFHE_TRLWE_N);
    const uint8_t aes_key[AES_KEY_LEN] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    printf("[info] AES-128 key: ");
    for (int i = 0; i < 16; i++) printf("%02x", aes_key[i]);
    printf("\n");

    // Demo public key arrays. Replace with a real PK.
    uint64_t pk_a[TFHE_TRLWE_N];
    uint64_t pk_b[TFHE_TRLWE_N];
    for (uint32_t i = 0; i < TFHE_TRLWE_N; i++) { pk_a[i] = 1ULL; pk_b[i] = 1ULL; }
    printf("[info] PK a[0..7]: ");
    for (int i = 0; i < 8 && i < (int)TFHE_TRLWE_N; i++) printf("%llu ", (unsigned long long)pk_a[i]);
    printf("\n[info] PK b[0..7]: ");
    for (int i = 0; i < 8 && i < (int)TFHE_TRLWE_N; i++) printf("%llu ", (unsigned long long)pk_b[i]);
    printf("\n");

    if (strcmp(mode, "tfhe") == 0 || strcmp(mode, "both") == 0) {
        // Pack the public key into an opaque buffer
        printf("[info] Packing TFHE PK...\n");
        unsigned char pk_buf[1<<18];
        size_t pk_len = 0;
B_START
        rc = tfhe_pack_public_key(pk_a, pk_b, pk_buf, sizeof pk_buf, &pk_len);
B_SP("tfhe_pack_public_key()")
        if (rc != BATTERY_OK) {
            fprintf(stderr, "tfhe_pack_public_key failed: %s (%d)\n", battery_strerror(rc), rc);
            return 1;
        }

        // Output ciphertext and fixed RNG seed
        unsigned char ct_buf[1<<19];
        size_t ct_written = 0;
        uint8_t seed[BATTERY_SEED_LEN];
        memset(seed, 42, sizeof(seed));
        printf("[info] Seed (first 8 bytes): ");
        for (int i = 0; i < 8; i++) printf("%02x", seed[i]);
        printf("..\n");

        // Baseline before TFHE encrypt
        //memsnap_t base; read_memsnap(&base);
        printf("[info] Encrypting AES key with TFHE PK...\n");
B_START
        rc = tfhe_pk_encrypt_aes_key(pk_buf, pk_len, aes_key, seed, BATTERY_SEED_LEN,
                                     ct_buf, sizeof ct_buf, &ct_written);
B_SP("tfhe_pk_encrypt_aes_key()")
        if (rc != BATTERY_OK) {
            fprintf(stderr, "tfhe_pk_encrypt_aes_key failed: %s (%d)\n", battery_strerror(rc), rc);
            return 1;
        }
        printf("[info] CT (postcard) length: %zu bytes\n", ct_written);
        //print_end_stats("tfhe_pk_encrypt", &base);
        if (strcmp(mode, "tfhe") == 0) return 0;
    }

    // E2E: encrypt some demo data under AES-128-CTR using the plaintext AES key
    uint8_t data[64];
    for (int i = 0; i < 64; i++) data[i] = (uint8_t)i; // demo data 0..63
    uint8_t iv[16];
    memset(iv, 0x23, sizeof iv); // demo IV (non-random) — replace in production
    printf("[info] AES-CTR IV: ");
    for (int i = 0; i < 16; i++) printf("%02x", iv[i]);
    printf("\n[info] AES-CTR plaintext[0..15]: ");
    for (int i = 0; i < 16; i++) printf("%02x", data[i]);
    printf("\n[info] Encrypting with AES-CTR...\n");
B_START
    if (aes_ctr_encrypt(data, sizeof(data), aes_key, AES_KEY_LEN, iv, AES_IV_LEN) != BATTERY_OK) {
        fprintf(stderr, "aes_ctr_encrypt failed\n");
        return 1;
    }
B_SP("aes_ctr_encrypt()")
    // No memory print here; AES is usually negligible vs ZKP/TFHE
    printf("[info] AES-CTR ciphertext[0..15]: ");
    for (int i = 0; i < 16; i++) printf("%02x", data[i]);
    printf("\n");

    return 0;
}

