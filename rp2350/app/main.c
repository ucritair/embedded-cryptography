#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "pico/stdlib.h"
#include "pico/bootrom.h"
#include "hardware/uart.h"
#include "TinyFrame.h"
#include "tf_port.h"
#include "ipc.h"

#include "pico/cyw43_arch.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/netif.h"

#include "FreeRTOS.h"
#include "task.h"

#include "httpss_client.h"
#include "http_post_client.h"
#include "lwip/apps/sntp.h"
#include <time.h>

#include "pico/multicore.h"
#include "psram_config.h"
#include "crypto_shared.h"
#include "mbedtls/base64.h"

// Rust FFI
#include "include/battery.h"

// Global variables for WiFi credentials
static char wifi_ssid[MAX_SSID_LEN + 1];
static char wifi_password[MAX_PASSWORD_LEN + 1];

// Time synchronization state
static uint64_t sntp_sync_time_us = 0;
static time_t sntp_sync_time_sec = 0;


typedef enum {
    APP_STATE_WAIT_CREDENTIALS,
    APP_STATE_CONNECTING_WIFI,
    APP_STATE_WIFI_CONNECTED,
    APP_STATE_WIFI_CONNECTED_IDLE,
} app_state_t;

static app_state_t app_state = APP_STATE_WAIT_CREDENTIALS;

void sntp_init_func(void)
{
    printf("Initializing SNTP...\n");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_init();
    printf("SNTP initialized.\n");
}

// Callback function called by SNTP client when time is synchronized
void sntp_set_system_time(u32_t sec)
{
    if (sec > 0) {
        sntp_sync_time_sec = sec;
        sntp_sync_time_us = time_us_64();
        
        char buf[32];
        time_t now = sntp_sync_time_sec;
        struct tm* utc = gmtime(&now);
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", utc);
        printf("SNTP time synchronized: %s\n", buf);
    }
}

// Override for the C library's time function
int _gettimeofday(struct timeval *tv, void *tz) {
    if (sntp_sync_time_sec > 0) {
        // Time has been synchronized
        uint64_t current_us = time_us_64();
        uint64_t elapsed_us = current_us - sntp_sync_time_us;
        tv->tv_sec = sntp_sync_time_sec + (elapsed_us / 1000000);
        tv->tv_usec = (elapsed_us % 1000000);
    } else {
        // Time not synchronized yet, return 0 or a boot-based time
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }
    return 0;
}


// Task priorities
#define MAIN_TASK_PRIORITY      ( tskIDLE_PRIORITY + 1UL )
#define CRYPTO_TASK_PRIORITY    ( tskIDLE_PRIORITY + 2UL )

// Task stack sizes
#define MAIN_TASK_STACK_SIZE 4096
#define CRYPTO_TASK_STACK_SIZE 2048

static bool connect_to_wifi(uint8_t auth_mode)
{
    // Map our simple auth mode to CYW43 auth constants
    uint32_t cyw43_auth;
    switch (auth_mode) {
        case WIFI_AUTH_OPEN:
            cyw43_auth = CYW43_AUTH_OPEN;
            break;
        case WIFI_AUTH_WPA:
            cyw43_auth = CYW43_AUTH_WPA_TKIP_PSK;
            break;
        case WIFI_AUTH_WPA2:
            cyw43_auth = CYW43_AUTH_WPA2_AES_PSK;
            break;
        case WIFI_AUTH_WPA_WPA2:
            cyw43_auth = CYW43_AUTH_WPA2_MIXED_PSK;
            break;
        default:
            printf("Unknown auth mode: %u, defaulting to WPA2\n", auth_mode);
            cyw43_auth = CYW43_AUTH_WPA2_AES_PSK;
            break;
    }

    printf("Connecting to Wi-Fi (SSID: %s, Auth: %u)...\n", wifi_ssid, auth_mode);
    if (cyw43_arch_wifi_connect_timeout_ms(wifi_ssid, wifi_password, cyw43_auth, 30000)) {
        printf("failed to connect to Wi-Fi.\n");
        return false;
    } else {
        printf("Connected to Wi-Fi.\n");
        return true;
    }
}

// TinyFrame instance
static TinyFrame *tf;

/**
 * Listener for the firmware version query
 */
TF_Result firmware_version_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received firmware version query.\n");
    static msg_payload_version_response_t response;
    response.version = (FIRMWARE_VERSION_MAJOR << 24) | (FIRMWARE_VERSION_MINOR << 16) | FIRMWARE_VERSION_PATCH;

    msg->data = (const uint8_t *)&response;
    msg->len = sizeof(response);
    TF_Respond(tf, msg);
    return TF_STAY;
}

/**
 * Listener for the protocol version query
 */
TF_Result protocol_version_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received protocol version query.\n");
    static msg_payload_version_response_t response;
    response.version = (PROTOCOL_VERSION_MAJOR << 24) | (PROTOCOL_VERSION_MINOR << 16) | PROTOCOL_VERSION_PATCH;

    msg->data = (const uint8_t *)&response;
    msg->len = sizeof(response);
    TF_Respond(tf, msg);
    return TF_STAY;
}

/**
 * Listener for WiFi connect request (type MSG_TYPE_WIFI_CONNECT)
 */
TF_Result wifi_connect_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received WiFi connect request. Attempting to connect (this will block)...\n");

    if (msg->len == sizeof(msg_payload_wifi_connect_t)) {
        // Copy credentials from payload
        msg_payload_wifi_connect_t *credentials = (msg_payload_wifi_connect_t *)msg->data;
        strncpy(wifi_ssid, credentials->ssid, MAX_SSID_LEN);
        wifi_ssid[MAX_SSID_LEN] = '\0';
        strncpy(wifi_password, credentials->password, MAX_PASSWORD_LEN);
        wifi_password[MAX_PASSWORD_LEN] = '\0';

        // Perform the blocking connection attempt with specified auth mode
        if (connect_to_wifi(credentials->auth_mode)) {
            // On success, update state and send ACK
            app_state = APP_STATE_WIFI_CONNECTED_IDLE;
            TF_Respond(tf, msg); // ACK indicates success
        } else {
            // On failure, do not send an ACK. The host will time out.
            app_state = APP_STATE_WAIT_CREDENTIALS; // Go back to waiting
        }
    } else {
        printf("Received WiFi connect with invalid payload size: %u (expected %u)\n",
               msg->len, sizeof(msg_payload_wifi_connect_t));
    }
    return TF_STAY;
}

/**
 * Listener for sensor data (type MSG_TYPE_SENSOR_DATA)
 */
TF_Result sensor_data_listener(TinyFrame *tf, TF_Msg *msg)
{
    if (msg->len == sizeof(msg_payload_sensor_data_t)) {
        msg_payload_sensor_data_t *payload = (msg_payload_sensor_data_t *)msg->data;
        printf("\n=== Received Sensor Data ===\n");
        printf("Sensor values: [");
        for (int i = 0; i < NUM_SENSORS; i++) {
            printf("%u", payload->sensor_values[i]);
            if (i < NUM_SENSORS - 1) printf(", ");
        }
        printf("]\n");

        balvi_api_get_config("air.gp.xyz");

        balvi_config_t* config = get_current_config();
        if (config && config->valid) {
            printf("\n=== TFHE Public Key ===\n");
            printf("TFHE Public Key (base64, first 100 chars): %.100s...\n",
                   config->tfhe_public_key_b64);
            printf("TFHE Public Key length: %zu characters\n",
                   strlen(config->tfhe_public_key_b64));
            printf("Merkle Root (base64): %s\n", config->merkle_root_b64);

            // TODO: Encrypt sensor data with TFHE and send to /ingest
        } else {
            printf("ERROR: TFHE public key not available \n");
        }

        // Acknowledge the message
        TF_Respond(tf, msg);
    } else {
        printf("Received sensor data with invalid payload size: %u (expected %zu)\n",
               msg->len, sizeof(msg_payload_sensor_data_t));
    }
    return TF_STAY;
}

// WiFi scan state
static msg_payload_wifi_scan_response_t scan_results = {0};
static volatile bool scan_in_progress = false;

/**
 * WiFi scan callback - called for each AP found
 */
static int scan_result_callback(void *env, const cyw43_ev_scan_result_t *result)
{
    if (!result || scan_results.count >= MAX_SCAN_RESULTS) {
        return 0;
    }

    // Check if this BSSID already exists (deduplicate by MAC address)
    for (int i = 0; i < scan_results.count; i++) {
        if (memcmp(scan_results.aps[i].bssid, result->bssid, 6) == 0) {
            // Already have this AP, update RSSI if stronger
            if (result->rssi > scan_results.aps[i].rssi) {
                scan_results.aps[i].rssi = result->rssi;
            }
            return 0;
        }
    }

    // New AP - add it
    wifi_ap_record_t *ap = &scan_results.aps[scan_results.count];

    // Copy SSID
    size_t ssid_len = result->ssid_len;
    if (ssid_len > MAX_SSID_LEN - 1) ssid_len = MAX_SSID_LEN - 1;
    memcpy(ap->ssid, result->ssid, ssid_len);
    ap->ssid[ssid_len] = '\0';

    // Copy BSSID
    memcpy(ap->bssid, result->bssid, 6);

    // RSSI
    ap->rssi = result->rssi;

    // Channel
    ap->channel = result->channel;

    // Auth mode (simplified mapping)
    if (result->auth_mode == 0) {
        ap->auth_mode = 0; // Open
    } else if (result->auth_mode & 0x00400000) {
        ap->auth_mode = 3; // WPA2
    } else if (result->auth_mode & 0x00200000) {
        ap->auth_mode = 2; // WPA
    } else {
        ap->auth_mode = 1; // WEP or other
    }

    scan_results.count++;
    printf("  Found: %s [%02X:%02X:%02X:%02X:%02X:%02X] (RSSI: %d dBm, Ch: %d)\n",
           ap->ssid,
           ap->bssid[0], ap->bssid[1], ap->bssid[2],
           ap->bssid[3], ap->bssid[4], ap->bssid[5],
           ap->rssi, ap->channel);

    return 0;
}

/**
 * Listener for WiFi scan request (type MSG_TYPE_WIFI_SCAN_REQUEST)
 */
TF_Result wifi_scan_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received WiFi scan request\n");

    if (scan_in_progress) {
        printf("Scan already in progress\n");
        // Send empty response
        scan_results.count = 0;
        msg->data = (const uint8_t *)&scan_results;
        msg->len = sizeof(scan_results);
        TF_Respond(tf, msg);
        return TF_STAY;
    }

    // Reset scan results
    memset(&scan_results, 0, sizeof(scan_results));
    scan_in_progress = true;

    // Perform WiFi scan with extended options
    printf("Starting WiFi scan (this may take 10-15 seconds)...\n");
    cyw43_wifi_scan_options_t scan_options = {
        .scan_type = 0,  // Active scan
    };
    int err = cyw43_wifi_scan(&cyw43_state, &scan_options, NULL, scan_result_callback);

    if (err == 0) {
        // Wait for scan to complete (allow longer time for thorough scan)
        // Typical scan: ~1-2 seconds per channel, ~13 channels = up to 26 seconds
        int timeout = 200; // 20 seconds timeout
        int elapsed = 0;
        while (cyw43_wifi_scan_active(&cyw43_state) && timeout > 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            timeout--;
            elapsed++;
            if (elapsed % 10 == 0) {
                printf("  Scanning... (%d seconds elapsed)\n", elapsed / 10);
            }
        }

        if (timeout == 0) {
            printf("WiFi scan timed out after 20 seconds\n");
        } else {
            printf("WiFi scan complete in %d seconds. Found %d unique APs\n", elapsed / 10, scan_results.count);
        }
    } else {
        printf("WiFi scan failed with error: %d\n", err);
        scan_results.count = 0;
    }

    scan_in_progress = false;

    // Send response
    msg->data = (const uint8_t *)&scan_results;
    msg->len = sizeof(scan_results);
    TF_Respond(tf, msg);

    return TF_STAY;
}

/**
 * Listener for reboot to bootloader request (type MSG_TYPE_REBOOT_TO_BOOTLOADER)
 */
TF_Result reboot_to_bootloader_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received reboot to bootloader request\n");

    // Send ACK first
    TF_Respond(tf, msg);

    // Give time for ACK to be sent
    vTaskDelay(pdMS_TO_TICKS(100));

    printf("Rebooting into USB bootloader mode...\n");

    // For RP2350, use the ROM function directly
    // This is equivalent to holding BOOTSEL during reset
    rom_reset_usb_boot_extra(0, 0, 0);

    // Should never reach here
    return TF_STAY;
}

/**
 * Send ZKP authentication status update to host (unsolicited message)
 */
void send_zkp_auth_status(uint8_t stage, uint8_t progress, const char* message) {
    static msg_payload_zkp_auth_status_t status;
    memset(&status, 0, sizeof(status));

    status.stage = stage;
    status.progress = progress;
    strncpy(status.message, message, MAX_STATUS_MESSAGE_LEN - 1);
    status.message[MAX_STATUS_MESSAGE_LEN - 1] = '\0';

    TF_Msg msg;
    TF_ClearMsg(&msg);
    msg.type = MSG_TYPE_ZKP_AUTH_STATUS;
    msg.data = (const uint8_t*)&status;
    msg.len = sizeof(status);
    TF_Send(tf, &msg);

    // Small delay to ensure message is sent before next operation
    vTaskDelay(pdMS_TO_TICKS(10));
}

/**
 * Listener for ZKP authentication request (type MSG_TYPE_ZKP_AUTHENTICATE)
 * This is a blocking operation that performs the full authentication flow
 */
TF_Result zkp_authenticate_listener(TinyFrame *tf, TF_Msg *msg)
{
    printf("Received ZKP authentication request\n");

    static msg_payload_zkp_authenticate_response_t response;
    memset(&response, 0, sizeof(response));

    // Perform full authentication flow (blocking)
    // This will take several minutes due to proof generation on Core1
    printf("[ZKP Auth] Starting authentication flow (this will take ~10 minutes)...\n");

    static auth_verify_response_t auth_result = {0};
    memset(&auth_result, 0, sizeof(auth_result));
    int rc = perform_zkp_authentication("air.gp.xyz", &auth_result);

    if (rc == 0 && auth_result.valid) {
        // Success - copy token and expiry to response
        response.success = 1;
        strncpy(response.access_token, auth_result.access_token, MAX_ACCESS_TOKEN_LEN - 1);
        response.access_token[MAX_ACCESS_TOKEN_LEN - 1] = '\0';
        strncpy(response.expires_at, auth_result.expires_at, MAX_TIMESTAMP_LEN - 1);
        response.expires_at[MAX_TIMESTAMP_LEN - 1] = '\0';

        printf("[ZKP Auth] Authentication successful\n");
        printf("[ZKP Auth] Access Token: %.32s...\n", response.access_token);
        printf("[ZKP Auth] Expires at: %s\n", response.expires_at);
    } else {
        // Failure
        response.success = 0;
        response.access_token[0] = '\0';
        response.expires_at[0] = '\0';

        printf("[ZKP Auth] Authentication failed with error code: %d\n", rc);
    }

    // Send response
    msg->data = (const uint8_t *)&response;
    msg->len = sizeof(response);
    TF_Respond(tf, msg);

    return TF_STAY;
}

// Compute parent commitment on Core1 and return it to Core0
int compute_parent_on_core1(uint8_t* parent_out) {
	printf("[Core0] Starting Core1 to compute parent commitment\n");

	// Initialize pointer to shared memory
	if (crypto_shared == NULL) {
		crypto_shared = (crypto_shared_t*)CRYPTO_SHARED_ADDR;
	}

	// Initialize shared memory
	memset(crypto_shared, 0, sizeof(crypto_shared_t));
	crypto_shared->compute_done = false;
	crypto_shared->error_code = 0;

	// Stop Core1 if running
	multicore_reset_core1();

	// Launch Core1 with PSRAM stack to run parent computation
	multicore_launch_core1_with_stack(core1_compute_parent_entry, (uint32_t *)PSRAM_STACK_BOT, PSRAM_STACK_SIZE);

	// Wait for Core1 to complete (poll the done flag)
	printf("[Core0] Waiting for Core1 to complete...\n");
	int timeout = 100; // 10 seconds
	while (!crypto_shared->compute_done && timeout-- > 0) {
		sleep_ms(100);
	}

	if (!crypto_shared->compute_done) {
		printf("[Core0] Timeout waiting for Core1\n");
		multicore_reset_core1();
		return -1;
	}

	if (crypto_shared->error_code != 0) {
		printf("[Core0] Core1 returned error: %d\n", crypto_shared->error_code);
		multicore_reset_core1();
		return crypto_shared->error_code;
	}

	// Copy parent from shared memory
	memcpy(parent_out, crypto_shared->parent, 32);

	printf("[Core0] Parent computation successful\n");

	// Stop Core1
	multicore_reset_core1();

	return 0;
}

// Generate ZKP proof on Core1
// witness_b64 and nonce_b64 should be base64 encoded strings
// proof_out should point to a buffer (can be static/global on Core0)
int generate_proof_on_core1(const char* witness_b64, const char* nonce_b64, uint8_t** proof_out, size_t* proof_len) {
	uint32_t start_time = to_ms_since_boot(get_absolute_time());
	printf("[Core0] [%u ms] Starting Core1 to generate ZKP proof\n", start_time);

	// Initialize pointer to shared memory
	if (crypto_shared == NULL) {
		crypto_shared = (crypto_shared_t*)CRYPTO_SHARED_ADDR;
	}

	// Initialize shared memory
	memset(crypto_shared, 0, sizeof(crypto_shared_t));
	crypto_shared->compute_done = false;
	crypto_shared->error_code = 0;

	// Copy witness and nonce to shared memory (avoid stack on Core0)
	strncpy(crypto_shared->witness_b64, witness_b64, sizeof(crypto_shared->witness_b64) - 1);
	strncpy(crypto_shared->nonce_b64, nonce_b64, sizeof(crypto_shared->nonce_b64) - 1);

	// Stop Core1 if running
	multicore_reset_core1();

	// Launch Core1 with PSRAM stack to run proof generation
	uint32_t launch_time = to_ms_since_boot(get_absolute_time());
	multicore_launch_core1_with_stack(core1_generate_proof_entry, (uint32_t *)PSRAM_STACK_BOT, PSRAM_STACK_SIZE);

	// Wait for Core1 to complete (proof generation can take several minutes!)
	printf("[Core0] [%u ms] Waiting for Core1 to complete proof generation...\n", launch_time);
	int timeout = 6000; // 600 seconds = 10 minutes
	while (!crypto_shared->compute_done && timeout-- > 0) {
		sleep_ms(100);
	}

	uint32_t complete_time = to_ms_since_boot(get_absolute_time());

	if (!crypto_shared->compute_done) {
		printf("[Core0] [%u ms] Timeout waiting for Core1\n", complete_time);
		multicore_reset_core1();
		return -1;
	}

	if (crypto_shared->error_code != 0) {
		printf("[Core0] [%u ms] Core1 returned error: %d\n", complete_time, crypto_shared->error_code);
		multicore_reset_core1();
		return crypto_shared->error_code;
	}

	// Return pointer to proof in shared memory (avoid copying large proof)
	*proof_out = crypto_shared->proof;
	*proof_len = crypto_shared->proof_len;

	uint32_t elapsed = complete_time - start_time;
	printf("[Core0] [%u ms] Proof generation successful: %zu bytes (took %u ms = %.1f seconds)\n",
	       complete_time, *proof_len, elapsed, elapsed / 1000.0);

	// Stop Core1
	multicore_reset_core1();

	return 0;
}

// Perform full ZKP authentication flow
// Returns: 0 on success, negative on error
// Outputs: auth_response structure with access token
int perform_zkp_authentication(const char* hostname, auth_verify_response_t* auth_response) {
    if (hostname == NULL || auth_response == NULL) {
        return -1;
    }

    int rc;  // Declare rc for HTTP tests

    ///////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////
    /////////////////// GET NONCE /////////////////////////////
    ///////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////
    printf("\n=== Getting Nonce from Server ===\n");
    send_zkp_auth_status(ZKP_STAGE_NONCE, 0, "Getting nonce from server...");

    static nonce_response_t nonce_response = {0};
    memset(&nonce_response, 0, sizeof(nonce_response));
    rc = balvi_api_get_nonce("air.gp.xyz", &nonce_response);

    if (rc == 0 && nonce_response.valid) {
        printf("Nonce retrieved successfully!\n");
        printf("  Nonce: %s\n", nonce_response.nonce);
        printf("  Expires at: %s\n", nonce_response.expires_at);
        send_zkp_auth_status(ZKP_STAGE_NONCE, 100, "Nonce received");
    } else {
        printf("Failed to get nonce from server\n");
        send_zkp_auth_status(ZKP_STAGE_NONCE, 0, "Failed to get nonce");
        return -1;
    }

    ///////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////
    /////////////////// COMPUTE PARENT & GET WITNESS //////////
    ///////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////
    printf("\n=== STAGE 2: Computing Parent Commitment on Core1 ===\n");
    send_zkp_auth_status(ZKP_STAGE_PARENT, 0, "Computing parent commitment...");

    uint8_t parent[32];
    rc = compute_parent_on_core1(parent);
    if (rc != 0) {
        printf("[Core0] Parent computation failed: %d\n", rc);
        send_zkp_auth_status(ZKP_STAGE_PARENT, 0, "Parent computation failed");
        return -2;
    }

    send_zkp_auth_status(ZKP_STAGE_PARENT, 100, "Parent commitment computed");

    printf("PARENT (binary hex):");
    for (int i = 0; i < 32; i++) {
        if (i % 16 == 0) printf("\n");
        printf("%02x ", parent[i]);
    }
    printf("\n");

    // Encode parent as base64 for server request
    char parent_b64[64];
    size_t parent_b64_len = 0;
    int ret = mbedtls_base64_encode(
        (unsigned char*)parent_b64,
        sizeof(parent_b64),
        &parent_b64_len,
        parent,
        32
    );

    if (ret != 0) {
        printf("[Core0] Base64 encode failed: %d\n", ret);
        return -3;
    }

    parent_b64[parent_b64_len] = '\0';
    printf("PARENT (base64): %s\n", parent_b64);
    printf("PARENT (base64) LENGTH: %zu\n", parent_b64_len);

    // Fetch witness from server using parent commitment
    printf("\n=== STAGE 3: Fetching Witness from Server ===\n");
    printf("SENDING TO SERVER - Parent commitment: %s\n", parent_b64);
    send_zkp_auth_status(ZKP_STAGE_WITNESS, 0, "Requesting Merkle witness from server...");

    static witness_response_t witness_response = {0};
    memset(&witness_response, 0, sizeof(witness_response));
    rc = balvi_api_get_witness(hostname, parent_b64, &witness_response);

    if (rc == 0 && witness_response.valid) {
        printf("RECEIVED FROM SERVER:\n");
        printf("ROOT (base64): %s\n", witness_response.root_b64);
        printf("ROOT LENGTH: %zu\n", strlen(witness_response.root_b64));
        printf("WITNESS (base64): %s\n", witness_response.witness_b64);
        printf("WITNESS LENGTH: %zu\n", strlen(witness_response.witness_b64));
        send_zkp_auth_status(ZKP_STAGE_WITNESS, 100, "Merkle witness received");

        ///////////////////////////////////////////////////////////
        /////////////////// GENERATE PROOF & AUTHENTICATE /////////
        ///////////////////////////////////////////////////////////
        printf("\n=== STAGE 4: Generating ZKP Proof on Core1 ===\n");
        printf("INPUTS TO PROOF GENERATION:\n");
        printf("WITNESS (base64): %s\n", witness_response.witness_b64);
        printf("NONCE (base64): %s\n", nonce_response.nonce);
        send_zkp_auth_status(ZKP_STAGE_PROOF, 0, "Generating ZKP proof (~10 minutes)...");

        uint8_t* proof_ptr = NULL;
        size_t proof_len = 0;
        rc = generate_proof_on_core1(witness_response.witness_b64, nonce_response.nonce, &proof_ptr, &proof_len);
        if (rc != 0 || proof_ptr == NULL) {
            printf("[Core0] Proof generation failed: %d\n", rc);
            send_zkp_auth_status(ZKP_STAGE_PROOF, 0, "Proof generation failed");
            return -4;
        }

        send_zkp_auth_status(ZKP_STAGE_PROOF, 100, "ZKP proof generated successfully");

        // Encode proof as base64 for server
        // Use dedicated proof_b64 buffer in shared memory
        printf("[Core0] Encoding proof to base64...\n");
        crypto_shared->proof_b64_len = 0;

        int ret = mbedtls_base64_encode(
            (unsigned char*)crypto_shared->proof_b64,
            sizeof(crypto_shared->proof_b64),
            &crypto_shared->proof_b64_len,
            proof_ptr,
            proof_len
        );

        if (ret != 0) {
            printf("[Core0] Failed to encode proof to base64: %d\n", ret);
            return -5;
        }

        crypto_shared->proof_b64[crypto_shared->proof_b64_len] = '\0';
        printf("PROOF (base64) LENGTH: %zu chars\n", crypto_shared->proof_b64_len);

        // Authenticate with server
        printf("\n=== STAGE 5: Authenticating with Server ===\n");
        printf("INPUTS TO AUTHENTICATION:\n");
        printf("NONCE (base64): %s\n", nonce_response.nonce);
        send_zkp_auth_status(ZKP_STAGE_VERIFY, 0, "Submitting proof for verification...");

        // Print only first 100 and last 100 bytes of proof bundle
        if (crypto_shared->proof_b64_len <= 200) {
            printf("PROOF_BUNDLE (base64): %s\n", crypto_shared->proof_b64);
        } else {
            printf("PROOF_BUNDLE (base64, first 100 chars): %.100s\n", crypto_shared->proof_b64);
            printf("...\n");
            printf("PROOF_BUNDLE (base64, last 100 chars): %s\n",
                   crypto_shared->proof_b64 + crypto_shared->proof_b64_len - 100);
        }

        rc = balvi_api_verify_proof(hostname, nonce_response.nonce, crypto_shared->proof_b64, auth_response);

        if (rc == 0 && auth_response->valid) {
            printf("*** AUTHENTICATION SUCCESSFUL! ***\n");
            printf("  Access Token: %.32s...\n", auth_response->access_token);
            printf("  Expires at: %s\n", auth_response->expires_at);
            send_zkp_auth_status(ZKP_STAGE_VERIFY, 100, "Authentication successful!");
            return 0; // Success
        } else {
            printf("Authentication failed\n");
            send_zkp_auth_status(ZKP_STAGE_VERIFY, 0, "Authentication verification failed");
            return -6;
        }
    } else {
        printf("Failed to get witness from server\n");
        send_zkp_auth_status(ZKP_STAGE_WITNESS, 0, "Failed to get witness from server");
        return -7;
    }
}

void main_task(__unused void *params) {
    stdio_init_all();
    tf_port_init();

    printf("Hello, Pico!\n");

    // // Add a delay to allow for UART connection
    // for (int i = 0; i < 5; i++) {
    //     printf("Waiting for UART...\n");
    //     vTaskDelay(1000);
    // }
 
    printf("Querying Rust library version...\n");
    printf("battery_api_version(): 0x%X\n", battery_api_version());

    init_psram();
    rust_heap_init(RUST_HEAP_BASE, RUST_HEAP_SIZE);

    printf("PSRAM Memory Layout:\n");
    printf("  Rust Heap:   0x%08X - 0x%08X (%d MB)\n",
           RUST_HEAP_BASE, RUST_HEAP_BASE + RUST_HEAP_SIZE - 1, RUST_HEAP_SIZE / (1024*1024));
    printf("  Shared Mem:  0x%08X - 0x%08X (%d MB)\n",
           SHARED_MEM_BASE, SHARED_MEM_BASE + SHARED_MEM_SIZE - 1, SHARED_MEM_SIZE / (1024*1024));
    printf("  Core1 Stack: 0x%08X - 0x%08X (%d MB)\n",
           PSRAM_STACK_BOT, PSRAM_STACK_TOP, PSRAM_STACK_SIZE / (1024*1024));

    if (cyw43_arch_init()) {
        printf("failed to initialise cyw43_arch\n");
        return;
    }

    cyw43_arch_enable_sta_mode();

    // Initialize TinyFrame
    tf = TF_Init(TF_MASTER);
    TF_AddTypeListener(tf, MSG_TYPE_FIRMWARE_VERSION_QUERY, firmware_version_listener);
    TF_AddTypeListener(tf, MSG_TYPE_PROTOCOL_VERSION_QUERY, protocol_version_listener);
    TF_AddTypeListener(tf, MSG_TYPE_WIFI_CONNECT, wifi_connect_listener);
    TF_AddTypeListener(tf, MSG_TYPE_SENSOR_DATA, sensor_data_listener);
    TF_AddTypeListener(tf, MSG_TYPE_WIFI_SCAN_REQUEST, wifi_scan_listener);
    TF_AddTypeListener(tf, MSG_TYPE_REBOOT_TO_BOOTLOADER, reboot_to_bootloader_listener);
    TF_AddTypeListener(tf, MSG_TYPE_ZKP_AUTHENTICATE, zkp_authenticate_listener);

    printf("[RP2350]: Listening for UART Messages\n");
    while (true) {
        // TinyFrame processing
        while (uart_is_readable(uart0)) {
            uint8_t ch = uart_getc(uart0);
            TF_Accept(tf, &ch, 1);
        }

        switch (app_state) {
            case APP_STATE_WAIT_CREDENTIALS:
                // Do nothing, the listener now handles connection triggering.
                break;

            case APP_STATE_CONNECTING_WIFI:
                // This state is no longer used.
                break;

            case APP_STATE_WIFI_CONNECTED:
                // Do nothing, wait for TinyFrame commands
                break;
        }

        vTaskDelay(1);
    }
}

int main(void) {
    // Start the main thread
    xTaskCreate(main_task, "MainThread", MAIN_TASK_STACK_SIZE, NULL, MAIN_TASK_PRIORITY, NULL);
    vTaskStartScheduler();

    return 0;
}
