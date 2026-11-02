#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_timer.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "psa/crypto.h"

#include "ascon_api.h"
#include "client_config.h"
#include "esp32_mceliece.h"
#include "esp32_ml_kem.h"
#include "protocol.h"

#ifndef CLIENT_ALG_ML_KEM
#define CLIENT_ALG_ML_KEM 4
#endif

#ifndef CLIENT_ALG_ALL_WITH_ML_KEM
#define CLIENT_ALG_ALL_WITH_ML_KEM 5
#endif

#ifndef CLIENT_ALG_MCELIECE
#define CLIENT_ALG_MCELIECE 6
#endif

#ifndef CLIENT_ALG_ALL_WITH_PQC
#define CLIENT_ALG_ALL_WITH_PQC 7
#endif

#define WIFI_CONNECTED_BIT BIT0
#define ML_KEM_TASK_STACK_SIZE 65536
#define ML_KEM_TASK_PRIORITY 4
#define MCELIECE_TASK_STACK_SIZE 98304
#define MCELIECE_TASK_PRIORITY 4

#define AES_KEY_SIZE 32
#define AES_NONCE_SIZE 12
#define AES_TAG_SIZE 16
#define AES_OVERHEAD_BYTES (AES_NONCE_SIZE + AES_TAG_SIZE)

#define ASCON_KEY_SIZE 16
#define ASCON_NONCE_SIZE 16
#define ASCON_TAG_SIZE 16
#define ASCON_OVERHEAD_BYTES (ASCON_NONCE_SIZE + ASCON_TAG_SIZE)

static const char *TAG = "esp32-lock";

static EventGroupHandle_t wifi_event_group;
static uint8_t aes_key[AES_KEY_SIZE];
static uint8_t ascon_key[ASCON_KEY_SIZE];
static psa_key_id_t aes_key_id = 0;

static uint32_t sequence_number = 1;
static uint32_t battery_millivolts = 4020;
static int lock_state = 1;

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub,
                        const unsigned char *k);

static void write_be32(uint8_t *buf, uint32_t value)
{
    buf[0] = (uint8_t)((value >> 24) & 0xFF);
    buf[1] = (uint8_t)((value >> 16) & 0xFF);
    buf[2] = (uint8_t)((value >> 8) & 0xFF);
    buf[3] = (uint8_t)(value & 0xFF);
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i = 0;

    if (!hex || strlen(hex) != out_len * 2)
    {
        return -1;
    }

    for (i = 0; i < out_len; ++i)
    {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static double throughput_bps(size_t bytes, int64_t latency_us)
{
    if (latency_us <= 0)
    {
        return 0.0;
    }

    return (double)bytes / ((double)latency_us / 1000000.0);
}

static long overhead_bytes(size_t wire_len, size_t plaintext_len)
{
    return (long)wire_len - (long)plaintext_len;
}

static double overhead_percent(size_t wire_len, size_t plaintext_len)
{
    if (plaintext_len == 0)
    {
        return 0.0;
    }

    return ((double)wire_len - (double)plaintext_len) * 100.0 / (double)plaintext_len;
}

static int get_wifi_rssi(void)
{
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
    {
        return ap_info.rssi;
    }
    return 0;
}

static size_t build_payload(char *buf, size_t buf_size)
{
    int written = snprintf(buf,
                           buf_size,
                           "{\"device\":\"esp32-lock\",\"seq\":%lu,\"locked\":%s,\"battery_mv\":%lu,\"rssi\":%d,\"event\":\"heartbeat\"}",
                           (unsigned long)sequence_number,
                           lock_state ? "true" : "false",
                           (unsigned long)battery_millivolts,
                           get_wifi_rssi());
    size_t used = 0;

    if (written < 0 || (size_t)written >= buf_size)
    {
        return 0;
    }

    used = (size_t)written;
    if (used < TARGET_PAYLOAD_SIZE)
    {
        if (used > 0 && buf[used - 1] == '}')
        {
            buf[--used] = '\0';
        }

        const char *prefix = ",\"padding\":\"";
        const char *suffix = "\"}";
        size_t fixed = strlen(prefix) + strlen(suffix);
        if (TARGET_PAYLOAD_SIZE > used + fixed &&
            TARGET_PAYLOAD_SIZE + 1U <= buf_size)
        {
            size_t padding_len = TARGET_PAYLOAD_SIZE - used - fixed;
            size_t pos = used;
            size_t i = 0;

            memcpy(buf + pos, prefix, strlen(prefix));
            pos += strlen(prefix);
            for (i = 0; i < padding_len; ++i)
            {
                buf[pos++] = (char)('A' + (i % 26U));
            }
            memcpy(buf + pos, suffix, strlen(suffix));
            pos += strlen(suffix);
            buf[pos] = '\0';
        }
        else if (used + 2U <= buf_size)
        {
            buf[used++] = '}';
            buf[used] = '\0';
        }
    }

    return strlen(buf);
}

static int psa_aes256_init_key(void)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "psa_crypto_init failed: %ld", (long)status);
        return -1;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, AES_KEY_SIZE * 8U);

    status = psa_import_key(&attributes, aes_key, AES_KEY_SIZE, &aes_key_id);
    psa_reset_key_attributes(&attributes);

    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "psa_import_key failed: %ld", (long)status);
        return -1;
    }

    return 0;
}

static int aes256_gcm_encrypt(const uint8_t *plaintext,
                              size_t plaintext_len,
                              uint8_t *wire_ciphertext,
                              size_t *wire_ciphertext_len)
{
    psa_status_t status;
    uint8_t *nonce = wire_ciphertext;
    uint8_t *ciphertext_and_tag = wire_ciphertext + AES_NONCE_SIZE;
    size_t ciphertext_and_tag_len = 0;

    esp_fill_random(nonce, AES_NONCE_SIZE);

    status = psa_aead_encrypt(aes_key_id,
                              PSA_ALG_GCM,
                              nonce,
                              AES_NONCE_SIZE,
                              NULL,
                              0,
                              plaintext,
                              plaintext_len,
                              ciphertext_and_tag,
                              plaintext_len + AES_TAG_SIZE,
                              &ciphertext_and_tag_len);

    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "psa_aead_encrypt failed: %ld", (long)status);
        return -1;
    }

    *wire_ciphertext_len = AES_NONCE_SIZE + ciphertext_and_tag_len;
    return 0;
}

static int ascon_encrypt_packet(const uint8_t *plaintext,
                                size_t plaintext_len,
                                uint8_t *wire_ciphertext,
                                size_t *wire_ciphertext_len)
{
    uint8_t *nonce = wire_ciphertext;
    unsigned long long ref_len = 0;
    int rc = 0;

    esp_fill_random(nonce, ASCON_NONCE_SIZE);

    rc = crypto_aead_encrypt(wire_ciphertext + ASCON_NONCE_SIZE,
                             &ref_len,
                             plaintext,
                             (unsigned long long)plaintext_len,
                             NULL,
                             0,
                             NULL,
                             nonce,
                             ascon_key);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "Ascon crypto_aead_encrypt failed");
        return -1;
    }

    *wire_ciphertext_len = ASCON_NONCE_SIZE + (size_t)ref_len;
    return 0;
}

static int send_all(int sock, const uint8_t *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len)
    {
        int rc = send(sock, buf + sent, len - sent, 0);
        if (rc <= 0)
        {
            return -1;
        }
        sent += (size_t)rc;
    }

    return 0;
}

static int recv_ack_line(int sock, char *buf, size_t buf_len)
{
    size_t total = 0;

    while (total + 1U < buf_len)
    {
        char c = 0;
        int rc = recv(sock, &c, 1, 0);
        if (rc <= 0)
        {
            return -1;
        }
        if (c == '\n')
        {
            break;
        }
        buf[total++] = c;
    }

    buf[total] = '\0';
    return 0;
}

static int open_server_socket(void)
{
    struct sockaddr_in dest_addr;
    struct timeval timeout;
    int sock = -1;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_HOST, &dest_addr.sin_addr) != 1)
    {
        ESP_LOGE(TAG, "SERVER_HOST must be an IPv4 address");
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "socket failed: errno=%d", errno);
        return -1;
    }

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0)
    {
        ESP_LOGE(TAG, "connect failed: errno=%d", errno);
        close(sock);
        return -1;
    }

    return sock;
}

static void fill_header(uint8_t *header,
                        uint8_t algorithm,
                        uint8_t payload_type,
                        uint32_t plaintext_len,
                        uint32_t wire_len)
{
    memcpy(header, IOT_PROTOCOL_MAGIC, 4);
    header[4] = IOT_PROTOCOL_VERSION;
    header[5] = algorithm;
    header[6] = IOT_DEVICE_ESP32_LOCK;
    header[7] = payload_type;
    write_be32(header + 8, sequence_number);
    write_be32(header + 12, plaintext_len);
    write_be32(header + 16, wire_len);
}

static int send_packet(uint8_t algorithm,
                       uint8_t payload_type,
                       const uint8_t *wire_payload,
                       size_t wire_len,
                       size_t plaintext_len,
                       int64_t *latency_e2e_us)
{
    uint8_t header[IOT_PROTOCOL_HEADER_SIZE];
    char ack[64];
    int64_t start_us = esp_timer_get_time();
    int sock = open_server_socket();

    if (sock < 0)
    {
        return -1;
    }

    fill_header(header, algorithm, payload_type, (uint32_t)plaintext_len, (uint32_t)wire_len);

    if (send_all(sock, header, sizeof(header)) != 0 ||
        send_all(sock, wire_payload, wire_len) != 0 ||
        recv_ack_line(sock, ack, sizeof(ack)) != 0)
    {
        ESP_LOGW(TAG, "send/ack failed");
        close(sock);
        return -1;
    }

    if (latency_e2e_us)
    {
        *latency_e2e_us = esp_timer_get_time() - start_us;
    }

    ESP_LOGI(TAG, "seq=%lu alg=%u sent wire=%u ack=%s",
             (unsigned long)sequence_number,
             algorithm,
             (unsigned)wire_len,
             ack);
    close(sock);
    return 0;
}

static int send_aead_algorithm(uint8_t algorithm)
{
    size_t payload_capacity = TARGET_PAYLOAD_SIZE + 256U;
    char *payload = (char *)malloc(payload_capacity);
    uint8_t *wire = NULL;
    size_t plaintext_len = 0;
    size_t wire_len = 0;
    size_t overhead = algorithm == IOT_ALG_AES256_GCM ? AES_OVERHEAD_BYTES : ASCON_OVERHEAD_BYTES;
    int64_t encrypt_start_us = 0;
    int64_t encrypt_us = 0;
    int64_t latency_e2e_us = 0;
    uint32_t memory_before = esp_get_free_heap_size();
    uint32_t memory_after = 0;
    uint32_t memory_min = 0;
    int rc = -1;

    if (!payload)
    {
        return -1;
    }

    plaintext_len = build_payload(payload, payload_capacity);
    wire = (uint8_t *)malloc(plaintext_len + overhead);
    if (!wire)
    {
        free(payload);
        return -1;
    }

    if (algorithm == IOT_ALG_AES256_GCM)
    {
        encrypt_start_us = esp_timer_get_time();
        rc = aes256_gcm_encrypt((const uint8_t *)payload, plaintext_len, wire, &wire_len);
        encrypt_us = esp_timer_get_time() - encrypt_start_us;
    }
    else
    {
        encrypt_start_us = esp_timer_get_time();
        rc = ascon_encrypt_packet((const uint8_t *)payload, plaintext_len, wire, &wire_len);
        encrypt_us = esp_timer_get_time() - encrypt_start_us;
    }

    if (rc == 0)
    {
        rc = send_packet(algorithm, IOT_PAYLOAD_TELEMETRY, wire, wire_len, plaintext_len, &latency_e2e_us);
    }

    memory_after = esp_get_free_heap_size();
    memory_min = esp_get_minimum_free_heap_size();

    ESP_LOGI(TAG,
             "metric device=esp32-lock alg=%s seq=%lu payload=telemetry pt=%u ct=%u pk=0 wire=%u encrypt_us=%lld keypair_us=0 encaps_us=0 decaps_us=0 total_kem_us=0 latency_e2e_us=%lld overhead_bytes=%ld overhead_percent=%.2f throughput_Bps=%.2f memory_before_B=%lu memory_after_B=%lu memory_min_B=%lu valid_secret=0 ack_ok=%d size_ok=1",
             algorithm == IOT_ALG_AES256_GCM ? "aes256-gcm" : "ascon-128a",
             (unsigned long)sequence_number,
             (unsigned)plaintext_len,
             (unsigned)wire_len,
             (unsigned)wire_len,
             (long long)encrypt_us,
             (long long)latency_e2e_us,
             overhead_bytes(wire_len, plaintext_len),
             overhead_percent(wire_len, plaintext_len),
             throughput_bps(wire_len, latency_e2e_us),
             (unsigned long)memory_before,
             (unsigned long)memory_after,
             (unsigned long)memory_min,
             rc == 0 ? 1 : 0);

    free(wire);
    free(payload);
    return rc;
}

static int send_ml_kem_algorithm(void)
{
    Esp32MlKemResult kem;
    uint8_t *wire = NULL;
    int64_t latency_e2e_us = 0;
    int rc = -1;

    if (esp32_ml_kem_run(&kem) != 0)
    {
        ESP_LOGE(TAG, "ML-KEM failed");
        return -1;
    }

    ESP_LOGI(TAG,
             "ml-kem keypair_us=%lld encaps_us=%lld decaps_us=%lld total_us=%lld pk=%u ct=%u wire=%u valid=%s ss_fp=%08lx memory_before=%lu memory_after=%lu memory_min=%lu",
             (long long)kem.keypair_us,
             (long long)kem.encaps_us,
             (long long)kem.decaps_us,
             (long long)kem.total_us,
             (unsigned)kem.public_key_len,
             (unsigned)kem.ciphertext_len,
             (unsigned)kem.wire_len,
             kem.valid ? "yes" : "no",
             (unsigned long)kem.ss_fingerprint,
             (unsigned long)kem.memory_before,
             (unsigned long)kem.memory_after,
             (unsigned long)kem.memory_min);

    wire = (uint8_t *)malloc(kem.wire_len);
    if (!wire)
    {
        ESP_LOGE(TAG, "ML-KEM wire allocation failed");
        esp32_ml_kem_result_free(&kem);
        return -1;
    }

    memcpy(wire, kem.public_key, kem.public_key_len);
    memcpy(wire + kem.public_key_len, kem.ciphertext, kem.ciphertext_len);

    rc = send_packet(IOT_ALG_ML_KEM,
                     IOT_PAYLOAD_PQC_HANDSHAKE,
                     wire,
                     kem.wire_len,
                     0,
                     &latency_e2e_us);

    ESP_LOGI(TAG,
             "metric device=esp32-lock alg=ml-kem seq=%lu payload=pqc-handshake pt=0 ct=%u pk=%u wire=%u encrypt_us=0 keypair_us=%lld encaps_us=%lld decaps_us=%lld total_kem_us=%lld latency_e2e_us=%lld overhead_bytes=%ld overhead_percent=0.00 throughput_Bps=%.2f memory_before_B=%lu memory_after_B=%lu memory_min_B=%lu valid_secret=%d ack_ok=%d size_ok=1",
             (unsigned long)sequence_number,
             (unsigned)kem.ciphertext_len,
             (unsigned)kem.public_key_len,
             (unsigned)kem.wire_len,
             (long long)kem.keypair_us,
             (long long)kem.encaps_us,
             (long long)kem.decaps_us,
             (long long)kem.total_us,
             (long long)latency_e2e_us,
             overhead_bytes(kem.wire_len, 0U),
             throughput_bps(kem.wire_len, latency_e2e_us),
             (unsigned long)kem.memory_before,
             (unsigned long)kem.memory_after,
             (unsigned long)kem.memory_min,
             kem.valid ? 1 : 0,
             rc == 0 ? 1 : 0);

    free(wire);
    esp32_ml_kem_result_free(&kem);
    return rc;
}

static int send_mceliece_algorithm(void)
{
    Esp32McelieceResult kem;
    uint8_t *wire = NULL;
    int64_t latency_e2e_us = 0;
    int rc = -1;

    if (esp32_mceliece_run(&kem) != 0)
    {
        ESP_LOGE(TAG, "Classic McEliece failed or unavailable");
        return -1;
    }

    ESP_LOGI(TAG,
             "mceliece keypair_us=%lld encaps_us=%lld decaps_us=%lld total_us=%lld pk=%u ct=%u wire=%u valid=%s ss_fp=%08lx memory_before=%lu memory_after=%lu memory_min=%lu",
             (long long)kem.keypair_us,
             (long long)kem.encaps_us,
             (long long)kem.decaps_us,
             (long long)kem.total_us,
             (unsigned)kem.public_key_len,
             (unsigned)kem.ciphertext_len,
             (unsigned)kem.wire_len,
             kem.valid ? "yes" : "no",
             (unsigned long)kem.ss_fingerprint,
             (unsigned long)kem.free_heap_before,
             (unsigned long)kem.free_heap_after,
             (unsigned long)kem.free_heap_min);

    wire = (uint8_t *)malloc(kem.wire_len);
    if (!wire)
    {
        ESP_LOGE(TAG,
                 "Classic McEliece wire allocation failed, wire=%u free_heap=%lu",
                 (unsigned)kem.wire_len,
                 (unsigned long)esp_get_free_heap_size());
        esp32_mceliece_result_free(&kem);
        return -1;
    }

    memcpy(wire, kem.public_key, kem.public_key_len);
    memcpy(wire + kem.public_key_len, kem.ciphertext, kem.ciphertext_len);

    rc = send_packet(IOT_ALG_CLASSIC_MCELIECE,
                     IOT_PAYLOAD_PQC_HANDSHAKE,
                     wire,
                     kem.wire_len,
                     0,
                     &latency_e2e_us);

    ESP_LOGI(TAG,
             "metric device=esp32-lock alg=classic-mceliece seq=%lu payload=pqc-handshake pt=0 ct=%u pk=%u wire=%u encrypt_us=0 keypair_us=%lld encaps_us=%lld decaps_us=%lld total_kem_us=%lld latency_e2e_us=%lld overhead_bytes=%ld overhead_percent=0.00 throughput_Bps=%.2f memory_before_B=%lu memory_after_B=%lu memory_min_B=%lu valid_secret=%d ack_ok=%d size_ok=1",
             (unsigned long)sequence_number,
             (unsigned)kem.ciphertext_len,
             (unsigned)kem.public_key_len,
             (unsigned)kem.wire_len,
             (long long)kem.keypair_us,
             (long long)kem.encaps_us,
             (long long)kem.decaps_us,
             (long long)kem.total_us,
             (long long)latency_e2e_us,
             overhead_bytes(kem.wire_len, 0U),
             throughput_bps(kem.wire_len, latency_e2e_us),
             (unsigned long)kem.free_heap_before,
             (unsigned long)kem.free_heap_after,
             (unsigned long)kem.free_heap_min,
             kem.valid ? 1 : 0,
             rc == 0 ? 1 : 0);

    free(wire);
    esp32_mceliece_result_free(&kem);
    return rc;
}

typedef struct
{
    TaskHandle_t caller;
    int result;
} MlKemTaskArgs;

static void ml_kem_task(void *arg)
{
    MlKemTaskArgs *args = (MlKemTaskArgs *)arg;

    args->result = send_ml_kem_algorithm();
    xTaskNotifyGive(args->caller);
    vTaskDelete(NULL);
}

static int run_ml_kem_in_dedicated_task(void)
{
    MlKemTaskArgs args = {
        .caller = xTaskGetCurrentTaskHandle(),
        .result = -1,
    };

    BaseType_t ok = xTaskCreatePinnedToCore(ml_kem_task,
                                            "mlkem_task",
                                            ML_KEM_TASK_STACK_SIZE,
                                            &args,
                                            ML_KEM_TASK_PRIORITY,
                                            NULL,
                                            1);
    if (ok != pdPASS)
    {
        ESP_LOGE(TAG,
                 "failed to create ML-KEM task, free_heap=%lu",
                 (unsigned long)esp_get_free_heap_size());
        return -1;
    }

    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    return args.result;
}

typedef struct
{
    TaskHandle_t caller;
    int result;
} McelieceTaskArgs;

static void mceliece_task(void *arg)
{
    McelieceTaskArgs *args = (McelieceTaskArgs *)arg;

    args->result = send_mceliece_algorithm();
    xTaskNotifyGive(args->caller);
    vTaskDelete(NULL);
}

static int run_mceliece_in_dedicated_task(void)
{
    McelieceTaskArgs args = {
        .caller = xTaskGetCurrentTaskHandle(),
        .result = -1,
    };

    BaseType_t ok = xTaskCreatePinnedToCore(mceliece_task,
                                            "mceliece_task",
                                            MCELIECE_TASK_STACK_SIZE,
                                            &args,
                                            MCELIECE_TASK_PRIORITY,
                                            NULL,
                                            1);
    if (ok != pdPASS)
    {
        ESP_LOGE(TAG,
                 "failed to create Classic McEliece task, free_heap=%lu",
                 (unsigned long)esp_get_free_heap_size());
        return -1;
    }

    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    return args.result;
}

static int run_selected_algorithm(uint8_t algorithm)
{
    switch (algorithm)
    {
    case CLIENT_ALG_AES:
        return send_aead_algorithm(IOT_ALG_AES256_GCM);
    case CLIENT_ALG_ASCON:
        return send_aead_algorithm(IOT_ALG_ASCON_128A);
    case CLIENT_ALG_ML_KEM:
        return run_ml_kem_in_dedicated_task();
    case CLIENT_ALG_MCELIECE:
        return run_mceliece_in_dedicated_task();
    default:
        return -1;
    }
}

static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        ESP_LOGW(TAG, "wifi disconnected, reconnecting");
        esp_wifi_connect();
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "got ip: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void)
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_config_t wifi_config = {0};

    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    strncpy((char *)wifi_config.sta.ssid, WIFI_SSID, sizeof(wifi_config.sta.ssid) - 1U);
    strncpy((char *)wifi_config.sta.password, WIFI_PASSWORD, sizeof(wifi_config.sta.password) - 1U);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.sta.pmf_cfg.capable = true;
    wifi_config.sta.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

static void wait_for_wifi(void)
{
    xEventGroupWaitBits(wifi_event_group,
                        WIFI_CONNECTED_BIT,
                        pdFALSE,
                        pdFALSE,
                        portMAX_DELAY);
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    if (hex_to_bytes(AES256_HEX_KEY, aes_key, AES_KEY_SIZE) != 0)
    {
        ESP_LOGE(TAG, "invalid AES256_HEX_KEY");
        return;
    }

    if (hex_to_bytes(ASCON_HEX_KEY, ascon_key, ASCON_KEY_SIZE) != 0)
    {
        ESP_LOGE(TAG, "invalid ASCON_HEX_KEY");
        return;
    }

    if (psa_aes256_init_key() != 0)
    {
        return;
    }

    wifi_init_sta();
    wait_for_wifi();

    while (1)
    {
#if CLIENT_ALGORITHM == CLIENT_ALG_ALL || CLIENT_ALGORITHM == CLIENT_ALG_ALL_WITH_ML_KEM || CLIENT_ALGORITHM == CLIENT_ALG_ALL_WITH_PQC
        const uint8_t algs[] = {
            CLIENT_ALG_AES,
            CLIENT_ALG_ASCON
#if CLIENT_ALGORITHM == CLIENT_ALG_ALL_WITH_ML_KEM || CLIENT_ALGORITHM == CLIENT_ALG_ALL_WITH_PQC
            ,
            CLIENT_ALG_ML_KEM
#endif
#if CLIENT_ALGORITHM == CLIENT_ALG_ALL_WITH_PQC
            ,
            CLIENT_ALG_MCELIECE
#endif
        };
        size_t i = 0;
        for (i = 0; i < sizeof(algs) / sizeof(algs[0]); ++i)
        {
            wait_for_wifi();
            if (run_selected_algorithm(algs[i]) == 0)
            {
                sequence_number++;
            }
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
#else
        wait_for_wifi();
        if (run_selected_algorithm(CLIENT_ALGORITHM) == 0)
        {
            sequence_number++;
        }
#endif

        lock_state = !lock_state;
        if (battery_millivolts > 3600)
        {
            battery_millivolts -= 3;
        }

        vTaskDelay(pdMS_TO_TICKS(SEND_INTERVAL_MS));
    }
}
