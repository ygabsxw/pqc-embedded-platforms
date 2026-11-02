#include "esp32_ml_kem.h"

#include <string.h>

#include "api.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_timer.h"

static uint32_t fingerprint32(const uint8_t *buf, size_t len)
{
    uint32_t h = 2166136261u;

    for (size_t i = 0; i < len; i++)
    {
        h ^= buf[i];
        h *= 16777619u;
    }

    return h;
}

static void secure_zero(uint8_t *buf, size_t len)
{
    if (!buf)
    {
        return;
    }

    volatile uint8_t *p = buf;
    for (size_t i = 0; i < len; i++)
    {
        p[i] = 0;
    }
}

int esp32_ml_kem_run(Esp32MlKemResult *result)
{
    if (!result)
    {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->memory_before = esp_get_free_heap_size();

    uint8_t *pk = heap_caps_malloc(ESP32_ML_KEM_PUBLIC_KEY_BYTES, MALLOC_CAP_8BIT);
    uint8_t *sk = heap_caps_malloc(ESP32_ML_KEM_SECRET_KEY_BYTES, MALLOC_CAP_8BIT);
    uint8_t *ct = heap_caps_malloc(ESP32_ML_KEM_CIPHERTEXT_BYTES, MALLOC_CAP_8BIT);
    uint8_t *ss_enc = heap_caps_malloc(ESP32_ML_KEM_SHARED_SECRET_BYTES, MALLOC_CAP_8BIT);
    uint8_t *ss_dec = heap_caps_malloc(ESP32_ML_KEM_SHARED_SECRET_BYTES, MALLOC_CAP_8BIT);

    if (!pk || !sk || !ct || !ss_enc || !ss_dec)
    {
        heap_caps_free(pk);
        heap_caps_free(sk);
        heap_caps_free(ct);
        heap_caps_free(ss_enc);
        heap_caps_free(ss_dec);
        return -1;
    }

    int64_t total_start = esp_timer_get_time();

    int64_t start = esp_timer_get_time();
    int ret = pqcrystals_kyber768_ref_keypair(pk, sk);
    result->keypair_us = esp_timer_get_time() - start;
    if (ret != 0)
    {
        goto fail;
    }

    start = esp_timer_get_time();
    ret = pqcrystals_kyber768_ref_enc(ct, ss_enc, pk);
    result->encaps_us = esp_timer_get_time() - start;
    if (ret != 0)
    {
        goto fail;
    }

    start = esp_timer_get_time();
    ret = pqcrystals_kyber768_ref_dec(ss_dec, ct, sk);
    result->decaps_us = esp_timer_get_time() - start;
    if (ret != 0)
    {
        goto fail;
    }

    result->total_us = esp_timer_get_time() - total_start;
    result->valid = memcmp(ss_enc, ss_dec, ESP32_ML_KEM_SHARED_SECRET_BYTES) == 0;
    result->ss_fingerprint = fingerprint32(ss_enc, ESP32_ML_KEM_SHARED_SECRET_BYTES);
    result->memory_after = esp_get_free_heap_size();
    result->memory_min = esp_get_minimum_free_heap_size();

    secure_zero(sk, ESP32_ML_KEM_SECRET_KEY_BYTES);
    secure_zero(ss_enc, ESP32_ML_KEM_SHARED_SECRET_BYTES);
    secure_zero(ss_dec, ESP32_ML_KEM_SHARED_SECRET_BYTES);

    heap_caps_free(sk);
    heap_caps_free(ss_enc);
    heap_caps_free(ss_dec);

    result->public_key = pk;
    result->ciphertext = ct;
    result->public_key_len = ESP32_ML_KEM_PUBLIC_KEY_BYTES;
    result->ciphertext_len = ESP32_ML_KEM_CIPHERTEXT_BYTES;
    result->wire_len = ESP32_ML_KEM_WIRE_BYTES;

    return result->valid ? 0 : -1;

fail:
    secure_zero(sk, ESP32_ML_KEM_SECRET_KEY_BYTES);
    secure_zero(ss_enc, ESP32_ML_KEM_SHARED_SECRET_BYTES);
    secure_zero(ss_dec, ESP32_ML_KEM_SHARED_SECRET_BYTES);

    heap_caps_free(pk);
    heap_caps_free(sk);
    heap_caps_free(ct);
    heap_caps_free(ss_enc);
    heap_caps_free(ss_dec);

    memset(result, 0, sizeof(*result));
    return -1;
}

void esp32_ml_kem_result_free(Esp32MlKemResult *result)
{
    if (!result)
    {
        return;
    }

    heap_caps_free(result->public_key);
    heap_caps_free(result->ciphertext);
    memset(result, 0, sizeof(*result));
}
