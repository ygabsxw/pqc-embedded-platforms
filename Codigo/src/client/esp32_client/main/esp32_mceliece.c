#include "esp32_mceliece.h"

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"

/*
 * A implementacao real fica no componente ESP-IDF classic_mceliece_348864.
 * Sem ENABLE_ESP32_MCELIECE, este arquivo compila em modo seguro e retorna
 * erro controlado.
 */
#ifdef ENABLE_ESP32_MCELIECE
#include "classic_mceliece_api.h"
#endif

static const char *TAG_MCELIECE = "esp32-mceliece";

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

static uint8_t *alloc_crypto_buffer(size_t len)
{
    uint8_t *p = NULL;

#ifdef CONFIG_SPIRAM
    p = heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p)
    {
        return p;
    }
#endif

    return heap_caps_malloc(len, MALLOC_CAP_8BIT);
}

int esp32_mceliece_run(Esp32McelieceResult *result)
{
    if (!result)
    {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->free_heap_before = esp_get_free_heap_size();

#ifndef ENABLE_ESP32_MCELIECE
    ESP_LOGE(TAG_MCELIECE,
             "Classic McEliece nao esta ligado: adicione componente externo e compile com ENABLE_ESP32_MCELIECE");
    return -2;
#else
    uint8_t *pk = alloc_crypto_buffer(ESP32_MCELIECE_PUBLIC_KEY_BYTES);
    uint8_t *sk = alloc_crypto_buffer(ESP32_MCELIECE_SECRET_KEY_BYTES);
    uint8_t *ct = alloc_crypto_buffer(ESP32_MCELIECE_CIPHERTEXT_BYTES);
    uint8_t *ss_enc = alloc_crypto_buffer(ESP32_MCELIECE_SHARED_SECRET_BYTES);
    uint8_t *ss_dec = alloc_crypto_buffer(ESP32_MCELIECE_SHARED_SECRET_BYTES);

    if (!pk || !sk || !ct || !ss_enc || !ss_dec)
    {
        ESP_LOGE(TAG_MCELIECE,
                 "falha de memoria: pk=%p sk=%p ct=%p ss_enc=%p ss_dec=%p free_heap=%lu",
                 pk,
                 sk,
                 ct,
                 ss_enc,
                 ss_dec,
                 (unsigned long)esp_get_free_heap_size());
        heap_caps_free(pk);
        heap_caps_free(sk);
        heap_caps_free(ct);
        heap_caps_free(ss_enc);
        heap_caps_free(ss_dec);
        return -1;
    }

    int64_t total_start = esp_timer_get_time();

    int64_t start = esp_timer_get_time();
    int ret = classic_mceliece_348864_keypair(pk, sk);
    result->keypair_us = esp_timer_get_time() - start;
    if (ret != 0)
    {
        ESP_LOGE(TAG_MCELIECE,
                 "Classic McEliece keypair failed ret=%d free_heap=%lu min_heap=%lu",
                 ret,
                 (unsigned long)esp_get_free_heap_size(),
                 (unsigned long)esp_get_minimum_free_heap_size());
        goto fail;
    }

    start = esp_timer_get_time();
    ret = classic_mceliece_348864_enc(ct, ss_enc, pk);
    result->encaps_us = esp_timer_get_time() - start;
    if (ret != 0)
    {
        ESP_LOGE(TAG_MCELIECE,
                 "Classic McEliece encaps failed ret=%d free_heap=%lu min_heap=%lu",
                 ret,
                 (unsigned long)esp_get_free_heap_size(),
                 (unsigned long)esp_get_minimum_free_heap_size());
        goto fail;
    }

    start = esp_timer_get_time();
    ret = classic_mceliece_348864_dec(ss_dec, ct, sk);
    result->decaps_us = esp_timer_get_time() - start;
    if (ret != 0)
    {
        ESP_LOGE(TAG_MCELIECE,
                 "Classic McEliece decaps failed ret=%d free_heap=%lu min_heap=%lu",
                 ret,
                 (unsigned long)esp_get_free_heap_size(),
                 (unsigned long)esp_get_minimum_free_heap_size());
        goto fail;
    }

    result->total_us = esp_timer_get_time() - total_start;
    result->valid = memcmp(ss_enc, ss_dec, ESP32_MCELIECE_SHARED_SECRET_BYTES) == 0;
    result->ss_fingerprint = fingerprint32(ss_enc, ESP32_MCELIECE_SHARED_SECRET_BYTES);
    result->free_heap_after = esp_get_free_heap_size();
    result->free_heap_min = esp_get_minimum_free_heap_size();

    secure_zero(sk, ESP32_MCELIECE_SECRET_KEY_BYTES);
    secure_zero(ss_enc, ESP32_MCELIECE_SHARED_SECRET_BYTES);
    secure_zero(ss_dec, ESP32_MCELIECE_SHARED_SECRET_BYTES);

    heap_caps_free(sk);
    heap_caps_free(ss_enc);
    heap_caps_free(ss_dec);

    result->public_key = pk;
    result->ciphertext = ct;
    result->public_key_len = ESP32_MCELIECE_PUBLIC_KEY_BYTES;
    result->ciphertext_len = ESP32_MCELIECE_CIPHERTEXT_BYTES;
    result->wire_len = ESP32_MCELIECE_WIRE_BYTES;

    return result->valid ? 0 : -1;

fail:
    ESP_LOGE(TAG_MCELIECE, "Classic McEliece falhou durante keypair/enc/dec");

    secure_zero(sk, ESP32_MCELIECE_SECRET_KEY_BYTES);
    secure_zero(ss_enc, ESP32_MCELIECE_SHARED_SECRET_BYTES);
    secure_zero(ss_dec, ESP32_MCELIECE_SHARED_SECRET_BYTES);

    heap_caps_free(pk);
    heap_caps_free(sk);
    heap_caps_free(ct);
    heap_caps_free(ss_enc);
    heap_caps_free(ss_dec);

    memset(result, 0, sizeof(*result));
    return -1;
#endif
}

void esp32_mceliece_result_free(Esp32McelieceResult *result)
{
    if (!result)
    {
        return;
    }

    heap_caps_free(result->public_key);
    heap_caps_free(result->ciphertext);
    memset(result, 0, sizeof(*result));
}
