#ifndef ESP32_ML_KEM_H
#define ESP32_ML_KEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ESP32_ML_KEM_PUBLIC_KEY_BYTES 1184U
#define ESP32_ML_KEM_SECRET_KEY_BYTES 2400U
#define ESP32_ML_KEM_CIPHERTEXT_BYTES 1088U
#define ESP32_ML_KEM_SHARED_SECRET_BYTES 32U
#define ESP32_ML_KEM_WIRE_BYTES \
    (ESP32_ML_KEM_PUBLIC_KEY_BYTES + ESP32_ML_KEM_CIPHERTEXT_BYTES)

typedef struct
{
    uint8_t *public_key;
    uint8_t *ciphertext;
    size_t public_key_len;
    size_t ciphertext_len;
    size_t wire_len;
    int64_t keypair_us;
    int64_t encaps_us;
    int64_t decaps_us;
    int64_t total_us;
    uint32_t memory_before;
    uint32_t memory_after;
    uint32_t memory_min;
    bool valid;
    uint32_t ss_fingerprint;
} Esp32MlKemResult;

int esp32_ml_kem_run(Esp32MlKemResult *result);
void esp32_ml_kem_result_free(Esp32MlKemResult *result);

#endif
