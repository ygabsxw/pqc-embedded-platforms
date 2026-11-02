#ifndef ESP32_MCELIECE_H
#define ESP32_MCELIECE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ESP32_MCELIECE_PUBLIC_KEY_BYTES 261120U
#define ESP32_MCELIECE_SECRET_KEY_BYTES 6492U
#define ESP32_MCELIECE_CIPHERTEXT_BYTES 96U
#define ESP32_MCELIECE_SHARED_SECRET_BYTES 32U
#define ESP32_MCELIECE_WIRE_BYTES \
    (ESP32_MCELIECE_PUBLIC_KEY_BYTES + ESP32_MCELIECE_CIPHERTEXT_BYTES)

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
    uint32_t free_heap_before;
    uint32_t free_heap_after;
    uint32_t free_heap_min;
    bool valid;
    uint32_t ss_fingerprint;
} Esp32McelieceResult;

int esp32_mceliece_run(Esp32McelieceResult *result);
void esp32_mceliece_result_free(Esp32McelieceResult *result);

#endif
