#ifndef PQC_COMMON_H
#define PQC_COMMON_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret_enc;
    uint8_t *shared_secret_dec;

    size_t public_key_len;
    size_t secret_key_len;
    size_t ciphertext_len;
    size_t shared_secret_len;

    double keypair_us;
    double encaps_us;
    double decaps_us;
    double total_us;
} PQCKEMResult;

#endif
