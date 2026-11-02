#ifndef AES256_H
#define AES256_H

#include <stddef.h>
#include <stdint.h>

#define AES256_KEY_SIZE 32
#define AES256_NONCE_SIZE 12
#define AES256_TAG_SIZE 16
#define AES256_OVERHEAD_BYTES (AES256_NONCE_SIZE + AES256_TAG_SIZE)

typedef struct
{
    uint8_t key[AES256_KEY_SIZE];
    int initialized;
} AES256Context;

int aes256_keygen(AES256Context *ctx);

int aes256_encrypt(const AES256Context *ctx,
                   const uint8_t *plaintext,
                   size_t pt_len,
                   uint8_t *ciphertext,
                   size_t *ct_len);

int aes256_decrypt(const AES256Context *ctx,
                   const uint8_t *ciphertext,
                   size_t ct_len,
                   uint8_t *plaintext,
                   size_t *pt_len);

void aes256_context_free(AES256Context *ctx);

#endif
