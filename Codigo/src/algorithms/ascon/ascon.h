#ifndef ASCON_H
#define ASCON_H

#include <stddef.h>
#include <stdint.h>

#define ASCON_KEY_SIZE 16
#define ASCON_NONCE_SIZE 16
#define ASCON_TAG_SIZE 16
#define ASCON_OVERHEAD_BYTES 32

typedef struct
{
    uint8_t key[ASCON_KEY_SIZE];
    int initialized;
} AsconContext;

int ascon_keygen(AsconContext *ctx);

int ascon_encrypt(const AsconContext *ctx,
                  const uint8_t *plaintext,
                  size_t pt_len,
                  uint8_t *ciphertext,
                  size_t *ct_len);

int ascon_decrypt(const AsconContext *ctx,
                  const uint8_t *ciphertext,
                  size_t ct_len,
                  uint8_t *plaintext,
                  size_t *pt_len);

void ascon_context_free(AsconContext *ctx);

#endif
