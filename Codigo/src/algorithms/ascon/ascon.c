#include "ascon.h"
#include "ascon_ref/ascon_api.h"

#include <stdio.h>
#include <string.h>

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub,
                        const unsigned char *k);

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec, const unsigned char *c,
                        unsigned long long clen, const unsigned char *ad,
                        unsigned long long adlen, const unsigned char *npub,
                        const unsigned char *k);

static int read_random_bytes(uint8_t *buf, size_t len)
{
    FILE *fp = fopen("/dev/urandom", "rb");
    size_t n = 0;

    if (!fp)
    {
        perror("[ascon] fopen /dev/urandom");
        return -1;
    }

    n = fread(buf, 1, len, fp);
    fclose(fp);

    if (n != len)
    {
        fprintf(stderr, "[ascon] incomplete read from /dev/urandom\n");
        return -1;
    }

    return 0;
}

int ascon_keygen(AsconContext *ctx)
{
    if (!ctx)
    {
        return -1;
    }

    if (read_random_bytes(ctx->key, ASCON_KEY_SIZE) != 0)
    {
        return -1;
    }

    ctx->initialized = 1;
    return 0;
}

int ascon_encrypt(const AsconContext *ctx,
                  const uint8_t *plaintext,
                  size_t pt_len,
                  uint8_t *ciphertext,
                  size_t *ct_len)
{
    uint8_t nonce[ASCON_NONCE_SIZE];
    unsigned long long ref_ct_len = 0;
    int ret = 0;

    if (!ctx || !ctx->initialized || !plaintext || !ciphertext || !ct_len)
    {
        return -1;
    }

    if (read_random_bytes(nonce, ASCON_NONCE_SIZE) != 0)
    {
        return -1;
    }

    memcpy(ciphertext, nonce, ASCON_NONCE_SIZE);

    ret = crypto_aead_encrypt(ciphertext + ASCON_NONCE_SIZE,
                              &ref_ct_len,
                              plaintext,
                              (unsigned long long)pt_len,
                              NULL,
                              0,
                              NULL,
                              nonce,
                              ctx->key);

    if (ret != 0)
    {
        fprintf(stderr, "[ascon] crypto_aead_encrypt failed\n");
        return -1;
    }

    *ct_len = ASCON_NONCE_SIZE + (size_t)ref_ct_len;
    return 0;
}

int ascon_decrypt(const AsconContext *ctx,
                  const uint8_t *ciphertext,
                  size_t ct_len,
                  uint8_t *plaintext,
                  size_t *pt_len)
{
    const uint8_t *nonce = NULL;
    const uint8_t *data_src = NULL;
    size_t data_len = 0;
    unsigned long long ref_pt_len = 0;
    int ret = 0;

    if (!ctx || !ctx->initialized || !ciphertext || !plaintext || !pt_len)
    {
        return -1;
    }

    if (ct_len <= ASCON_OVERHEAD_BYTES)
    {
        fprintf(stderr, "[ascon] ciphertext too short (%zu bytes)\n", ct_len);
        return -1;
    }

    nonce = ciphertext;
    data_src = ciphertext + ASCON_NONCE_SIZE;
    data_len = ct_len - ASCON_NONCE_SIZE;

    ret = crypto_aead_decrypt(plaintext,
                              &ref_pt_len,
                              NULL,
                              data_src,
                              (unsigned long long)data_len,
                              NULL,
                              0,
                              nonce,
                              ctx->key);

    if (ret != 0)
    {
        fprintf(stderr, "[ascon] authentication failed\n");
        return -1;
    }

    *pt_len = (size_t)ref_pt_len;
    return 0;
}

void ascon_context_free(AsconContext *ctx)
{
    volatile uint8_t *p = NULL;
    size_t i = 0;

    if (!ctx)
    {
        return;
    }

    p = ctx->key;
    for (i = 0; i < ASCON_KEY_SIZE; ++i)
    {
        p[i] = 0;
    }
    ctx->initialized = 0;
}
