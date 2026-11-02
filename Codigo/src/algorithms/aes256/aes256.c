#include "aes256.h"

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static int openssl_error(const char *context)
{
    fprintf(stderr, "[aes256] error in %s: ", context);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
    return -1;
}

int aes256_keygen(AES256Context *ctx)
{
    if (!ctx)
    {
        return -1;
    }

    if (RAND_bytes(ctx->key, AES256_KEY_SIZE) != 1)
    {
        return openssl_error("RAND_bytes (keygen)");
    }

    ctx->initialized = 1;
    return 0;
}

int aes256_encrypt(const AES256Context *ctx,
                   const uint8_t *plaintext,
                   size_t pt_len,
                   uint8_t *ciphertext,
                   size_t *ct_len)
{
    if (!ctx || !ctx->initialized || !plaintext || !ciphertext || !ct_len)
    {
        return -1;
    }

    EVP_CIPHER_CTX *evp_ctx = NULL;
    int out_len = 0;
    int final_len = 0;
    uint8_t nonce[AES256_NONCE_SIZE];
    uint8_t *data_dst = NULL;
    uint8_t *tag_dst = NULL;

    if (RAND_bytes(nonce, AES256_NONCE_SIZE) != 1)
    {
        return openssl_error("RAND_bytes (nonce)");
    }

    memcpy(ciphertext, nonce, AES256_NONCE_SIZE);
    data_dst = ciphertext + AES256_NONCE_SIZE;

    evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx)
    {
        return openssl_error("EVP_CIPHER_CTX_new");
    }

    if (EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_gcm(), NULL, ctx->key, nonce) != 1)
    {
        EVP_CIPHER_CTX_free(evp_ctx);
        return openssl_error("EVP_EncryptInit_ex");
    }

    if (EVP_EncryptUpdate(evp_ctx, data_dst, &out_len, plaintext, (int)pt_len) != 1)
    {
        EVP_CIPHER_CTX_free(evp_ctx);
        return openssl_error("EVP_EncryptUpdate");
    }

    if (EVP_EncryptFinal_ex(evp_ctx, data_dst + out_len, &final_len) != 1)
    {
        EVP_CIPHER_CTX_free(evp_ctx);
        return openssl_error("EVP_EncryptFinal_ex");
    }

    tag_dst = data_dst + out_len + final_len;
    if (EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, AES256_TAG_SIZE, tag_dst) != 1)
    {
        EVP_CIPHER_CTX_free(evp_ctx);
        return openssl_error("EVP_CTRL_GCM_GET_TAG");
    }

    EVP_CIPHER_CTX_free(evp_ctx);
    *ct_len = AES256_NONCE_SIZE + (size_t)(out_len + final_len) + AES256_TAG_SIZE;
    return 0;
}

int aes256_decrypt(const AES256Context *ctx,
                   const uint8_t *ciphertext,
                   size_t ct_len,
                   uint8_t *plaintext,
                   size_t *pt_len)
{
    if (!ctx || !ctx->initialized || !ciphertext || !plaintext || !pt_len)
    {
        return -1;
    }

    if (ct_len <= AES256_OVERHEAD_BYTES)
    {
        fprintf(stderr, "[aes256] ciphertext too short (%zu bytes)\n", ct_len);
        return -1;
    }

    EVP_CIPHER_CTX *evp_ctx = NULL;
    int out_len = 0;
    int final_len = 0;
    const uint8_t *nonce_src = ciphertext;
    const uint8_t *data_src = ciphertext + AES256_NONCE_SIZE;
    size_t data_len = ct_len - AES256_OVERHEAD_BYTES;
    uint8_t tag[AES256_TAG_SIZE];

    memcpy(tag, ciphertext + ct_len - AES256_TAG_SIZE, AES256_TAG_SIZE);

    evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx)
    {
        return openssl_error("EVP_CIPHER_CTX_new (decrypt)");
    }

    if (EVP_DecryptInit_ex(evp_ctx, EVP_aes_256_gcm(), NULL, ctx->key, nonce_src) != 1)
    {
        EVP_CIPHER_CTX_free(evp_ctx);
        return openssl_error("EVP_DecryptInit_ex");
    }

    if (EVP_DecryptUpdate(evp_ctx, plaintext, &out_len, data_src, (int)data_len) != 1)
    {
        EVP_CIPHER_CTX_free(evp_ctx);
        return openssl_error("EVP_DecryptUpdate");
    }

    if (EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG, AES256_TAG_SIZE, tag) != 1)
    {
        EVP_CIPHER_CTX_free(evp_ctx);
        return openssl_error("EVP_CTRL_GCM_SET_TAG");
    }

    if (EVP_DecryptFinal_ex(evp_ctx, plaintext + out_len, &final_len) != 1)
    {
        EVP_CIPHER_CTX_free(evp_ctx);
        fprintf(stderr, "[aes256] authentication failed (invalid GCM tag)\n");
        return -1;
    }

    EVP_CIPHER_CTX_free(evp_ctx);
    *pt_len = (size_t)(out_len + final_len);
    return 0;
}

void aes256_context_free(AES256Context *ctx)
{
    if (!ctx)
    {
        return;
    }

    OPENSSL_cleanse(ctx->key, AES256_KEY_SIZE);
    ctx->initialized = 0;
}
