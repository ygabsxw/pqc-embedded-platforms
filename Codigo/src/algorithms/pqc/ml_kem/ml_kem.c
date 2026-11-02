#include "ml_kem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <oqs/oqs.h>

static const char *ml_kem_oqs_name(void)
{
#ifdef OQS_KEM_alg_ml_kem_768
    return OQS_KEM_alg_ml_kem_768;
#elif defined(OQS_KEM_alg_kyber_768)
    return OQS_KEM_alg_kyber_768;
#else
    return "ML-KEM-768";
#endif
}

static void result_zero(PQCKEMResult *result)
{
    if (!result)
    {
        return;
    }

    memset(result, 0, sizeof(*result));
}

static int result_alloc(PQCKEMResult *result, const OQS_KEM *kem)
{
    result->public_key_len = kem->length_public_key;
    result->secret_key_len = kem->length_secret_key;
    result->ciphertext_len = kem->length_ciphertext;
    result->shared_secret_len = kem->length_shared_secret;

    result->public_key = (uint8_t *)malloc(result->public_key_len);
    result->secret_key = (uint8_t *)malloc(result->secret_key_len);
    result->ciphertext = (uint8_t *)malloc(result->ciphertext_len);
    result->shared_secret_enc = (uint8_t *)malloc(result->shared_secret_len);
    result->shared_secret_dec = (uint8_t *)malloc(result->shared_secret_len);

    if (!result->public_key ||
        !result->secret_key ||
        !result->ciphertext ||
        !result->shared_secret_enc ||
        !result->shared_secret_dec)
    {
        return -1;
    }

    return 0;
}

static double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;
}

int ml_kem_run(PQCKEMResult *result)
{
    const char *alg_name = ml_kem_oqs_name();
    OQS_KEM *kem = NULL;
    double total_start = 0.0;
    double start = 0.0;

    if (!result)
    {
        return -1;
    }

    result_zero(result);

    if (!OQS_KEM_alg_is_enabled(alg_name))
    {
        fprintf(stderr, "[ml-kem] algorithm is not enabled in liboqs: %s\n", alg_name);
        return -1;
    }

    kem = OQS_KEM_new(alg_name);
    if (!kem)
    {
        fprintf(stderr, "[ml-kem] OQS_KEM_new failed for %s\n", alg_name);
        return -1;
    }

    if (result_alloc(result, kem) != 0)
    {
        fprintf(stderr, "[ml-kem] buffer allocation failed\n");
        OQS_KEM_free(kem);
        ml_kem_result_free(result);
        return -1;
    }

    total_start = now_us();

    start = now_us();
    if (OQS_KEM_keypair(kem, result->public_key, result->secret_key) != OQS_SUCCESS)
    {
        fprintf(stderr, "[ml-kem] keypair failed\n");
        OQS_KEM_free(kem);
        ml_kem_result_free(result);
        return -1;
    }
    result->keypair_us = now_us() - start;

    start = now_us();
    if (OQS_KEM_encaps(kem,
                       result->ciphertext,
                       result->shared_secret_enc,
                       result->public_key) != OQS_SUCCESS)
    {
        fprintf(stderr, "[ml-kem] encaps failed\n");
        OQS_KEM_free(kem);
        ml_kem_result_free(result);
        return -1;
    }
    result->encaps_us = now_us() - start;

    start = now_us();
    if (OQS_KEM_decaps(kem,
                       result->shared_secret_dec,
                       result->ciphertext,
                       result->secret_key) != OQS_SUCCESS)
    {
        fprintf(stderr, "[ml-kem] decaps failed\n");
        OQS_KEM_free(kem);
        ml_kem_result_free(result);
        return -1;
    }
    result->decaps_us = now_us() - start;
    result->total_us = now_us() - total_start;

    if (memcmp(result->shared_secret_enc,
               result->shared_secret_dec,
               result->shared_secret_len) != 0)
    {
        fprintf(stderr, "[ml-kem] shared secret validation failed\n");
        OQS_KEM_free(kem);
        ml_kem_result_free(result);
        return -1;
    }

    OQS_KEM_free(kem);
    return 0;
}

void ml_kem_result_free(PQCKEMResult *result)
{
    if (!result)
    {
        return;
    }

    if (result->secret_key)
    {
        OQS_MEM_cleanse(result->secret_key, result->secret_key_len);
        free(result->secret_key);
    }

    if (result->shared_secret_enc)
    {
        OQS_MEM_cleanse(result->shared_secret_enc, result->shared_secret_len);
        free(result->shared_secret_enc);
    }

    if (result->shared_secret_dec)
    {
        OQS_MEM_cleanse(result->shared_secret_dec, result->shared_secret_len);
        free(result->shared_secret_dec);
    }

    free(result->public_key);
    free(result->ciphertext);

    result_zero(result);
}
