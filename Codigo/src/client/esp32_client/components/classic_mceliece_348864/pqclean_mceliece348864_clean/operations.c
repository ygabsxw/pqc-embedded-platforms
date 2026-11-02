#include "operations.h"

#include "controlbits.h"
#include "crypto_hash.h"
#include "decrypt.h"
#include "params.h"
#include "pk_gen.h"
#include "randombytes.h"
#include "sk_gen.h"
#include "util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#endif

/* Include last because of issues with unistd.h's encrypt definition */
#include "encrypt.h"

static void *mceliece_alloc(size_t len) {
#ifdef ESP_PLATFORM
#ifdef CONFIG_SPIRAM
    void *p = heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p != NULL) {
        return p;
    }
#endif
    return heap_caps_malloc(len, MALLOC_CAP_8BIT);
#else
    return malloc(len);
#endif
}

static void mceliece_free(void *ptr) {
#ifdef ESP_PLATFORM
    heap_caps_free(ptr);
#else
    free(ptr);
#endif
}

int crypto_kem_enc(
    unsigned char *c,
    unsigned char *key,
    const unsigned char *pk
) {
    unsigned char e[ SYS_N / 8 ];
    unsigned char one_ec[ 1 + SYS_N / 8 + SYND_BYTES ] = {1};

    //

    encrypt(c, pk, e);

    memcpy(one_ec + 1, e, SYS_N / 8);
    memcpy(one_ec + 1 + SYS_N / 8, c, SYND_BYTES);

    crypto_hash_32b(key, one_ec, sizeof(one_ec));

    return 0;
}

int crypto_kem_dec(
    unsigned char *key,
    const unsigned char *c,
    const unsigned char *sk
) {
    int i;

    unsigned char ret_decrypt = 0;

    uint16_t m;

    unsigned char e[ SYS_N / 8 ];
    unsigned char preimage[ 1 + SYS_N / 8 + SYND_BYTES ];
    unsigned char *x = preimage;
    const unsigned char *s = sk + 40 + IRR_BYTES + COND_BYTES;

    //

    ret_decrypt = (unsigned char)decrypt(e, sk + 40, c);

    m = ret_decrypt;
    m -= 1;
    m >>= 8;

    *x++ = m & 1;
    for (i = 0; i < SYS_N / 8; i++) {
        *x++ = (~m & s[i]) | (m & e[i]);
    }

    for (i = 0; i < SYND_BYTES; i++) {
        *x++ = c[i];
    }

    crypto_hash_32b(key, preimage, sizeof(preimage));

    return 0;
}

int crypto_kem_keypair
(
    unsigned char *pk,
    unsigned char *sk
) {
    int i;
    int ret = -1;
    unsigned char seed[ 33 ] = {64};
    const size_t r_len = SYS_N / 8 + (1 << GFBITS)*sizeof(uint32_t) + SYS_T * 2 + 32;
    const size_t perm_len = (1 << GFBITS) * sizeof(uint32_t);
    unsigned char *r = mceliece_alloc(r_len);
    unsigned char *rp, *skp;

    gf f[ SYS_T ]; // element in GF(2^mt)
    gf irr[ SYS_T ]; // Goppa polynomial
    uint32_t *perm = mceliece_alloc((1 << GFBITS) * sizeof(*perm)); // random permutation as 32-bit integers
    int16_t *pi = mceliece_alloc((1 << GFBITS) * sizeof(*pi)); // random permutation

    if (r == NULL || perm == NULL || pi == NULL) {
        goto cleanup;
    }

    randombytes(seed + 1, 32);

    while (1) {
        rp = &r[ r_len - 32 ];
        skp = sk;

        // expanding and updating the seed

        shake(r, r_len, seed, 33);
        memcpy(skp, seed + 1, 32);
        skp += 32 + 8;
        memcpy(seed + 1, &r[ r_len - 32 ], 32);

        // generating irreducible polynomial

        rp -= sizeof(f);

        for (i = 0; i < SYS_T; i++) {
            f[i] = load_gf(rp + i * 2);
        }

        if (genpoly_gen(irr, f)) {
            continue;
        }

        for (i = 0; i < SYS_T; i++) {
            store_gf(skp + i * 2, irr[i]);
        }

        skp += IRR_BYTES;

        // generating permutation

        rp -= perm_len;

        for (i = 0; i < (1 << GFBITS); i++) {
            perm[i] = load4(rp + i * 4);
        }

        ret = pk_gen(pk, skp - IRR_BYTES, perm, pi);
        if (ret == -2) {
            goto cleanup;
        }
        if (ret != 0) {
            continue;
        }

        controlbitsfrompermutation(skp, pi, GFBITS, 1 << GFBITS);
        skp += COND_BYTES;

        // storing the random string s

        rp -= SYS_N / 8;
        memcpy(skp, rp, SYS_N / 8);

        // storing positions of the 32 pivots

        store8(sk + 32, 0xFFFFFFFF);

        break;
    }

    ret = 0;

cleanup:
    mceliece_free(r);
    mceliece_free(perm);
    mceliece_free(pi);
    return ret;
}
