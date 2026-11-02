#include "classic_mceliece_api.h"

#include "api.h"

_Static_assert(CLASSIC_MCELIECE_348864_PUBLIC_KEY_BYTES ==
                   PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES,
               "Classic McEliece public-key size mismatch");
_Static_assert(CLASSIC_MCELIECE_348864_SECRET_KEY_BYTES ==
                   PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES,
               "Classic McEliece secret-key size mismatch");
_Static_assert(CLASSIC_MCELIECE_348864_CIPHERTEXT_BYTES ==
                   PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES,
               "Classic McEliece ciphertext size mismatch");
_Static_assert(CLASSIC_MCELIECE_348864_SHARED_SECRET_BYTES ==
                   PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_BYTES,
               "Classic McEliece shared-secret size mismatch");

int classic_mceliece_348864_keypair(uint8_t *pk, uint8_t *sk)
{
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pk, sk);
}

int classic_mceliece_348864_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int classic_mceliece_348864_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec(ss, ct, sk);
}
