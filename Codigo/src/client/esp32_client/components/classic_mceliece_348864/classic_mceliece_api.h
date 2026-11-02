#ifndef CLASSIC_MCELIECE_API_H
#define CLASSIC_MCELIECE_API_H

#include <stdint.h>

#define CLASSIC_MCELIECE_348864_PUBLIC_KEY_BYTES 261120U
#define CLASSIC_MCELIECE_348864_SECRET_KEY_BYTES 6492U
#define CLASSIC_MCELIECE_348864_CIPHERTEXT_BYTES 96U
#define CLASSIC_MCELIECE_348864_SHARED_SECRET_BYTES 32U

int classic_mceliece_348864_keypair(uint8_t *pk, uint8_t *sk);
int classic_mceliece_348864_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int classic_mceliece_348864_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
