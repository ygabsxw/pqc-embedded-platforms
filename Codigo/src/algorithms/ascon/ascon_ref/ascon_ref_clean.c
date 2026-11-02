/**
 * @file ascon_ref_clean.c
 * @brief Adaptação da implementação de referência do Ascon-128a para o benchmark.
 *
 * Mudanças em relação ao original (ascon_ref.c):
 *   1. Includes corrigidos para refletir nomes dos arquivos copiados
 *   2. Chamadas de printstate/printbytes/print removidas (eram só debug, poderiam poluir os benchmarks)
 * O algoritmo em si é byte-a-byte idêntico ao original.
 */

#include "ascon_api.h"
#include "ascon_internal.h"
#include "permutations.h"
#include "word.h"

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  *clen = mlen + CRYPTO_ABYTES;

  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* --- 1. Fase de Inicialização (Initialization Phase) --- */
  ascon_state_t s;
  s.x[0] = ASCON_128A_IV;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = N0;
  s.x[4] = N1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  /* --- 2. Fase de Dados Associados (Associated Data Processing) --- */
  if (adlen) {
    while (adlen >= ASCON_128A_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, 8);
      P8(&s);
      ad += ASCON_128A_RATE;
      adlen -= ASCON_128A_RATE;
    }
    if (adlen >= 8) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, adlen - 8);
      s.x[1] ^= PAD(adlen - 8);
    } else {
      s.x[0] ^= LOADBYTES(ad, adlen);
      s.x[0] ^= PAD(adlen);
    }
    P8(&s);
  }

  /* Separação de domínio (Domain Separation) entre Dados Associados e Plaintext */
  s.x[4] ^= DSEP();

  /* --- 3. Fase de Processamento do Plaintext (Plaintext Processing) --- */
  while (mlen >= ASCON_128A_RATE) {
    s.x[0] ^= LOADBYTES(m, 8);
    s.x[1] ^= LOADBYTES(m + 8, 8);
    STOREBYTES(c, s.x[0], 8);
    STOREBYTES(c + 8, s.x[1], 8);
    P8(&s);
    m += ASCON_128A_RATE;
    c += ASCON_128A_RATE;
    mlen -= ASCON_128A_RATE;
  }
  if (mlen >= 8) {
    s.x[0] ^= LOADBYTES(m, 8);
    s.x[1] ^= LOADBYTES(m + 8, mlen - 8);
    STOREBYTES(c, s.x[0], 8);
    STOREBYTES(c + 8, s.x[1], mlen - 8);
    s.x[1] ^= PAD(mlen - 8);
  } else {
    s.x[0] ^= LOADBYTES(m, mlen);
    STOREBYTES(c, s.x[0], mlen);
    s.x[0] ^= PAD(mlen);
  }
  c += mlen;

  /* --- 4. Fase de Finalização (Finalization Phase) --- */
  s.x[2] ^= K0;
  s.x[3] ^= K1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  /* Extrai a tag de autenticação gerada e salva no ciphertext */
  STOREBYTES(c, s.x[3], 8);
  STOREBYTES(c + 8, s.x[4], 8);

  return 0;
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  if (clen < CRYPTO_ABYTES) return -1;

  *mlen = clen - CRYPTO_ABYTES;

  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* --- 1. Fase de Inicialização (Initialization Phase) --- */
  ascon_state_t s;
  s.x[0] = ASCON_128A_IV;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = N0;
  s.x[4] = N1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  /* --- 2. Fase de Dados Associados (Associated Data Processing) --- */
  if (adlen) {
    while (adlen >= ASCON_128A_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, 8);
      P8(&s);
      ad += ASCON_128A_RATE;
      adlen -= ASCON_128A_RATE;
    }
    if (adlen >= 8) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, adlen - 8);
      s.x[1] ^= PAD(adlen - 8);
    } else {
      s.x[0] ^= LOADBYTES(ad, adlen);
      s.x[0] ^= PAD(adlen);
    }
    P8(&s);
  }

  /* Separação de domínio (Domain Separation) entre Dados Associados e Ciphertext */
  s.x[4] ^= DSEP();

  clen -= CRYPTO_ABYTES;
  /* --- 3. Fase de Processamento do Ciphertext (Ciphertext Processing) --- */
  while (clen >= ASCON_128A_RATE) {
    uint64_t c0 = LOADBYTES(c, 8);
    uint64_t c1 = LOADBYTES(c + 8, 8);
    STOREBYTES(m, s.x[0] ^ c0, 8);
    STOREBYTES(m + 8, s.x[1] ^ c1, 8);
    s.x[0] = c0;
    s.x[1] = c1;
    P8(&s);
    m += ASCON_128A_RATE;
    c += ASCON_128A_RATE;
    clen -= ASCON_128A_RATE;
  }
  if (clen >= 8) {
    uint64_t c0 = LOADBYTES(c, 8);
    uint64_t c1 = LOADBYTES(c + 8, clen - 8);
    STOREBYTES(m, s.x[0] ^ c0, 8);
    STOREBYTES(m + 8, s.x[1] ^ c1, clen - 8);
    s.x[0] = c0;
    s.x[1] = CLEARBYTES(s.x[1], clen - 8);
    s.x[1] |= c1;
    s.x[1] ^= PAD(clen - 8);
  } else {
    uint64_t c0 = LOADBYTES(c, clen);
    STOREBYTES(m, s.x[0] ^ c0, clen);
    s.x[0] = CLEARBYTES(s.x[0], clen);
    s.x[0] |= c0;
    s.x[0] ^= PAD(clen);
  }
  c += clen;

  /* --- 4. Fase de Finalização (Finalization Phase) --- */
  s.x[2] ^= K0;
  s.x[3] ^= K1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  /* Extrai a tag para verificação local */
  uint8_t t[16];
  STOREBYTES(t, s.x[3], 8);
  STOREBYTES(t + 8, s.x[4], 8);

  /* --- 5. Verificação da Tag (Tag Verification) em tempo constante --- */
  int result = 0;
  for (int i = 0; i < CRYPTO_ABYTES; ++i) result |= c[i] ^ t[i];
  result = (((result - 1) >> 8) & 1) - 1;

  return result;
}
