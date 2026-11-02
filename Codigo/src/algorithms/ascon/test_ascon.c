#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ascon.h"

int main()
{
    AsconContext ctx;
    const char *message = "Mensagem secreta para teste do Ascon-128a!";
    size_t pt_len = strlen(message);

    printf("--- Iniciando teste do Ascon-128a ---\n\n");

    printf("1. Gerando chave...\n");
    if (ascon_keygen(&ctx) != 0)
    {
        fprintf(stderr, "Falha ao gerar chave.\n");
        return 1;
    }
    printf("Chave gerada com sucesso!\n\n");

    size_t ct_max_len = pt_len + ASCON_OVERHEAD_BYTES;
    uint8_t *ciphertext = (uint8_t *)malloc(ct_max_len);
    size_t ct_len = 0;

    printf("2. Cifrando mensagem: \"%s\"\n", message);
    if (ascon_encrypt(&ctx, (const uint8_t *)message, pt_len, ciphertext, &ct_len) != 0)
    {
        fprintf(stderr, "Falha ao cifrar a mensagem.\n");
        free(ciphertext);
        return 1;
    }
    printf("Mensagem cifrada com sucesso! Tamanho do ciphertext: %zu bytes.\n\n", ct_len);

    uint8_t *decryptedtext = (uint8_t *)malloc(ct_len);
    size_t dec_len = 0;

    printf("3. Decifrando mensagem...\n");
    if (ascon_decrypt(&ctx, ciphertext, ct_len, decryptedtext, &dec_len) != 0)
    {
        fprintf(stderr, "Falha ao decifrar a mensagem (ou falha de autenticidade).\n");
        free(ciphertext);
        free(decryptedtext);
        return 1;
    }

    /* Adiciona null-terminator para poder imprimir como string C padrão */
    decryptedtext[dec_len] = '\0';

    printf("Mensagem decifrada: \"%s\"\n\n", (char *)decryptedtext);

    if (strcmp(message, (char *)decryptedtext) == 0)
    {
        printf("=> SUCESSO: O texto decifrado eh idêntico ao original!\n");
    }
    else
    {
        printf("=> ERRO: O texto decifrado não corresponde ao original!\n");
    }

    ascon_context_free(&ctx);
    free(ciphertext);
    free(decryptedtext);

    return 0;
}