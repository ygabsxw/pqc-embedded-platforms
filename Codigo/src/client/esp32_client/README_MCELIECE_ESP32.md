# Classic McEliece no ESP32

Este projeto agora possui uma implementacao real de Classic McEliece-348864
para o cliente ESP32, integrada como componente ESP-IDF a partir da
implementacao `clean` do PQClean.

## Por que nao esta completa?

Classic McEliece-348864 possui:

```text
public key:     261120 bytes
secret key:       6492 bytes
ciphertext:         96 bytes
shared secret:      32 bytes
wire:           261216 bytes
```

No ESP32 classico, a chave publica sozinha pode exceder a memoria livre
disponivel quando Wi-Fi, pilhas de tasks e buffers TCP estao ativos.

A implementacao foi adaptada para mover os maiores buffers temporarios para
heap. Se o modulo tiver PSRAM e ela estiver habilitada no ESP-IDF, o codigo
tenta usar PSRAM primeiro; caso contrario, tenta a heap interna normal.

## Arquivos adicionados

```text
main/esp32_mceliece.c
main/esp32_mceliece.h
components/classic_mceliece_348864/
```

O componente novo contem:

```text
classic_mceliece_api.c/.h
pqclean_mceliece348864_clean/
pqclean_common/
```

O `main/CMakeLists.txt` ja inclui `classic_mceliece_348864` em `REQUIRES`
e define `ENABLE_ESP32_MCELIECE`, entao o wrapper deixa de retornar erro
controlado e passa a executar `keypair`, `encaps` e `decaps`.

## Como testar no client_config.h

```c
#define CLIENT_ALGORITHM CLIENT_ALG_MCELIECE
```

Ou para rodar AES, Ascon, ML-KEM e McEliece em sequencia:

```c
#define CLIENT_ALGORITHM CLIENT_ALG_ALL_WITH_PQC
```

## Comandos de build

```bat
cd C:\Users\gabri\plmg-cc-ti5-2026-1-G06-pqc-iot\Codigo\src\client\esp32_client
idf.py fullclean
idf.py set-target esp32
idf.py build
idf.py -p COM7 flash monitor
```

Use a porta correta do seu ESP32 se ela nao for `COM7`.

## Resultado esperado

Se o ESP32 nao tiver memoria suficiente, o teste deve falhar com log semelhante:

```text
falha de memoria: pk=... free_heap=...
```

Esse resultado tambem e valido para o artigo, pois demonstra a inviabilidade
pratica do Classic McEliece em um no IoT restrito.
