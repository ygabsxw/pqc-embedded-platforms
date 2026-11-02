# Integracao ML-KEM no ESP32

Este pacote adiciona o wrapper do ML-KEM-768 ao cliente ESP-IDF. Ele nao inclui
a implementacao completa do componente `mlkem768`, porque ela deve ser copiada
do repositorio de origem.

## 1. Copiar o componente ML-KEM

Clone o repositorio:

```bash
git clone https://github.com/aethyrai/esp32-awp-edge
```

Copie a pasta:

```text
esp32-awp-edge/components/mlkem768
```

para:

```text
Codigo/src/client/esp32_client/components/mlkem768
```

A estrutura esperada e:

```text
Codigo/src/client/esp32_client/
  CMakeLists.txt
  sdkconfig.defaults
  components/
    mlkem768/
      CMakeLists.txt
      api.h
      mlkem_native.c
      mlkem_native.h
      randombytes.c
      src/
  main/
    CMakeLists.txt
    client_config.h
    esp32_lock_client.c
    esp32_ml_kem.c
    esp32_ml_kem.h
```

## 2. Selecionar o algoritmo

No `main/client_config.h`, use:

```c
#define CLIENT_ALGORITHM CLIENT_ALG_ML_KEM
```

Ou, para rodar AES, Ascon e ML-KEM em sequencia:

```c
#define CLIENT_ALGORITHM CLIENT_ALG_ALL_WITH_ML_KEM
```

## 3. Compilar

Use o terminal do ESP-IDF:

```bash
cd Codigo/src/client/esp32_client
idf.py fullclean
idf.py set-target esp32
idf.py build
idf.py -p COM7 flash monitor
```

## 4. Servidor

No PC, rode o servidor aceitando qualquer algoritmo:

```bash
./src/bin/servidor_ascon --alg any --key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff --port 9000
```

O ML-KEM envia `[public_key | ciphertext]`, ou seja:

```text
1184 + 1088 = 2272 bytes
```

O servidor deve mostrar `alg=ml-kem`, `pk=1184`, `ct=1088` e `size=ok`.
