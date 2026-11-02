#ifndef IOT_PROTOCOL_H
#define IOT_PROTOCOL_H

#include <stdint.h>

#define IOT_PROTOCOL_MAGIC "IOT1"
#define IOT_PROTOCOL_VERSION 1
#define IOT_PROTOCOL_HEADER_SIZE 20

#define IOT_ML_KEM_768_PUBLIC_KEY_BYTES 1184U
#define IOT_ML_KEM_768_CIPHERTEXT_BYTES 1088U
#define IOT_CLASSIC_MCELIECE_348864_PUBLIC_KEY_BYTES 261120U
#define IOT_CLASSIC_MCELIECE_348864_CIPHERTEXT_BYTES 96U

typedef enum
{
    IOT_ALG_AES256_GCM = 1,
    IOT_ALG_ASCON_128A = 2,
    IOT_ALG_ML_KEM = 3,
    IOT_ALG_CLASSIC_MCELIECE = 4
} IotAlgorithm;

typedef enum
{
    IOT_DEVICE_UNKNOWN = 0,
    IOT_DEVICE_ESP32_LOCK = 1,
    IOT_DEVICE_RPI_CAMERA = 2,
    IOT_DEVICE_QEMU_CAMERA = 3
} IotDeviceType;

typedef enum
{
    IOT_PAYLOAD_UNKNOWN = 0,
    IOT_PAYLOAD_TELEMETRY = 1,
    IOT_PAYLOAD_COMMAND = 2,
    IOT_PAYLOAD_FRAME_CHUNK = 3,
    IOT_PAYLOAD_PQC_HANDSHAKE = 4
} IotPayloadType;

typedef struct
{
    uint8_t version;
    uint8_t algorithm;
    uint8_t device_type;
    uint8_t payload_type;
    uint32_t sequence;
    uint32_t plaintext_len;
    uint32_t ciphertext_len;
} IotHeaderFields;

#endif
