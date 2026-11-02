#include "protocol.h"
#include "aes256.h"

#ifdef ENABLE_ASCON
#include "ascon.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
typedef SOCKET socket_t;
typedef int socklen_t;
#define CLOSE_SOCKET closesocket
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
typedef int socket_t;
#define CLOSE_SOCKET close
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#endif

typedef struct
{
    uint8_t algorithm;
    AES256Context aes_ctx;
#ifdef ENABLE_ASCON
    AsconContext ascon_ctx;
#endif
} ServerConfig;

#define MAX_PLAINTEXT_BYTES (1024U * 1024U)
#define MAX_CIPHERTEXT_BYTES (2U * 1024U * 1024U)

static uint32_t read_be32(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           ((uint32_t)buf[3]);
}

static int write_all(socket_t sock, const uint8_t *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len)
    {
        int rc = send(sock, (const char *)(buf + sent), (int)(len - sent), 0);
        if (rc <= 0)
        {
            return -1;
        }
        sent += (size_t)rc;
    }

    return 0;
}

static int recv_all(socket_t sock, uint8_t *buf, size_t len)
{
    size_t total = 0;

    while (total < len)
    {
        int rc = recv(sock, (char *)(buf + total), (int)(len - total), 0);
        if (rc == 0)
        {
            return 1;
        }
        if (rc < 0)
        {
            return -1;
        }
        total += (size_t)rc;
    }

    return 0;
}

static double now_microseconds(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq;
    LARGE_INTEGER counter;

    if (freq.QuadPart == 0)
    {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000000.0 / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;
#endif
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    size_t i = 0;

    if (hex_len != out_len * 2)
    {
        return -1;
    }

    for (i = 0; i < out_len; ++i)
    {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static const char *algorithm_name(uint8_t algorithm)
{
    switch (algorithm)
    {
    case 0:
        return "any";
    case IOT_ALG_AES256_GCM:
        return "aes256-gcm";
    case IOT_ALG_ASCON_128A:
        return "ascon-128a";
    case IOT_ALG_ML_KEM:
        return "ml-kem";
    case IOT_ALG_CLASSIC_MCELIECE:
        return "classic-mceliece";
    default:
        return "unknown";
    }
}

static const char *device_name(uint8_t device_type)
{
    switch (device_type)
    {
    case IOT_DEVICE_ESP32_LOCK:
        return "esp32-lock";
    case IOT_DEVICE_RPI_CAMERA:
        return "rpi-camera";
    case IOT_DEVICE_QEMU_CAMERA:
        return "qemu-camera";
    default:
        return "unknown";
    }
}

static const char *payload_name(uint8_t payload_type)
{
    switch (payload_type)
    {
    case IOT_PAYLOAD_TELEMETRY:
        return "telemetry";
    case IOT_PAYLOAD_COMMAND:
        return "command";
    case IOT_PAYLOAD_FRAME_CHUNK:
        return "frame-chunk";
    case IOT_PAYLOAD_PQC_HANDSHAKE:
        return "pqc-handshake";
    default:
        return "unknown";
    }
}

static int is_pqc_algorithm(uint8_t algorithm)
{
    return algorithm == IOT_ALG_ML_KEM || algorithm == IOT_ALG_CLASSIC_MCELIECE;
}

static int pqc_expected_sizes(uint8_t algorithm, size_t *public_key_len, size_t *ciphertext_len)
{
    if (!public_key_len || !ciphertext_len)
    {
        return -1;
    }

    if (algorithm == IOT_ALG_ML_KEM)
    {
        *public_key_len = IOT_ML_KEM_768_PUBLIC_KEY_BYTES;
        *ciphertext_len = IOT_ML_KEM_768_CIPHERTEXT_BYTES;
        return 0;
    }

    if (algorithm == IOT_ALG_CLASSIC_MCELIECE)
    {
        *public_key_len = IOT_CLASSIC_MCELIECE_348864_PUBLIC_KEY_BYTES;
        *ciphertext_len = IOT_CLASSIC_MCELIECE_348864_CIPHERTEXT_BYTES;
        return 0;
    }

    return -1;
}

static uint32_t fnv1a32(const uint8_t *data, size_t len)
{
    uint32_t hash = 2166136261U;
    size_t i = 0;

    if (!data)
    {
        return 0;
    }

    for (i = 0; i < len; ++i)
    {
        hash ^= data[i];
        hash *= 16777619U;
    }

    return hash;
}

static int parse_header(const uint8_t *raw, IotHeaderFields *header)
{
    if (memcmp(raw, IOT_PROTOCOL_MAGIC, 4) != 0)
    {
        return -1;
    }

    header->version = raw[4];
    header->algorithm = raw[5];
    header->device_type = raw[6];
    header->payload_type = raw[7];
    header->sequence = read_be32(raw + 8);
    header->plaintext_len = read_be32(raw + 12);
    header->ciphertext_len = read_be32(raw + 16);
    return 0;
}

static int decrypt_payload(const ServerConfig *config,
                           const IotHeaderFields *header,
                           const uint8_t *ciphertext,
                           uint8_t *plaintext,
                           size_t *plaintext_len)
{
    if (header->algorithm == IOT_ALG_AES256_GCM)
    {
        return aes256_decrypt(&config->aes_ctx,
                              ciphertext,
                              header->ciphertext_len,
                              plaintext,
                              plaintext_len);
    }

#ifdef ENABLE_ASCON
    if (header->algorithm == IOT_ALG_ASCON_128A)
    {
        return ascon_decrypt(&config->ascon_ctx,
                             ciphertext,
                             header->ciphertext_len,
                             plaintext,
                             plaintext_len);
    }
#endif

    fprintf(stderr, "[server] unsupported algorithm id: %u\n", header->algorithm);
    return -1;
}

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s --alg aes --key <hex> [--port 9000] [--host 0.0.0.0]\n"
            "       %s --alg ascon --key <hex> [--port 9000] [--host 0.0.0.0]\n"
            "       %s --alg ml-kem [--port 9000] [--host 0.0.0.0]\n"
            "       %s --alg mceliece [--port 9000] [--host 0.0.0.0]\n"
            "       %s --alg any --key <aes-hex> [--port 9000] [--host 0.0.0.0]\n",
            program, program, program, program, program);
}

static int init_config(ServerConfig *config,
                       const char *alg_name,
                       const char *hex_key)
{
    memset(config, 0, sizeof(*config));

    if (strcmp(alg_name, "aes") == 0)
    {
        if (!hex_key)
        {
            fprintf(stderr, "[server] AES requires --key\n");
            return -1;
        }
        config->algorithm = IOT_ALG_AES256_GCM;
        if (hex_to_bytes(hex_key, config->aes_ctx.key, AES256_KEY_SIZE) != 0)
        {
            fprintf(stderr, "[server] AES key must be %d hex chars\n", AES256_KEY_SIZE * 2);
            return -1;
        }
        config->aes_ctx.initialized = 1;
        return 0;
    }

    if (strcmp(alg_name, "any") == 0)
    {
        if (!hex_key)
        {
            fprintf(stderr, "[server] any mode requires --key with 64 AES hex chars\n");
            return -1;
        }

        config->algorithm = 0;
        if (hex_to_bytes(hex_key, config->aes_ctx.key, AES256_KEY_SIZE) != 0)
        {
            fprintf(stderr, "[server] AES key must be %d hex chars\n", AES256_KEY_SIZE * 2);
            return -1;
        }
        config->aes_ctx.initialized = 1;

#ifdef ENABLE_ASCON
        memcpy(config->ascon_ctx.key, config->aes_ctx.key, ASCON_KEY_SIZE);
        config->ascon_ctx.initialized = 1;
#endif

        return 0;
    }

    if (strcmp(alg_name, "ascon") == 0)
    {
#ifdef ENABLE_ASCON
        if (!hex_key)
        {
            fprintf(stderr, "[server] Ascon requires --key\n");
            return -1;
        }
        config->algorithm = IOT_ALG_ASCON_128A;
        if (hex_to_bytes(hex_key, config->ascon_ctx.key, ASCON_KEY_SIZE) != 0)
        {
            fprintf(stderr, "[server] Ascon key must be %d hex chars\n", ASCON_KEY_SIZE * 2);
            return -1;
        }
        config->ascon_ctx.initialized = 1;
        return 0;
#else
        fprintf(stderr, "[server] rebuild with -DENABLE_ASCON to use Ascon\n");
        return -1;
#endif
    }

    if (strcmp(alg_name, "ml-kem") == 0)
    {
        config->algorithm = IOT_ALG_ML_KEM;
        return 0;
    }

    if (strcmp(alg_name, "mceliece") == 0)
    {
        config->algorithm = IOT_ALG_CLASSIC_MCELIECE;
        return 0;
    }

    fprintf(stderr, "[server] unknown algorithm: %s\n", alg_name);
    return -1;
}

static int network_init(void)
{
#ifdef _WIN32
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data);
#else
    return 0;
#endif
}

static void network_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

static socket_t create_listen_socket(const char *host, uint16_t port)
{
    struct sockaddr_in addr;
    socket_t listen_sock = INVALID_SOCKET;
    int opt = 1;

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET)
    {
        perror("[server] socket");
        return INVALID_SOCKET;
    }

    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, (int)sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (!host || strcmp(host, "0.0.0.0") == 0)
    {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
    {
        fprintf(stderr, "[server] invalid host: %s\n", host);
        CLOSE_SOCKET(listen_sock);
        return INVALID_SOCKET;
    }

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        perror("[server] bind");
        CLOSE_SOCKET(listen_sock);
        return INVALID_SOCKET;
    }

    if (listen(listen_sock, 4) == SOCKET_ERROR)
    {
        perror("[server] listen");
        CLOSE_SOCKET(listen_sock);
        return INVALID_SOCKET;
    }

    return listen_sock;
}

static int handle_client(socket_t client_sock, const ServerConfig *config)
{
    uint8_t raw_header[IOT_PROTOCOL_HEADER_SIZE];
    int rc = 0;

    for (;;)
    {
        IotHeaderFields header;
        uint8_t *ciphertext = NULL;
        uint8_t *plaintext = NULL;
        size_t plaintext_len = 0;
        double t0 = 0.0;
        double t1 = 0.0;
        char ack[64];
        int ack_len = 0;

        rc = recv_all(client_sock, raw_header, sizeof(raw_header));
        if (rc == 1)
        {
            return 0;
        }
        if (rc != 0)
        {
            perror("[server] recv header");
            return -1;
        }

        if (parse_header(raw_header, &header) != 0)
        {
            fprintf(stderr, "[server] invalid header magic\n");
            return -1;
        }

        if (header.version != IOT_PROTOCOL_VERSION)
        {
            fprintf(stderr, "[server] unsupported protocol version: %u\n", header.version);
            return -1;
        }

        if (config->algorithm != 0 && header.algorithm != config->algorithm)
        {
            fprintf(stderr,
                    "[server] received %s but server is configured for %s\n",
                    algorithm_name(header.algorithm),
                    algorithm_name(config->algorithm));
            return -1;
        }

        if ((!is_pqc_algorithm(header.algorithm) && header.plaintext_len == 0) ||
            (is_pqc_algorithm(header.algorithm) &&
            header.plaintext_len != 0) ||
            header.plaintext_len > MAX_PLAINTEXT_BYTES ||
            header.ciphertext_len == 0 ||
            header.ciphertext_len > MAX_CIPHERTEXT_BYTES)
        {
            fprintf(stderr,
                    "[server] invalid message sizes: pt=%u ct=%u\n",
                    header.plaintext_len,
                    header.ciphertext_len);
            return -1;
        }

        ciphertext = (uint8_t *)malloc(header.ciphertext_len);
        plaintext = (uint8_t *)malloc((size_t)header.plaintext_len + 1U);
        if (!ciphertext || !plaintext)
        {
            fprintf(stderr, "[server] memory allocation failed\n");
            free(ciphertext);
            free(plaintext);
            return -1;
        }

        rc = recv_all(client_sock, ciphertext, header.ciphertext_len);
        if (rc != 0)
        {
            perror("[server] recv ciphertext");
            free(ciphertext);
            free(plaintext);
            return -1;
        }

        if (is_pqc_algorithm(header.algorithm))
        {
            size_t expected_pk_len = 0;
            size_t expected_ct_len = 0;
            size_t expected_wire_len = 0;
            const char *size_status = "unexpected-size";

            if (header.payload_type != IOT_PAYLOAD_PQC_HANDSHAKE)
            {
                fprintf(stderr,
                        "[server] PQC packet must use payload=pqc-handshake, got %s\n",
                        payload_name(header.payload_type));
                free(ciphertext);
                free(plaintext);
                return -1;
            }

            if (pqc_expected_sizes(header.algorithm, &expected_pk_len, &expected_ct_len) != 0)
            {
                fprintf(stderr, "[server] unsupported PQC algorithm id: %u\n", header.algorithm);
                free(ciphertext);
                free(plaintext);
                return -1;
            }

            expected_wire_len = expected_pk_len + expected_ct_len;
            if (header.ciphertext_len == expected_wire_len)
            {
                size_status = "ok";
            }

            printf("[server] seq=%u alg=%s device=%s payload=%s pk=%zuB ct=%zuB wire=%uB expected_wire=%zuB size=%s pk_fp=%08x ct_fp=%08x\n",
                   header.sequence,
                   algorithm_name(header.algorithm),
                   device_name(header.device_type),
                   payload_name(header.payload_type),
                   expected_pk_len,
                   expected_ct_len,
                   header.ciphertext_len,
                   expected_wire_len,
                   size_status,
                   fnv1a32(ciphertext, header.ciphertext_len >= expected_pk_len ? expected_pk_len : header.ciphertext_len),
                   header.ciphertext_len > expected_pk_len
                       ? fnv1a32(ciphertext + expected_pk_len, header.ciphertext_len - expected_pk_len)
                       : 0);
            fflush(stdout);
        }
        else
        {
            t0 = now_microseconds();
            if (decrypt_payload(config, &header, ciphertext, plaintext, &plaintext_len) != 0)
            {
                fprintf(stderr, "[server] decrypt failed for sequence %u\n", header.sequence);
                free(ciphertext);
                free(plaintext);
                return -1;
            }
            t1 = now_microseconds();

            printf("[server] seq=%u alg=%s device=%s payload=%s pt=%uB ct=%uB decrypt_us=%.2f\n",
                   header.sequence,
                   algorithm_name(header.algorithm),
                   device_name(header.device_type),
                   payload_name(header.payload_type),
                   header.plaintext_len,
                   header.ciphertext_len,
                   t1 - t0);
            // printf("[server] plaintext: %.*s\n", (int)plaintext_len, (char *)plaintext);
            printf("[server] plaintext_len: %d\n", (int)plaintext_len);
            fflush(stdout);
        }

        ack_len = snprintf(ack, sizeof(ack), "ACK %u\n", header.sequence);
        if (ack_len > 0)
        {
            if (write_all(client_sock, (const uint8_t *)ack, (size_t)ack_len) != 0)
            {
                free(ciphertext);
                free(plaintext);
                return -1;
            }
        }

        free(ciphertext);
        free(plaintext);
    }
}

int main(int argc, char **argv)
{
    const char *host = "0.0.0.0";
    const char *alg_name = NULL;
    const char *hex_key = NULL;
    uint16_t port = 9000;
    ServerConfig config;
    socket_t listen_sock = INVALID_SOCKET;
    int i = 0;

    for (i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
        {
            host = argv[++i];
        }
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
        {
            port = (uint16_t)strtoul(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "--alg") == 0 && i + 1 < argc)
        {
            alg_name = argv[++i];
        }
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
        {
            hex_key = argv[++i];
        }
        else
        {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!alg_name)
    {
        print_usage(argv[0]);
        return 1;
    }

    if (init_config(&config, alg_name, hex_key) != 0)
    {
        return 1;
    }

    if (network_init() != 0)
    {
        fprintf(stderr, "[server] network initialization failed\n");
        return 1;
    }

    listen_sock = create_listen_socket(host, port);
    if (listen_sock == INVALID_SOCKET)
    {
        network_cleanup();
        return 1;
    }

    printf("[server] listening on %s:%u with %s\n", host, (unsigned)port, algorithm_name(config.algorithm));
    fflush(stdout);

    for (;;)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = (socklen_t)sizeof(client_addr);
        socket_t client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);
        char client_ip[64] = {0};

        if (client_sock == INVALID_SOCKET)
        {
            perror("[server] accept");
            break;
        }

        if (!inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip)))
        {
            strncpy(client_ip, "unknown", sizeof(client_ip) - 1U);
        }

        printf("[server] client connected from %s:%u\n", client_ip, (unsigned)ntohs(client_addr.sin_port));
        fflush(stdout);

        if (handle_client(client_sock, &config) != 0)
        {
            fprintf(stderr, "[server] client session finished with error\n");
        }
        else
        {
            printf("[server] client disconnected\n");
        }
        fflush(stdout);
        CLOSE_SOCKET(client_sock);
    }

    CLOSE_SOCKET(listen_sock);
    network_cleanup();
    return 0;
}
