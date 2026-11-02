#include "aes256.h"
#include "ascon.h"
#include "classic_mceliece.h"
#include "ml_kem.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 9000
#define DEFAULT_PAYLOAD_SIZE 64U
#define DEFAULT_REPEAT 30U

static uint32_t sequence_number = 1;

typedef struct
{
    long vmrss_kb;
    long vmhwm_kb;
    long vmpeak_kb;
} MemorySnapshot;

static double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;
}

static void read_memory_snapshot(MemorySnapshot *snapshot)
{
    FILE *fp = NULL;
    char line[256];

    if (!snapshot)
    {
        return;
    }

    snapshot->vmrss_kb = -1;
    snapshot->vmhwm_kb = -1;
    snapshot->vmpeak_kb = -1;

    fp = fopen("/proc/self/status", "r");
    if (!fp)
    {
        return;
    }

    while (fgets(line, sizeof(line), fp))
    {
        long value = -1;

        if (sscanf(line, "VmRSS: %ld kB", &value) == 1)
        {
            snapshot->vmrss_kb = value;
        }
        else if (sscanf(line, "VmHWM: %ld kB", &value) == 1)
        {
            snapshot->vmhwm_kb = value;
        }
        else if (sscanf(line, "VmPeak: %ld kB", &value) == 1)
        {
            snapshot->vmpeak_kb = value;
        }
    }

    fclose(fp);
}

static double throughput_bps(size_t bytes, double latency_us)
{
    if (latency_us <= 0.0)
    {
        return 0.0;
    }

    return (double)bytes / (latency_us / 1000000.0);
}

static long overhead_bytes(size_t wire_len, size_t plaintext_len)
{
    return (long)wire_len - (long)plaintext_len;
}

static double overhead_percent(size_t wire_len, size_t plaintext_len)
{
    if (plaintext_len == 0)
    {
        return 0.0;
    }

    return ((double)wire_len - (double)plaintext_len) * 100.0 / (double)plaintext_len;
}

static void write_be32(uint8_t *buf, uint32_t value)
{
    buf[0] = (uint8_t)((value >> 24) & 0xFF);
    buf[1] = (uint8_t)((value >> 16) & 0xFF);
    buf[2] = (uint8_t)((value >> 8) & 0xFF);
    buf[3] = (uint8_t)(value & 0xFF);
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
    size_t i = 0;

    if (!hex || strlen(hex) != out_len * 2)
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

static int connect_tcp(const char *host, uint16_t port)
{
    struct sockaddr_in addr;
    int sock = -1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("[rpi] socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
    {
        fprintf(stderr, "[rpi] host must be an IPv4 address: %s\n", host);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("[rpi] connect");
        close(sock);
        return -1;
    }

    return sock;
}

static int send_all(int sock, const uint8_t *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len)
    {
        ssize_t rc = send(sock, buf + sent, len - sent, 0);
        if (rc <= 0)
        {
            return -1;
        }
        sent += (size_t)rc;
    }

    return 0;
}

static int recv_ack(int sock)
{
    char buf[64];
    ssize_t rc = recv(sock, buf, sizeof(buf) - 1U, 0);
    if (rc <= 0)
    {
        return -1;
    }

    buf[rc] = '\0';
    return 0;
}

static size_t build_payload(uint8_t *buf, size_t target_size, uint32_t seq)
{
    int n = snprintf((char *)buf,
                     target_size + 1U,
                     "{\"device\":\"rpi-camera\",\"seq\":%u,\"event\":\"frame-chunk\"}",
                     seq);
    size_t used = 0;

    if (n < 0)
    {
        return 0;
    }

    used = (size_t)n;
    if (used > target_size)
    {
        return used;
    }

    while (used < target_size)
    {
        buf[used++] = (uint8_t)('A' + (used % 26U));
    }

    return used;
}

static int send_protocol_packet(int sock,
                                uint8_t algorithm,
                                uint8_t payload_type,
                                const uint8_t *wire_payload,
                                size_t wire_payload_len,
                                size_t plaintext_len,
                                double *latency_e2e_us)
{
    uint8_t header[IOT_PROTOCOL_HEADER_SIZE];
    double t0 = now_us();

    memcpy(header, IOT_PROTOCOL_MAGIC, 4);
    header[4] = IOT_PROTOCOL_VERSION;
    header[5] = algorithm;
    header[6] = IOT_DEVICE_RPI_CAMERA;
    header[7] = payload_type;
    write_be32(header + 8, sequence_number);
    write_be32(header + 12, (uint32_t)plaintext_len);
    write_be32(header + 16, (uint32_t)wire_payload_len);

    if (send_all(sock, header, sizeof(header)) != 0 ||
        send_all(sock, wire_payload, wire_payload_len) != 0 ||
        recv_ack(sock) != 0)
    {
        return -1;
    }

    if (latency_e2e_us)
    {
        *latency_e2e_us = now_us() - t0;
    }

    return 0;
}

static int run_aead_round(const char *host,
                          uint16_t port,
                          const char *alg,
                          const char *hex_key,
                          size_t payload_size)
{
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    size_t plaintext_len = 0;
    size_t ciphertext_len = 0;
    double t0 = 0.0;
    double t1 = 0.0;
    double latency_e2e_us = 0.0;
    double latency_start_us = 0.0;
    MemorySnapshot mem_before;
    MemorySnapshot mem_after;
    int sock = -1;
    int result = -1;

    plaintext = (uint8_t *)malloc(payload_size + 256U);
    if (!plaintext)
    {
        return -1;
    }

    plaintext_len = build_payload(plaintext, payload_size, sequence_number);
    read_memory_snapshot(&mem_before);

    if (strcmp(alg, "aes") == 0)
    {
        AES256Context ctx;

        memset(&ctx, 0, sizeof(ctx));
        if (hex_to_bytes(hex_key, ctx.key, AES256_KEY_SIZE) != 0)
        {
            fprintf(stderr, "[rpi] AES key must have 64 hex chars\n");
            goto cleanup;
        }

        ctx.initialized = 1;
        ciphertext = (uint8_t *)malloc(plaintext_len + AES256_OVERHEAD_BYTES);
        if (!ciphertext)
        {
            goto cleanup;
        }

        t0 = now_us();
        result = aes256_encrypt(&ctx, plaintext, plaintext_len, ciphertext, &ciphertext_len);
        t1 = now_us();
        aes256_context_free(&ctx);

        if (result != 0)
        {
            goto cleanup;
        }

        latency_start_us = now_us();
        sock = connect_tcp(host, port);
        if (sock < 0)
        {
            goto cleanup;
        }

        result = send_protocol_packet(sock,
                                      IOT_ALG_AES256_GCM,
                                      IOT_PAYLOAD_FRAME_CHUNK,
                                      ciphertext,
                                      ciphertext_len,
                                      plaintext_len,
                                      &latency_e2e_us);
        latency_e2e_us = now_us() - latency_start_us;
        read_memory_snapshot(&mem_after);

        printf("alg=aes seq=%u pt=%zu ct=%zu encrypt_us=%.2f\n",
               sequence_number,
               plaintext_len,
               ciphertext_len,
               t1 - t0);
        printf("metric device=rpi-camera alg=aes256-gcm seq=%u payload=frame-chunk pt=%zu ct=%zu pk=0 wire=%zu encrypt_us=%.2f keypair_us=0.00 encaps_us=0.00 decaps_us=0.00 total_kem_us=0.00 latency_e2e_us=%.2f overhead_bytes=%ld overhead_percent=%.2f throughput_Bps=%.2f memory_before_kb=%ld memory_after_kb=%ld memory_peak_kb=%ld valid_secret=0 ack_ok=%d size_ok=1\n",
               sequence_number,
               plaintext_len,
               ciphertext_len,
               ciphertext_len,
               t1 - t0,
               latency_e2e_us,
               overhead_bytes(ciphertext_len, plaintext_len),
               overhead_percent(ciphertext_len, plaintext_len),
               throughput_bps(ciphertext_len, latency_e2e_us),
               mem_before.vmrss_kb,
               mem_after.vmrss_kb,
               mem_after.vmhwm_kb,
               result == 0 ? 1 : 0);
    }
    else if (strcmp(alg, "ascon") == 0)
    {
        AsconContext ctx;
        char ascon_hex_key[ASCON_KEY_SIZE * 2U + 1U];

        memset(&ctx, 0, sizeof(ctx));

        if (!hex_key || strlen(hex_key) < ASCON_KEY_SIZE * 2U)
        {
            fprintf(stderr, "[rpi] Ascon key needs at least 32 hex chars\n");
            goto cleanup;
        }

        memcpy(ascon_hex_key, hex_key, ASCON_KEY_SIZE * 2U);
        ascon_hex_key[ASCON_KEY_SIZE * 2U] = '\0';

        if (hex_to_bytes(ascon_hex_key, ctx.key, ASCON_KEY_SIZE) != 0)
        {
            fprintf(stderr, "[rpi] Ascon key must have 32 hex chars\n");
            goto cleanup;
        }

        ctx.initialized = 1;
        ciphertext = (uint8_t *)malloc(plaintext_len + ASCON_OVERHEAD_BYTES);
        if (!ciphertext)
        {
            goto cleanup;
        }

        t0 = now_us();
        result = ascon_encrypt(&ctx, plaintext, plaintext_len, ciphertext, &ciphertext_len);
        t1 = now_us();
        ascon_context_free(&ctx);

        if (result != 0)
        {
            goto cleanup;
        }

        latency_start_us = now_us();
        sock = connect_tcp(host, port);
        if (sock < 0)
        {
            goto cleanup;
        }

        result = send_protocol_packet(sock,
                                      IOT_ALG_ASCON_128A,
                                      IOT_PAYLOAD_FRAME_CHUNK,
                                      ciphertext,
                                      ciphertext_len,
                                      plaintext_len,
                                      &latency_e2e_us);
        latency_e2e_us = now_us() - latency_start_us;
        read_memory_snapshot(&mem_after);

        printf("alg=ascon seq=%u pt=%zu ct=%zu encrypt_us=%.2f\n",
               sequence_number,
               plaintext_len,
               ciphertext_len,
               t1 - t0);
        printf("metric device=rpi-camera alg=ascon-128a seq=%u payload=frame-chunk pt=%zu ct=%zu pk=0 wire=%zu encrypt_us=%.2f keypair_us=0.00 encaps_us=0.00 decaps_us=0.00 total_kem_us=0.00 latency_e2e_us=%.2f overhead_bytes=%ld overhead_percent=%.2f throughput_Bps=%.2f memory_before_kb=%ld memory_after_kb=%ld memory_peak_kb=%ld valid_secret=0 ack_ok=%d size_ok=1\n",
               sequence_number,
               plaintext_len,
               ciphertext_len,
               ciphertext_len,
               t1 - t0,
               latency_e2e_us,
               overhead_bytes(ciphertext_len, plaintext_len),
               overhead_percent(ciphertext_len, plaintext_len),
               throughput_bps(ciphertext_len, latency_e2e_us),
               mem_before.vmrss_kb,
               mem_after.vmrss_kb,
               mem_after.vmhwm_kb,
               result == 0 ? 1 : 0);
    }

cleanup:
    if (sock >= 0)
    {
        close(sock);
    }

    free(ciphertext);
    free(plaintext);
    return result;
}

static int kem_result_is_valid(const PQCKEMResult *result)
{
    if (!result ||
        !result->shared_secret_enc ||
        !result->shared_secret_dec ||
        result->shared_secret_len == 0)
    {
        return 0;
    }

    return memcmp(result->shared_secret_enc,
                  result->shared_secret_dec,
                  result->shared_secret_len) == 0;
}

static uint32_t shared_secret_fingerprint(const PQCKEMResult *result)
{
    uint32_t hash = 2166136261U;
    size_t i = 0;

    if (!result || !result->shared_secret_enc)
    {
        return 0;
    }

    for (i = 0; i < result->shared_secret_len; ++i)
    {
        hash ^= result->shared_secret_enc[i];
        hash *= 16777619U;
    }

    return hash;
}

static int send_kem_artifacts(const char *host,
                              uint16_t port,
                              uint8_t wire_algorithm,
                              const PQCKEMResult *kem_result,
                              double *latency_e2e_us)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int sock = -1;
    int result = -1;
    double latency_start_us = 0.0;

    wire_len = kem_result->public_key_len + kem_result->ciphertext_len;
    wire = (uint8_t *)malloc(wire_len);
    if (!wire)
    {
        return -1;
    }

    memcpy(wire, kem_result->public_key, kem_result->public_key_len);
    memcpy(wire + kem_result->public_key_len,
           kem_result->ciphertext,
           kem_result->ciphertext_len);

    latency_start_us = now_us();
    sock = connect_tcp(host, port);
    if (sock < 0)
    {
        goto cleanup;
    }

    result = send_protocol_packet(sock,
                                  wire_algorithm,
                                  IOT_PAYLOAD_PQC_HANDSHAKE,
                                  wire,
                                  wire_len,
                                  0U,
                                  latency_e2e_us);
    if (latency_e2e_us)
    {
        *latency_e2e_us = now_us() - latency_start_us;
    }

cleanup:
    if (sock >= 0)
    {
        close(sock);
    }
    free(wire);
    return result;
}

static int run_ml_kem_round(const char *host, uint16_t port)
{
    PQCKEMResult kem_result;
    double latency_e2e_us = 0.0;
    MemorySnapshot mem_before;
    MemorySnapshot mem_after;
    int result = -1;

    memset(&kem_result, 0, sizeof(kem_result));
    read_memory_snapshot(&mem_before);

    if (ml_kem_run(&kem_result) != 0)
    {
        return -1;
    }

    if (!kem_result_is_valid(&kem_result))
    {
        fprintf(stderr, "[rpi] ML-KEM shared secret validation failed\n");
        goto cleanup;
    }

    result = send_kem_artifacts(host, port, IOT_ALG_ML_KEM, &kem_result, &latency_e2e_us);
    read_memory_snapshot(&mem_after);

    printf("alg=ml-kem seq=%u pk=%zu ct=%zu wire=%zu ss=%zu valid=yes ss_fp=%08x total_kem_us=%.2f\n",
           sequence_number,
           kem_result.public_key_len,
           kem_result.ciphertext_len,
           kem_result.public_key_len + kem_result.ciphertext_len,
           kem_result.shared_secret_len,
           shared_secret_fingerprint(&kem_result),
           kem_result.total_us);
    printf("metric device=rpi-camera alg=ml-kem seq=%u payload=pqc-handshake pt=0 ct=%zu pk=%zu wire=%zu encrypt_us=0.00 keypair_us=%.2f encaps_us=%.2f decaps_us=%.2f total_kem_us=%.2f latency_e2e_us=%.2f overhead_bytes=%ld overhead_percent=0.00 throughput_Bps=%.2f memory_before_kb=%ld memory_after_kb=%ld memory_peak_kb=%ld valid_secret=1 ack_ok=%d size_ok=1\n",
           sequence_number,
           kem_result.ciphertext_len,
           kem_result.public_key_len,
           kem_result.public_key_len + kem_result.ciphertext_len,
           kem_result.keypair_us,
           kem_result.encaps_us,
           kem_result.decaps_us,
           kem_result.total_us,
           latency_e2e_us,
           overhead_bytes(kem_result.public_key_len + kem_result.ciphertext_len, 0U),
           throughput_bps(kem_result.public_key_len + kem_result.ciphertext_len, latency_e2e_us),
           mem_before.vmrss_kb,
           mem_after.vmrss_kb,
           mem_after.vmhwm_kb,
           result == 0 ? 1 : 0);

cleanup:
    ml_kem_result_free(&kem_result);
    return result;
}

static int run_classic_mceliece_round(const char *host, uint16_t port)
{
    PQCKEMResult kem_result;
    double latency_e2e_us = 0.0;
    MemorySnapshot mem_before;
    MemorySnapshot mem_after;
    int result = -1;

    memset(&kem_result, 0, sizeof(kem_result));
    read_memory_snapshot(&mem_before);

    if (classic_mceliece_run(&kem_result) != 0)
    {
        return -1;
    }

    if (!kem_result_is_valid(&kem_result))
    {
        fprintf(stderr, "[rpi] Classic McEliece shared secret validation failed\n");
        goto cleanup;
    }

    result = send_kem_artifacts(host, port, IOT_ALG_CLASSIC_MCELIECE, &kem_result, &latency_e2e_us);
    read_memory_snapshot(&mem_after);

    printf("alg=classic-mceliece seq=%u pk=%zu ct=%zu wire=%zu ss=%zu valid=yes ss_fp=%08x total_kem_us=%.2f\n",
           sequence_number,
           kem_result.public_key_len,
           kem_result.ciphertext_len,
           kem_result.public_key_len + kem_result.ciphertext_len,
           kem_result.shared_secret_len,
           shared_secret_fingerprint(&kem_result),
           kem_result.total_us);
    printf("metric device=rpi-camera alg=classic-mceliece seq=%u payload=pqc-handshake pt=0 ct=%zu pk=%zu wire=%zu encrypt_us=0.00 keypair_us=%.2f encaps_us=%.2f decaps_us=%.2f total_kem_us=%.2f latency_e2e_us=%.2f overhead_bytes=%ld overhead_percent=0.00 throughput_Bps=%.2f memory_before_kb=%ld memory_after_kb=%ld memory_peak_kb=%ld valid_secret=1 ack_ok=%d size_ok=1\n",
           sequence_number,
           kem_result.ciphertext_len,
           kem_result.public_key_len,
           kem_result.public_key_len + kem_result.ciphertext_len,
           kem_result.keypair_us,
           kem_result.encaps_us,
           kem_result.decaps_us,
           kem_result.total_us,
           latency_e2e_us,
           overhead_bytes(kem_result.public_key_len + kem_result.ciphertext_len, 0U),
           throughput_bps(kem_result.public_key_len + kem_result.ciphertext_len, latency_e2e_us),
           mem_before.vmrss_kb,
           mem_after.vmrss_kb,
           mem_after.vmhwm_kb,
           result == 0 ? 1 : 0);

cleanup:
    classic_mceliece_result_free(&kem_result);
    return result;
}

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s --host <ip> --port 9000 --alg aes|ascon|ml-kem|mceliece|all --key <hex> --payload-size <bytes> --repeat 30\n",
            program);
}

int main(int argc, char **argv)
{
    const char *host = DEFAULT_HOST;
    const char *alg = "all";
    const char *key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    uint16_t port = DEFAULT_PORT;
    size_t payload_size = DEFAULT_PAYLOAD_SIZE;
    unsigned repeat = DEFAULT_REPEAT;
    unsigned i = 0;
    int argi = 0;

    for (argi = 1; argi < argc; ++argi)
    {
        if (strcmp(argv[argi], "--host") == 0 && argi + 1 < argc)
        {
            host = argv[++argi];
        }
        else if (strcmp(argv[argi], "--port") == 0 && argi + 1 < argc)
        {
            port = (uint16_t)strtoul(argv[++argi], NULL, 10);
        }
        else if (strcmp(argv[argi], "--alg") == 0 && argi + 1 < argc)
        {
            alg = argv[++argi];
        }
        else if (strcmp(argv[argi], "--key") == 0 && argi + 1 < argc)
        {
            key = argv[++argi];
        }
        else if (strcmp(argv[argi], "--payload-size") == 0 && argi + 1 < argc)
        {
            payload_size = (size_t)strtoul(argv[++argi], NULL, 10);
        }
        else if (strcmp(argv[argi], "--repeat") == 0 && argi + 1 < argc)
        {
            repeat = (unsigned)strtoul(argv[++argi], NULL, 10);
        }
        else
        {
            print_usage(argv[0]);
            return 1;
        }
    }

    for (i = 0; i < repeat; ++i)
    {
        int rc = 0;

        if (strcmp(alg, "aes") == 0)
        {
            rc = run_aead_round(host, port, "aes", key, payload_size);
        }
        else if (strcmp(alg, "ascon") == 0)
        {
            rc = run_aead_round(host, port, "ascon", key, payload_size);
        }
        else if (strcmp(alg, "ml-kem") == 0)
        {
            rc = run_ml_kem_round(host, port);
        }
        else if (strcmp(alg, "mceliece") == 0)
        {
            rc = run_classic_mceliece_round(host, port);
        }
        else if (strcmp(alg, "all") == 0)
        {
            rc = run_aead_round(host, port, "aes", key, payload_size);
            sequence_number++;

            rc |= run_aead_round(host, port, "ascon", key, payload_size);
            sequence_number++;

            rc |= run_ml_kem_round(host, port);
            sequence_number++;

            rc |= run_classic_mceliece_round(host, port);
        }
        else
        {
            print_usage(argv[0]);
            return 1;
        }

        if (rc != 0)
        {
            fprintf(stderr, "[rpi] round failed at seq=%u\n", sequence_number);
            return 1;
        }

        sequence_number++;
    }

    return 0;
}
