CC := gcc
CFLAGS := -O2 -Wall -Wextra -std=c11
LDFLAGS :=

SERVER_LDLIBS := -lssl -lcrypto -lws2_32
RPI_LDLIBS := -loqs -lssl -lcrypto

SRC_DIR := src
BUILD_DIR := src/bin

COMMON_DIR := $(SRC_DIR)/common
ALG_DIR := $(SRC_DIR)/algorithms
AES_DIR := $(ALG_DIR)/aes256
ASCON_DIR := $(ALG_DIR)/ascon
PQC_DIR := $(ALG_DIR)/pqc
ML_KEM_DIR := $(PQC_DIR)/ml_kem
MCELIECE_DIR := $(PQC_DIR)/classic_mceliece
CLIENT_DIR := $(SRC_DIR)/client
SERVER_DIR := $(SRC_DIR)/server

INCLUDES := \
	-I$(COMMON_DIR) \
	-I$(AES_DIR) \
	-I$(ASCON_DIR) \
	-I$(ASCON_DIR)/ascon_ref \
	-I$(PQC_DIR) \
	-I$(ML_KEM_DIR) \
	-I$(MCELIECE_DIR)

SERVER_SRC := $(SERVER_DIR)/servidor.c
RPI_CLIENT_SRC := $(CLIENT_DIR)/raspberry/client_raspberry.c

AES_SRC := $(AES_DIR)/aes256.c
ASCON_SRC := $(ASCON_DIR)/ascon.c
ASCON_REF_SRC := $(ASCON_DIR)/ascon_ref/ascon_ref_clean.c
ML_KEM_SRC := $(ML_KEM_DIR)/ml_kem.c
MCELIECE_SRC := $(MCELIECE_DIR)/classic_mceliece.c

SERVER_BIN := $(BUILD_DIR)/servidor.exe
SERVER_ASCON_BIN := $(BUILD_DIR)/servidor_ascon.exe
RPI_CLIENT_BIN := $(BUILD_DIR)/client_raspberry

all: $(SERVER_BIN)

dirs:
	mkdir -p $(BUILD_DIR)

$(SERVER_BIN): $(SERVER_SRC) $(AES_SRC) $(COMMON_DIR)/protocol.h $(AES_DIR)/aes256.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SERVER_SRC) $(AES_SRC) $(LDFLAGS) $(SERVER_LDLIBS)

server_ascon: $(SERVER_ASCON_BIN)

$(SERVER_ASCON_BIN): $(SERVER_SRC) $(AES_SRC) $(ASCON_SRC) $(ASCON_REF_SRC) $(COMMON_DIR)/protocol.h $(AES_DIR)/aes256.h $(ASCON_DIR)/ascon.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -DENABLE_ASCON -o $@ $(SERVER_SRC) $(AES_SRC) $(ASCON_SRC) $(ASCON_REF_SRC) $(LDFLAGS) $(SERVER_LDLIBS)

raspberry_client: $(RPI_CLIENT_BIN)

$(RPI_CLIENT_BIN): $(RPI_CLIENT_SRC) $(AES_SRC) $(ASCON_SRC) $(ASCON_REF_SRC) $(ML_KEM_SRC) $(MCELIECE_SRC) $(COMMON_DIR)/protocol.h $(PQC_DIR)/pqc_common.h $(ML_KEM_DIR)/ml_kem.h $(MCELIECE_DIR)/classic_mceliece.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(RPI_CLIENT_SRC) $(AES_SRC) $(ASCON_SRC) $(ASCON_REF_SRC) $(ML_KEM_SRC) $(MCELIECE_SRC) $(LDFLAGS) $(RPI_LDLIBS)

clean:
	rm -f $(SERVER_BIN) $(SERVER_ASCON_BIN) $(RPI_CLIENT_BIN)

.PHONY: all dirs clean server_ascon raspberry_client
