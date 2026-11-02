# ML-KEM-768 component

ESP-IDF component copied from:

https://github.com/aethyrai/esp32-awp-edge/tree/main/components/mlkem768

The component packages the portable C implementation from `mlkem-native`
v1.0.0 and provides an ESP32 hardware RNG adapter through
`esp_fill_random()`.

The compatibility header `api.h` maps the implementation symbols to the API
used by this project:

```c
pqcrystals_kyber768_ref_keypair()
pqcrystals_kyber768_ref_enc()
pqcrystals_kyber768_ref_dec()
```

Parameters:

```text
public key:    1184 bytes
secret key:    2400 bytes
ciphertext:    1088 bytes
shared secret:   32 bytes
```

The upstream project was tested on ESP32-S3 with PSRAM. This project also
builds the portable implementation for the classic ESP32, where execution
time and available heap must be measured independently.

See `LICENSE` for the Apache-2.0 license and the source files for the
underlying `mlkem-native` license notices.
