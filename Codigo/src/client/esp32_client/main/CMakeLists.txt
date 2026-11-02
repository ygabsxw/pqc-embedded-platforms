idf_component_register(
    SRCS
        "esp32_lock_client.c"
        "esp32_ml_kem.c"
        "esp32_mceliece.c"
        "../../../algorithms/ascon/ascon_ref/ascon_ref_clean.c"
    INCLUDE_DIRS
        "."
        "../../../common"
        "../../../algorithms/ascon"
        "../../../algorithms/ascon/ascon_ref"
    REQUIRES
        esp_wifi
        esp_event
        esp_netif
        nvs_flash
        mbedtls
        esp_timer
        mlkem768
        classic_mceliece_348864
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE ENABLE_ESP32_MCELIECE)
