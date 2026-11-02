file(GLOB MCELIECE_CLEAN_SRCS
    "pqclean_mceliece348864_clean/*.c"
)

idf_component_register(
    SRCS
        ${MCELIECE_CLEAN_SRCS}
        "pqclean_common/aes.c"
        "pqclean_common/fips202.c"
        "pqclean_common/randombytes_esp32.c"
        "classic_mceliece_api.c"
    INCLUDE_DIRS
        "."
        "pqclean_mceliece348864_clean"
        "pqclean_common"
    REQUIRES
        heap
        esp_hw_support
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-error=unused-function
    -Wno-error=unused-variable
    -Wno-error=sign-compare
    -Wno-error=maybe-uninitialized
    -Wno-error=old-style-declaration
)
