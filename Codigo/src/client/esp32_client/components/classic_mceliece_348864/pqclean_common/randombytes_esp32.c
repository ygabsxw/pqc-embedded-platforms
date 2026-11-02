#include "randombytes.h"

#include "esp_random.h"

int PQCLEAN_randombytes(uint8_t *output, size_t n)
{
    esp_fill_random(output, n);
    return 0;
}
