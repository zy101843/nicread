#pragma once
#include <stdint.h>
class simple_encrypt
{
public:
    enum
    {
        SBOX_SIZE = 256
    };

public:
    simple_encrypt(uint8_t *key, int key_length);
    void encrypt_decrypt(uint8_t *input, int length, uint8_t *output, uint16_t id);
    void decrypt_decrypt(uint8_t *input, int length, uint8_t *output);

private:
    uint8_t S[256];
    uint8_t m_init_s[256];
};