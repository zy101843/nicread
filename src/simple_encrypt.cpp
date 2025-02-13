#include "simple_encrypt.h"
#include <cstring>
 simple_encrypt::simple_encrypt(uint8_t *key, int key_length) {
    int i = 0; 
    int j = 0;
    unsigned char temp;
    for (i = 0; i < SBOX_SIZE; i++) {
        S[i] = i;
    }
    for (i = 0; i < SBOX_SIZE; i++) {
        j = (j + S[i] + key[i % key_length]) & 0xff;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    memcpy(m_init_s, S, SBOX_SIZE);
}

void simple_encrypt::encrypt_decrypt(uint8_t *input, int length, uint8_t *output, uint16_t id)
{
    int i = 0, j = 0, t;
    unsigned char temp;
    uint8_t a = 10;
    uint8_t *inputCur  = input;
    uint8_t *inputEnd = input + length;
    uint8_t *outputCur = output;
    uint8_t *pid = (uint8_t *)&id;
    for (int i2 = 0; i2 < 2; i2++)
    {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        t = (S[i] + S[j]) & 0xff;
        *outputCur = *pid ^ S[t] ^ a;
        a = *outputCur;
        outputCur++;
        pid++;
    }

    while (inputCur < inputEnd)
    {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        t = (S[i] + S[j]) & 0xff;
        *outputCur = *inputCur ^ S[t] ^ a;
        a = *outputCur;
        inputCur++;
        outputCur++;
    }
}
void simple_encrypt::decrypt_decrypt(uint8_t *input, int length, uint8_t *output)
{
    int i = 0, j = 0, t;
    unsigned char temp;
    // memcpy(S, m_init_s, SBOX_SIZE);

    uint8_t a = 10;
    uint8_t *inputCur  = input;
    uint8_t *inputEnd  = input + length;
    uint8_t *outputCur = output;

    while (inputCur < inputEnd)
    {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        t = (S[i] + S[j]) & 0xff;
        *outputCur = *inputCur ^ S[t] ^ a;
        a = *inputCur;
        inputCur++;
        outputCur++;
    }
}