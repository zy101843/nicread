#pragma once
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

class simple_encrypt
{
public:
    enum
    {
        SBOX_SIZE = 256
    };

public:
    simple_encrypt(uint8_t *key, int key_length);
    ~simple_encrypt();
    int initkey(uint8_t *key, int key_length);
    uint8_t *getaeskey();
    void encrypt_decrypt(uint8_t *input, int length, uint8_t *output, uint16_t id);
    void decrypt_decrypt(uint8_t *input, int length, uint8_t *output);


    int encryptAes(uint8_t *plaintext, int plaintext_len, uint8_t *ciphertext, uint16_t id);
    int decryptAes(uint8_t *ciphertext, int ciphertext_len, uint8_t *plaintext);
private:
    uint8_t S[256];
    uint8_t m_init_s[256];

    EVP_CIPHER_CTX *m_ctxRes;
    EVP_CIPHER_CTX *m_ctxSed;

    uint8_t         m_key[16];
    uint8_t         m_reskey[16];
    uint8_t         m_resiv[16];

    uint8_t         m_sedkey[16];
    uint8_t         m_sediv[16];
};