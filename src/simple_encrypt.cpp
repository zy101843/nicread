#include "simple_encrypt.h"
#include <cstring>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

simple_encrypt::simple_encrypt(uint8_t *key, int key_length)
{
    int i = 0;
    int j = 0;
    unsigned char temp;
    for (i = 0; i < SBOX_SIZE; i++)
    {
        S[i] = i;
    }
    for (i = 0; i < SBOX_SIZE; i++)
    {
        j = (j + S[i] + key[i % key_length]) & 0xff;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    memcpy(m_init_s, S, SBOX_SIZE);

    m_ctxRes = NULL;
    m_ctxSed = NULL;
    initkey(key, key_length);
}
simple_encrypt::~simple_encrypt()
{
    if (m_ctxRes)
    {
        EVP_CIPHER_CTX_free(m_ctxRes);
    }
    if (m_ctxSed)
    {
        EVP_CIPHER_CTX_free(m_ctxSed);
    }
}

bool generate_key(uint8_t *plaintext, int key_length, unsigned char *key, int key_len)                 
{
    const int iterations = 10; 
    unsigned char salt[]="aaff55aa";
    if (1 != PKCS5_PBKDF2_HMAC(
                 (char *)plaintext, key_length, 
                 salt, 8,                        
                 iterations, EVP_sha256(),              
                 key_len, key))
    { 
        return false;
    }
    return true;
}
EVP_PKEY *get_ffdhe_params();
int simple_encrypt::initkey(uint8_t *key, int key_length)
{

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);
    generate_key(key, key_length, m_key, 16);
   
    return 0;
}
uint8_t *simple_encrypt::getaeskey()
{
    return m_key;
}

void simple_encrypt::encrypt_decrypt(uint8_t *input, int length, uint8_t *output, uint16_t id)
{
    int i = 0, j = 0, t;
    unsigned char temp;
    uint8_t a = 10;
    uint8_t *inputCur = input;
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


    uint8_t a = 10;
    uint8_t *inputCur = input;
    uint8_t *inputEnd = input + length;
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

int simple_encrypt::encryptAes(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, uint16_t id)
{
    int len            =0;
    int ciphertext_len =0;

    if (1 != EVP_EncryptInit_ex(m_ctxSed, NULL, NULL, NULL, NULL)) {
        std::cerr << "init error" << std::endl;
        return -1;
    }

    if (1 != EVP_EncryptUpdate(m_ctxSed, ciphertext, &len, (uint8_t*)&id, 2))
    {
        //EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    if (1 != EVP_EncryptUpdate(m_ctxSed, ciphertext, &len, plaintext, plaintext_len))
    {
        //EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

   
    if (1 != EVP_EncryptFinal_ex(m_ctxSed, ciphertext + len, &len))
    {
        //EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    //EVP_CIPHER_CTX_reset(m_ctxSed);
    return ciphertext_len;
}

int simple_encrypt::decryptAes(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    int len = 0;
    int plaintext_len =0;

    if (1 != EVP_DecryptInit_ex(m_ctxRes, NULL, NULL, NULL, NULL)) {
        std::cerr << "init error" << std::endl;
        return -1;
    }

    if (1 != EVP_DecryptUpdate(m_ctxRes, plaintext, &len, ciphertext, ciphertext_len))
    {
        //EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(m_ctxRes, plaintext + len, &len))
    {
        //EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    //EVP_CIPHER_CTX_reset(m_ctxRes);
    return plaintext_len;
}



