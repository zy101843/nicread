#include "rsaProc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>


void print_error(const char *msg) {
    fprintf(stderr, "%s: ", msg);
    ERR_print_errors_fp(stderr);
}


EVP_PKEY *load_private_key(const char *filename, const char *passwd) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("fopen"); return NULL; }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void*)passwd);
    fclose(fp);
    if (!pkey) print_error("PEM_read_PrivateKey");
    return pkey;
}


EVP_PKEY *load_public_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("fopen"); return NULL; }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) print_error("PEM_read_PUBKEY");
    return pkey;
}

int rsa_encrypt(void *param, const uint8_t *plaintext, int plaintext_len, uint8_t **ciphertext, int *ciphertext_len)
{
    EVP_PKEY *pubkey = (EVP_PKEY *)param;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ct = NULL;
    size_t temp_len = 0;

    ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) goto err;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto err;


    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto err;    
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) goto err;     


    if (EVP_PKEY_encrypt(ctx, NULL, &temp_len, plaintext, plaintext_len) <= 0)
        goto err;

    ct = (unsigned char*) malloc(temp_len);
    if (!ct) goto err;

    if (EVP_PKEY_encrypt(ctx, ct, &temp_len, plaintext, plaintext_len) <= 0) {
        free(ct); ct = NULL; goto err;
    }

    *ciphertext     = ct;
    *ciphertext_len = temp_len;
    EVP_PKEY_CTX_free(ctx);
    return 0;

err:
    ERR_print_errors_fp(stderr);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (ct) free(ct);
    return -1;
}

int rsa_decrypt(void *param, const uint8_t *ciphertext, int ciphertext_len, uint8_t **plaintext, int *plaintext_len)
{
    EVP_PKEY *privkey = (EVP_PKEY *)param;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *pt = NULL;
    size_t temp_len = 0;

    ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) goto err;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto err;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) goto err;

    if (EVP_PKEY_decrypt(ctx, NULL, &temp_len, ciphertext, ciphertext_len) <= 0)
        goto err;

    pt =(unsigned char*) malloc(temp_len);
    if (!pt) goto err;

    if (EVP_PKEY_decrypt(ctx, pt, &temp_len, ciphertext, ciphertext_len) <= 0) {
        free(pt); pt = NULL; goto err;
    }

    *plaintext      = pt;
    *plaintext_len  = temp_len;
    EVP_PKEY_CTX_free(ctx);
    return 0;

err:
    ERR_print_errors_fp(stderr);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pt) free(pt);
    return -1;
}


int publicEnc(const char *keyPath, const uint8_t *plaintext, int plaintext_len, uint8_t **ciphertext, int *ciphertext_len ,int type )
{

    EVP_PKEY *pubkey;
    if( type == 1  )
    { 
        pubkey = load_public_key(keyPath);
    }
    else
    {
       pubkey = load_private_key(keyPath, NULL);
    }
    if (!pubkey )
    {
        return -1;
    }
    int ret = rsa_encrypt(pubkey, plaintext, plaintext_len, ciphertext, ciphertext_len);
    EVP_PKEY_free(pubkey);
    return ret;

}
int keyDec(const char *keyPath, const uint8_t *ciphertext, int ciphertext_len, uint8_t **plaintext, int *plaintext_len, int type)
{
    EVP_PKEY *privkey;
    if (type == 1)
    {
        privkey = load_private_key(keyPath, NULL);
    }
    else
    {
        privkey = load_public_key(keyPath);
    }
    if (!privkey)
    {
        return -1;
    }
    int ret = rsa_decrypt(privkey, ciphertext, ciphertext_len, plaintext, plaintext_len);
    EVP_PKEY_free(privkey);
    return ret;
}

int rest_test() {

    const char *msg = "Hello OpenSSL RSA 2025!";
    int  msg_len = (int)strlen(msg);
    uint8_t *enc = NULL;
    int     encLen = 0;

    uint8_t *plan = NULL;
    int     planLen = 0;
    int ret = -1;
    if (0 == publicEnc("/zy/key/public_key.pem", (uint8_t*)msg, msg_len, &enc, &encLen))
    {
        if (0 == keyDec("/zy/key/private_key.pem", enc, encLen, &plan, &planLen))
        {
            if (0 == memcmp(msg, plan, planLen))
            {
                ret = 0;
            }
            free(plan);
            free(enc);
        }
        else
        {
            free(enc);
        }
    }
    return ret;
  
}