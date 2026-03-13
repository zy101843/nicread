#include "dhHand.h"


//#define SSL_MY_3
#ifdef  SSL_MY_3
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#endif

EVP_PKEY *dhHand::dh_params = NULL;
BIGNUM *dhHand::m_p  = NULL;
BIGNUM *dhHand::m_g  = NULL;

static const unsigned char ffdhe2048_p[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF};
static const unsigned char ffdhe2048_g[] = { 0x02 };

void print_hex(const char *label, const unsigned char *data, int len)
{
    printf("%s:", label);
    for (int i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}


int dhHand::write(uint8_t *data, int len)
{
    FILE *fp = NULL;
    fp = fopen("output2.bin", "wb");  // "wb" = 写入二进制文件
    if (fp == NULL) {
        perror("fopen_s failed");
        return 0;
    }

    size_t written = fwrite(data, 1, len, fp);
    if (written != len) {
        perror("fwrite failed");
    }
    fclose(fp);
    return len;
}

uint8_t *dhHand::realen(int &len)
{
    FILE *fp = NULL;

    fp = fopen("output.bin", "rb");
    if (fp == NULL) 
    {
        perror("fopen_s failed");
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    rewind(fp);

    if (filesize <= 0 || filesize > SIZE_MAX) {
        perror("invalid file size");
        fclose(fp);
        return NULL;
    }

    char *buffer = (char*)malloc((size_t)filesize);
    if (!buffer) 
    {
        perror("malloc failed");
        fclose(fp);
        return NULL;
    }
    size_t bytesRead = fread(buffer, 1, (size_t)filesize, fp);
    if (bytesRead != (size_t)filesize) 
    {
        perror("fread failed or incomplete");
        free(buffer);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    len = (int)bytesRead;
    return (uint8_t *)buffer;
}

dhHand::dhHand()
{
    m_public   = NULL;
    m_pubenLen = 0;
    m_key      = NULL;
    m_dh       = NULL;
}

dhHand::~dhHand()
{
#ifdef SSL_MY_3
    EVP_PKEY_free(m_key);
#else
    DH_free(m_dh);
#endif
   if (NULL != m_public)
    {
        free(m_public);
        m_public = NULL;
    }
    m_pubenLen = 0;
}

#ifndef SSL_MY_3
unsigned char *dhHand::getPublic(int &pkLen)
{
    if (NULL == m_public)
    {
        m_dh = DH_new();
        DH_set0_pqg(m_dh, BN_dup(m_p), NULL, BN_dup(m_g));
        if (!DH_generate_key(m_dh))
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        const BIGNUM *pubA;
        DH_get0_key(m_dh, &pubA, NULL);
        m_pubenLen = BN_num_bytes(pubA);
        m_public = (unsigned char *)malloc(m_pubenLen);
        BN_bn2bin(pubA, m_public);
        sha256(m_hash, m_public, m_pubenLen);
    }
    pkLen = m_pubenLen;
    return m_public;
}

unsigned char * dhHand::getShare(uint8_t *pub, int pub_len, int &outlen)
{
    int secret_len = DH_size(m_dh);
    BIGNUM *pu = BN_bin2bn(pub, pub_len, NULL);
    unsigned char * secret     = (unsigned char *)malloc(secret_len);
    secret_len = DH_compute_key(secret, pu, m_dh);
    BN_free(pu);
    outlen  = secret_len;
    return secret;
}

#else

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


EVP_PKEY *create_dh_params(void)
{
    EVP_PKEY *params = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params_data = NULL;

    if (!bld)
    {
        handleErrors();
    }
    BIGNUM *p_bn = BN_bin2bn(ffdhe2048_p, sizeof(ffdhe2048_p), NULL);
    BIGNUM *g_bn = BN_bin2bn(ffdhe2048_g, sizeof(ffdhe2048_g), NULL);

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p_bn) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g_bn))
        handleErrors();

    params_data = OSSL_PARAM_BLD_to_param(bld);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!ctx)
        handleErrors();

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        handleErrors();

    if (EVP_PKEY_fromdata(ctx, &params, EVP_PKEY_KEY_PARAMETERS, params_data) <= 0)
        handleErrors();

   
    BN_free(p_bn);
    BN_free(g_bn);
    OSSL_PARAM_free(params_data);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);

    return params;
}


 


unsigned char *get_dh_pubkey(EVP_PKEY *key, int *outlen)
{
    BIGNUM *pub_bn = NULL;
    if (EVP_PKEY_get_bn_param(key, "pub", &pub_bn) <= 0)
    {
        handleErrors();
    }
    int len = BN_num_bytes(pub_bn);
    unsigned char *buf = (unsigned char *)malloc(len);
    BN_bn2bin(pub_bn, buf);
    BN_free(pub_bn);
    *outlen = len;
    return buf;
}



EVP_PKEY *create_peer_key(EVP_PKEY *params, unsigned char *pub, int pub_len)
{
    EVP_PKEY *peer      = NULL;
    BIGNUM *pub_bn      = BN_bin2bn(pub, pub_len, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params_data = NULL;
    BIGNUM *p_bn = NULL;
    BIGNUM *g_bn = NULL;

    // 从params取出P,G
    if (EVP_PKEY_get_bn_param(params, OSSL_PKEY_PARAM_FFC_P, &p_bn) <= 0 ||
        EVP_PKEY_get_bn_param(params, OSSL_PKEY_PARAM_FFC_G, &g_bn) <= 0)
        handleErrors();

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p_bn) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g_bn) ||
        !OSSL_PARAM_BLD_push_BN(bld, "pub", pub_bn))
        handleErrors();

    params_data = OSSL_PARAM_BLD_to_param(bld);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!ctx)
        handleErrors();

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        handleErrors();

    if (EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY, params_data) <= 0)
        handleErrors();

    BN_free(pub_bn);
    BN_free(p_bn);
    BN_free(g_bn);
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params_data);
    EVP_PKEY_CTX_free(ctx);
    return peer;
}

unsigned char * dhHand::getPublic(int &pkLen)
{
    //dh_params = create_dh_params();
    EVP_PKEY_CTX *keygen_ctx;


    keygen_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_params, NULL);
    EVP_PKEY_keygen_init(keygen_ctx);
    EVP_PKEY_keygen(keygen_ctx, &m_key);
    EVP_PKEY_CTX_free(keygen_ctx);

    m_public = get_dh_pubkey(m_key, &m_pubenLen);
    pkLen = m_pubenLen;
    sha256(m_hash, m_public, m_pubenLen);

    return m_public;
}

unsigned char * dhHand::getShare(uint8_t *pub, int pub_len, int &outlen)
{
    EVP_PKEY *peerA = create_peer_key(dh_params, pub, pub_len);
    EVP_PKEY_CTX *deriveA = EVP_PKEY_CTX_new_from_pkey(NULL, m_key, NULL);

    EVP_PKEY_derive_init(deriveA);
    EVP_PKEY_derive_set_peer(deriveA, peerA);

    size_t secretA_len;
    EVP_PKEY_derive(deriveA, NULL, &secretA_len);
    unsigned char *secretA = (unsigned char *)malloc(secretA_len);
    EVP_PKEY_derive(deriveA, secretA, &secretA_len);
    outlen = secretA_len;

    EVP_PKEY_CTX_free(deriveA);
    EVP_PKEY_free(peerA);
    return secretA;
}
#endif
void dhHand::initAllParam()
{
#ifdef SSL_MY_3
    dh_params = create_dh_params();
#else
    m_p = BN_bin2bn(ffdhe2048_p, sizeof(ffdhe2048_p), NULL);
    m_g = BN_bin2bn(ffdhe2048_g, sizeof(ffdhe2048_g), NULL);
#endif
}

int dhHand::sha256(unsigned char *out, uint8_t *in, int inlen)
{
    EVP_MD_CTX *ctxHash = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctxHash, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctxHash, in, inlen);
    EVP_DigestFinal_ex(ctxHash, out, NULL);
    EVP_MD_CTX_free(ctxHash);
    return 32;
}