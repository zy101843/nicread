#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
class dhHand
{
public:
    dhHand();
    ~dhHand();
public:
    unsigned char *getPublic(int &pkLen);
    unsigned char *getShare(uint8_t *pub, int pub_len, int &outlen);

public:
   int      write(uint8_t *data, int len);
   uint8_t *realen(int &len);
public:
    unsigned char *m_public;
    int            m_pubenLen;
public:
    static  void initAllParam();
public:
    static   EVP_PKEY  *dh_params;
    static   BIGNUM    *m_p;
    static   BIGNUM    *m_g; 
public:
    DH       *m_dh;
    EVP_PKEY *m_key;
   
};