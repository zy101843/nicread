#pragma once 
#include "../interface.h"
#include "../NetModeBase.h"
#include "../simple_encrypt.h"
#include "../dhHand.h"
#include <vector>
#include <atomic>

#include <openssl/evp.h>
#include <openssl/aes.h>

struct loaclbuf
{
    uint8_t  *buf;
    uint32_t  buflen;
};

class CNetPort : public Interface
{
public:
    CNetPort();
    virtual  ~CNetPort();
public:
    virtual int writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam);
public:
    int32_t processFromNet(uint8_t *data, int len);
    int32_t regtoUp(void *mgr, int type);
public:
    void set(void *mgr, void *peer);
    void setKeyPath(std::string &path);
public:
    virtual void cleanPort(int type);
public:
    int  addRef();
    int  delRef();
public:
    int initkey();
    int restInitkey(uint8_t *key, int len, int dir);
    int encryptAes(uint8_t *plaintext, int plaintext_len, uint8_t  *ciphertext, uint16_t id);
    int decryptAes(uint8_t *ciphertext, int ciphertext_len, uint8_t *plaintext);
    int processData(uint8_t *data, int len);
    int processDataClint(uint8_t *data, int len);
    int HandData(uint8_t *data, int len, void *dstParam);
private:
    int registerToHub();
    int writetoHub(uint8_t *data, int len);
    int localwriteData(uint8_t *data, int len);
    int mkFristPacketClien(uint8_t **data);
    int mkFristPacketServer(uint8_t **data);
private:
    LinkParam   *m_linkParm;
    loaclbuf    m_localBuf;
    uint8_t     *m_deBuf;
    uint8_t     *m_enBuf;
    uint16_t     m_count;
    uint32_t     m_recvCount;
    bool         m_keyInit;

    EVP_CIPHER_CTX   *m_ctxRes;
    EVP_CIPHER_CTX   *m_ctxSed;
    uint8_t           m_reskey[16];
    uint8_t           m_resiv[16];
    uint8_t           m_sedkey[16];
    uint8_t           m_sediv[16];
    int               m_linkType;
    uint8_t           m_headdata[5];
    std::atomic<int>  m_ref;
    dhHand            *m_dhHand;
    uint32_t          m_recCount;
    uint32_t          m_sedCount;
    uint8_t           *m_outhKey;
    int               m_outhKeylen;
    uint8_t           m_localHash[32];
    std::string       m_keyPath;
};

