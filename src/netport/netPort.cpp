#include "netPort.h"
#include "../hub/hub.h"
#include "../rsaProc.h"

//extern simple_encrypt *g_ecn;
extern dhHand *g_dh;
#define BigLittleSwap16(A) ((((uint16_t)(A) & 0xff00) >> 8) | (((uint16_t)(A) & 0x00ff) << 8))

CNetPort::CNetPort()
{
    m_ref.store(1);
    m_type = 2;
    m_localBuf.buf = new uint8_t[64 * 1024];
    m_localBuf.buflen = 0;
    m_linkParm = new LinkParam();
    m_linkParm->linkType    = 2;
    m_linkParm->linkSubType = 0;
    m_linkParm->interFace = this;
    m_deBuf = new uint8_t[64 * 1024];
    m_enBuf = new uint8_t[64 * 1024];
    m_count = 0;
    m_recvCount = 0;
    m_ctxRes = NULL;
    m_ctxSed = NULL;
    m_linkType = 0;
    m_headdata[0] = 0x17;
    m_headdata[1] = 0x03;
    m_headdata[2] = 0x03;
    m_dhHand = NULL;
    m_recCount = 0;
    m_sedCount = 0;
    m_keyInit = false;
    m_outhKey = NULL;
}

int CNetPort::addRef()
{
    int ret = ++m_ref;
    return ret;
}
int CNetPort::delRef()
{
    int ret = --m_ref;
    if (ret == 0)
    {
        printf("delete linkport %d CNetPort::%s %d\n", ret, __FUNCTION__, __LINE__);
        delete this;
    }
    return ret;
}

void CNetPort::cleanPort(int type)
{
    m_linkParm->setLink(false);
    if (type == 1)
    {
        int refPar = -1;
        if (m_hub && m_linkParm->upReg)
        {
            m_hub->reg(-2, m_linkParm);
        }
        m_hub = NULL;
        refPar = m_linkParm->delRef();
        printf("delete link param %d  CNetPort::%s %d\n", refPar, __FUNCTION__, __LINE__);
    }
    delRef();
}

CNetPort::~CNetPort()
{
    delete m_localBuf.buf;
    delete m_deBuf;
    delete m_enBuf;

    if (m_ctxRes)
    {
        EVP_CIPHER_CTX_free(m_ctxRes);
    }
    if (m_ctxSed)
    {
        EVP_CIPHER_CTX_free(m_ctxSed);
    }
    if (NULL != m_dhHand)
    {
        delete m_dhHand;
        m_dhHand = NULL;
    }
    if (m_outhKey)
    {
        delete[] m_outhKey;
        m_outhKey = NULL;
    }
}

int CNetPort::initkey()
{
    return 0;
}

int CNetPort::restInitkey(uint8_t *key, int len, int dir)
{
    if (len < 32)
    {
        return 0;
    }
    if (m_ctxRes)
    {
        EVP_CIPHER_CTX_free(m_ctxRes);
    }
    if (m_ctxSed)
    {
        EVP_CIPHER_CTX_free(m_ctxSed);
    }

    m_ctxRes = EVP_CIPHER_CTX_new();
    m_ctxSed = EVP_CIPHER_CTX_new();

    if (1 == dir)
    {
        memcpy(m_sedkey, key, 16);
        memcpy(m_sediv, key + 16, 16);
        memcpy(m_reskey, key + 32, 16);
        memcpy(m_resiv, key + 48, 16);
    }
    else
    {
        memcpy(m_reskey, key, 16);
        memcpy(m_resiv, key + 16, 16);
        memcpy(m_sedkey, key + 32, 16);
        memcpy(m_sediv, key + 48, 16);
    }

    if (1 != EVP_DecryptInit_ex(m_ctxRes, EVP_aes_128_gcm(), NULL, NULL, NULL))
    {
        std::cerr << "init error" << std::endl;
        return -1;
    }
    if (1 != EVP_EncryptInit_ex(m_ctxSed, EVP_aes_128_gcm(), NULL, NULL, NULL))
    {
        std::cerr << "init error" << std::endl;
        return -1;
    }

    EVP_CIPHER_CTX_ctrl(m_ctxRes, EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
    EVP_EncryptInit_ex(m_ctxRes, NULL, NULL, m_reskey, m_resiv);

    EVP_CIPHER_CTX_ctrl(m_ctxSed, EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
    EVP_EncryptInit_ex(m_ctxSed, NULL, NULL, m_sedkey, m_sediv);
    m_keyInit = true;
    return 0;
}

int CNetPort::encryptAes(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, uint16_t id)
{
    int len = 0;
    int ciphertext_len = 0;
    (void)id;

    *(uint32_t *)(m_sediv + 12) = m_sedCount;
    m_sedCount++;

    if (1 != EVP_EncryptInit_ex(m_ctxSed, NULL, NULL, NULL, m_sediv))
    {
        std::cerr << "init error" << std::endl;
        return -1;
    }
    ciphertext_len = 8;
    if (1 != EVP_EncryptUpdate(m_ctxSed, ciphertext + ciphertext_len, &len, plaintext, plaintext_len))
    {
        return -1;
    }
    ciphertext_len += len;
    len = 0;
    if (1 != EVP_EncryptFinal_ex(m_ctxSed, ciphertext + ciphertext_len, &len))
    {
        return -1;
    }
    ciphertext_len += len;
    if (1 != EVP_CIPHER_CTX_ctrl(m_ctxSed, EVP_CTRL_GCM_GET_TAG, 8, ciphertext))
    {
        return -1;
    }
    return ciphertext_len;
}

int CNetPort::decryptAes(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    int len = 0;
    int plaintext_len = 0;

    *(uint32_t *)(m_resiv + 12) = m_recCount;
    m_recCount++;
    if (1 != EVP_DecryptInit_ex(m_ctxRes, NULL, NULL, NULL, m_resiv))
    {
        std::cerr << "init error" << std::endl;
        return -1;
    }
    if (1 != EVP_DecryptUpdate(m_ctxRes, plaintext, &len, ciphertext + 8, ciphertext_len - 8))
    {
        return -1;
    }
    plaintext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(m_ctxRes, EVP_CTRL_GCM_SET_TAG, 8, ciphertext))
    {
        return -1;
    }
    len = 0;
    int abc = EVP_DecryptFinal_ex(m_ctxRes, plaintext + plaintext_len, &len);
    if (abc <= 0)
    {
        return -1;
    }
    plaintext_len += len;
    return plaintext_len;
}

int CNetPort::writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam)
{
    int ret = 0;
    (void)type;
    (void)srcparam;
    bool link = m_linkParm->isLink();
    if (!link || dstParam != m_linkParm)
    {
        return -1;
    }
    ret = localwriteData(data, len);
    return ret;
}

int CNetPort::localwriteData(uint8_t *data, int len)
{
    int ret = 0;
    int needSend = encryptAes(data, len, m_enBuf, m_count++);
    uint8_t *post = m_headdata + 3;
    *post = ((needSend & 0xff00) >> 8);
    post++;
    *post = needSend & 0xff;
    ret = m_linkParm->linkMgr->sendData(m_linkParm->link, m_headdata, 5, m_enBuf, needSend);
    return ret;
}

int CNetPort::HandData(uint8_t *data, int len, void *dstParam)
{
    int ret = 0;
    unsigned int locallen = len + 4;
    LinkParam *param = (LinkParam *)dstParam;
    uint8_t local[9];
    uint8_t *post = local;
    *post = 0x17;
    post++;
    *post = 0x03;
    post++;
    *post = 0x03;
    post++;
    *post = ((locallen & 0xff00) >> 8);
    post++;
    *post = locallen & 0xff;
    post++;
    *((uint32_t *)(post)) = (*((uint32_t *)(data))) ^ 0xA55A5AA5;
    ret = param->linkMgr->sendData(param->link, local, 9, data, len);
    return ret;
}


int32_t CNetPort::processFromNet(uint8_t *data, int len)
{
    if (len <= 0)
    {
        return len;
    }
    int32_t ret = len;

    uint16_t payloadLen;
    uint8_t *curPost = NULL;
    uint8_t *prcoessData = NULL;
    uint32_t remainLen = 0;
    uint32_t copyLen = 0;
    uint32_t partLen;
    uint16_t partSSLlen;
    int deslen = 0;
    if (m_localBuf.buflen > 0)
    {
        uint32_t total = m_localBuf.buflen + len;
        if (total <= 5)
        {
            memcpy(m_localBuf.buf + m_localBuf.buflen, data, len);
            m_localBuf.buflen += len;
            return len;
        }
        if (m_localBuf.buflen < 5)
        {
            memcpy(m_localBuf.buf + m_localBuf.buflen, data, 5 - m_localBuf.buflen);
        }
        partSSLlen = BigLittleSwap16(*((uint16_t *)(m_localBuf.buf + 3))) + 5;
        if ((*m_localBuf.buf) != 0x17)
        {
            m_localBuf.buflen = 0;
            return 0;
        }
        if (partSSLlen > 2048)
        {
            m_localBuf.buflen = 0;
            return 0;
        }

        if ((m_localBuf.buflen + len) == partSSLlen)
        {
            prcoessData = (uint8_t *)m_localBuf.buf;
            memcpy((m_localBuf.buf + m_localBuf.buflen), data, len);
        }
        else if ((m_localBuf.buflen + len) > partSSLlen)
        {
            copyLen = partSSLlen - m_localBuf.buflen;
            memcpy((m_localBuf.buf + m_localBuf.buflen), data, copyLen);
            curPost = data + copyLen;
            remainLen = len - copyLen;
            prcoessData = (uint8_t *)m_localBuf.buf;
        }
        else
        {
            memcpy((m_localBuf.buf + m_localBuf.buflen), data, len);
            m_localBuf.buflen += len;
        }
    }
    else
    {
        prcoessData = data;
        if (len >= 5)
        {
            payloadLen = BigLittleSwap16(*((uint16_t *)(data + 3))) + 5;
            if (*data != 0x17)
            {
                return 0;
            }
            if (payloadLen > 2048)
            {
                return 0;
            }
            if (payloadLen > len)
            {
                memcpy((m_localBuf.buf), data, len);
                m_localBuf.buflen = len;
                prcoessData = NULL;
            }
            else if (payloadLen == len)
            {
            }
            else
            {
                curPost = data + payloadLen;
                remainLen = len - payloadLen;
            }
        }
        else
        {
            if (*prcoessData != 0x17)
            {
                return 0;
            }
            else
            {
                memcpy((m_localBuf.buf), data, len);
                m_localBuf.buflen = len;
                prcoessData = NULL;
            }
        }
    }
    if (NULL == prcoessData)
    {
        return 1;
    }

    m_localBuf.buflen = 0;
    partSSLlen = BigLittleSwap16(*((uint16_t *)(prcoessData + 3))) + 5;
    if (*prcoessData != 0x17)
    {
        return 0;
    }
    if (partSSLlen > 2048)
    {
        return 0;
    }
    if (partSSLlen < 16)
    {
        return 0;
    }
    bool send = true;
    if (m_recvCount == 0)
    {
        uint32_t mag = *((uint32_t *)(prcoessData + 5));
        mag ^= *((uint32_t *)(prcoessData + 9));
        if (mag == 0xA55A5AA5)
        {
            if (m_linkType == 2)
            {
                ret = processDataClint(prcoessData, partSSLlen);
                if(ret == -1)
                {
                    return 0;
                }

            }
            else if (m_linkType == 1)
            {
                ret = processData(prcoessData, partSSLlen);
            }
            if (NULL != curPost)
            {
                return 0;
            }
            return partSSLlen;
        }
        else
        {
            if (false == m_keyInit)
            {
                return 0;
            }
            deslen = decryptAes(prcoessData + 5, partSSLlen - 5, m_deBuf);
            if (deslen <= 0)
            {
                return 0;
            }
            if (m_linkType == 1)
            {
                int frsitlen = 0;
                uint8_t *fristdata = NULL;
                const  char *localPath = "private_key.pem";
                if(m_keyPath.empty() == false)
                {
                    localPath = m_keyPath.c_str();
                }  
                     
                if (0 == keyDec(localPath, m_deBuf + 4, deslen - 4, &fristdata, &frsitlen))
                {
                    if (frsitlen != 32 && 0 != memcmp(fristdata, m_localHash, 32))
                    {
                        free(fristdata);
                        return 0;
                    }
                    free(fristdata);
                    m_id = *((uint32_t *)(m_deBuf));
                    m_linkParm->id = m_id;
                    printf("first pub key check is good id: %d \n" ,m_id);
                    uint8_t *first_flag = NULL;
                    int send = mkFristPacketServer(&first_flag);
                    localwriteData(first_flag, send);
                    delete[] first_flag;
                    m_linkParm->setLink(true);
                    registerToHub();
                    m_recvCount = 1;
                }
                else
                {
                    return 0;
                }
            }
            else
            {
                if (deslen == 32 && 0 == memcmp(m_deBuf, m_localHash, 32))
                {
                    printf("servier hash is good \n");
                    m_linkParm->setLink(true);
                    registerToHub();
                    m_recvCount = 1;
                }
                else
                {
                    printf("servier hash is not good %d\n", deslen);
                    printf("m_deBuf key is:");
                    for (int i = 0; i < 16; i++)
                    {
                        printf("%02x ", m_deBuf[i]);
                    }
                    printf("\n");

                    printf("m_localHash key is:");
                    for (int i = 0; i < 16; i++)
                    {
                        printf("%02x ", m_localHash[i]);
                    }
                    printf("\n");
                    return 0;
                }
            }
        }
    }
    else
    {
        HubMidBuf *midbuf = m_hub->getMidBuf();
        deslen = decryptAes(prcoessData + 5, partSSLlen - 5, midbuf->buf);
        if (deslen <= 0)
        {
            m_hub->returnMidBuf(midbuf);
            return 0;
        }
        midbuf->len = deslen;
        ret = m_hub->addData(midbuf, m_linkParm);
    }
    m_recvCount++;
    if (NULL != curPost)
    {
        while (remainLen)
        {
            if (remainLen <= 5)
            {
                memcpy(m_localBuf.buf, curPost, remainLen);
                m_localBuf.buflen = remainLen;
                break;
            }
            partLen = BigLittleSwap16(*((uint16_t *)(curPost + 3))) + 5;

            if (*curPost != 0x17)
            {
                m_localBuf.buflen = 0;
                return 0;
            }
            if (partLen > 2048)
            {
                m_localBuf.buflen = 0;
                return 0;
            }
            if (partLen < 16)
            {
                m_localBuf.buflen = 0;
                return 0;
            }

            if (remainLen >= partLen)
            {

                HubMidBuf *midbuf = m_hub->getMidBuf();
                deslen = decryptAes(curPost + 5, partLen - 5, midbuf->buf);
                if (deslen <= 0)
                {
                    m_hub->returnMidBuf(midbuf);
                    return 0;
                }
                midbuf->len = deslen;
                ret = m_hub->addData(midbuf, m_linkParm);
                //ret = writetoHub(m_deBuf, deslen);
                m_recvCount++;
                curPost   += partLen;
                remainLen -= partLen;
            }
            else
            {
                memcpy(m_localBuf.buf, curPost, remainLen);
                m_localBuf.buflen = remainLen;
                break;
            }
        }
    }
    if (0 == m_recvCount)
    {
        m_recvCount = 1;
    }
    return ret;
}

int32_t CNetPort::regtoUp(void *mgr, int type)
{
    m_linkType = type;
    if (type == 2)
    {
        m_dhHand = new dhHand();
        int pkeln = 0;
        unsigned char *pk = m_dhHand->getPublic(pkeln);
        memcpy(m_localHash, m_dhHand->m_hash, 32);
        printf("pub key is:");
        for (int i = 0; i < pkeln && i < 16; i++)
        {
            printf("%02x ", pk[i]);
        }
        printf("\n");
        m_linkParm->id = m_id;
        HandData(pk, pkeln, m_linkParm);
    }
    return 1;
}

void CNetPort::set(void *mgr, void *peer)
{
    m_linkParm->linkMgr = (CNetworkMgr *)mgr;
    m_linkParm->link    = (CLinkPeer *)peer;
    addRef();
    m_linkParm->interFace = this;
}

void CNetPort::setKeyPath(std::string &path)
{
    m_keyPath = path;
}


int CNetPort::registerToHub()
{
    m_linkParm->addRef();
    m_linkParm->upReg = true;
    int ret = m_hub->reg(-1, m_linkParm);
    return ret;
}

int CNetPort::writetoHub(uint8_t *data, int len)
{
    int ret = m_hub->addData(data, len, m_linkParm);
    return ret;
}

int CNetPort::processData(uint8_t *data, int len)
{
    int ret = 0;
    int secret_len;
    if (m_linkType != 2)
    {
        m_dhHand = new dhHand();
    }
    int pkeln = 0;

    unsigned char *pk = m_dhHand->getPublic(pkeln);
    memcpy(m_localHash, m_dhHand->m_hash, 32);

    printf("service puk is :");
    for (int i = 0; i < pkeln && i < 16; i++)
    {
        printf("%02x ", pk[i]);
    }

    printf("\n");

    m_outhKey = new uint8_t[len - 9];
    memcpy(m_outhKey, data + 9, len - 9);
    m_outhKeylen = len - 9;

    printf("clien puk is :");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", m_outhKey[i]);
    }
    printf("\n");

    unsigned char *secret = m_dhHand->getShare(data + 9, len - 9, secret_len);
    printf("service key is :");
    for (int i = 0; i < secret_len && i < 16; i++)
    {
        printf("%02x ", secret[i]);
    }
    printf("\n");
    restInitkey(secret, secret_len, 1);
    free(secret);
    HandData(pk, pkeln, m_linkParm);
    delete m_dhHand;
    m_dhHand = NULL;
    return len;
}

int CNetPort::processDataClint(uint8_t *data, int len)
{
    int ret = 0;
    int secret_len;
    unsigned char *secret = m_dhHand->getShare(data + 9, len - 9, secret_len);
    delete m_dhHand;

    m_outhKey = new uint8_t[len - 9];
    memcpy(m_outhKey, data + 9, len - 9);
    m_outhKeylen = len - 9;

    m_dhHand = NULL;
    printf("client key is:");
    for (int i = 0; i < secret_len && i < 16; i++)
    {
        printf("%02x ", secret[i]);
    }
    printf("\n");
    restInitkey(secret, secret_len, 2);
    free(secret);
    uint8_t *first_flag = NULL;
    int fristlen = mkFristPacketClien(&first_flag);
    if (-1 == fristlen)
    {
        return -1;
    }
    localwriteData(first_flag, fristlen);
    delete[] first_flag;

    printf("clinet send frist packet\n");
    if (m_linkParm->link->m_mac[0] != 0)
    {
        m_linkParm->m_ext = m_linkParm->link->m_mac;
    }
    else
    {
        m_linkParm->m_ext = NULL;
    }
    return len;
}

int CNetPort::mkFristPacketClien(uint8_t **data)
{
    int sendlen = 0;
    unsigned char *hash = new unsigned char[32];
    uint8_t *end =0;
    m_dhHand->sha256(hash, m_outhKey, m_outhKeylen);


    const char *localPath = "public_key.pem";
    if (m_keyPath.empty() == false)
    {
        localPath = m_keyPath.c_str();
    }
    int pe = publicEnc(localPath, hash, 32, &end, &sendlen);
    if(pe == -1)
    {
        return -1;
    }
    delete []hash;

    uint8_t *localdata = new uint8_t[sendlen + 4];
    memcpy(localdata + 4, end, sendlen);
    *(uint32_t *)(localdata) = m_id;
    *data = localdata;
    sendlen += 4;
    free(end);

    return sendlen;
}

int CNetPort::mkFristPacketServer(uint8_t **data)
{
    uint8_t *hash = new uint8_t[32];
    *data = hash;
    m_dhHand->sha256(hash, m_outhKey, m_outhKeylen);
    return 32;
}