#include "netPort.h"
#include "../hub/hub.h"
#include "../simple_encrypt.h"

extern simple_encrypt *g_ecn; 
#define BigLittleSwap16(A)      ((((uint16_t)(A) & 0xff00) >> 8) | (((uint16_t)(A) & 0x00ff) << 8))
//#define BUF_3BYTE_TO_UINT(buf)  ((uint32_t)((((uint8_t *)(buf))[0]<<16) | (((uint8_t *)(buf))[1]<<8) | (((uint8_t *)(buf))[2])))

CNetPort::CNetPort()
{
    m_type = 2;
    m_localBuf.buf    = new uint8_t[64 * 1024];
    m_localBuf.buflen = 0;
    m_linkParm        = new LinkParam();
    m_deBuf           = new uint8_t[64 * 1024];
    m_enBuf           = new uint8_t[64 * 1024];
    m_count           = 0;
}

CNetPort::~CNetPort()
{
    CHub *hub = (CHub*)m_hub;
    if(hub)
    {
        hub->cleanLink(m_linkParm);
    }
    
    m_linkParm->delRef();
    delete m_localBuf.buf;
    delete m_deBuf;
    delete m_enBuf;
}

int CNetPort::writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam)
{
    int ret = 0;
    LinkParam *param = (LinkParam *)dstParam;
    uint8_t localdata[5];
    int needSend = len + 2;
    localdata[0] = 0x17;
    localdata[1] = 0x03;
    localdata[2] = 0x03;
    localdata[3] = ((needSend & 0xff00) >> 8);
    localdata[4] = needSend & 0xff;

    if (2 == type || 1 == type)
    {   
        g_ecn->encrypt_decrypt(data, len , m_enBuf, m_count++);
        ret = param->linkMgr->sendData(param->link, localdata, 5, m_enBuf, needSend);
    }
    return ret;
}


int32_t CNetPort::processFromNet(uint8_t *data, int len)
{
    if(len <= 0)
    {
        return len;
    }
    CHub *hub = (CHub*)m_hub;
    int32_t ret = 0;

    uint16_t  payloadLen;
    uint8_t  *curPost     = NULL;
    uint8_t  *prcoessData = NULL;
    uint32_t remainLen = 0;
    uint32_t copyLen   = 0;
    uint32_t partLen;
    uint16_t partSSLlen;
    if (m_localBuf.buflen > 0)
    {
        uint32_t total = m_localBuf.buflen + len;
        if(total <= 5)
        {
            memcpy(m_localBuf.buf + m_localBuf.buflen, data, len);
            m_localBuf.buflen += len;
            return len;
        }
        if (m_localBuf.buflen < 5)
        {
            memcpy(m_localBuf.buf + m_localBuf.buflen, data, 5 - m_localBuf.buflen);
        }
        partSSLlen = BigLittleSwap16(*((uint16_t*)(m_localBuf.buf + 3))) + 5;

        if ((m_localBuf.buflen + len) == partSSLlen)
        {
            prcoessData = (uint8_t*)m_localBuf.buf;
            memcpy((m_localBuf.buf + m_localBuf.buflen), data, len);
        }
        else if ((m_localBuf.buflen + len) > partSSLlen)
        {
            copyLen = partSSLlen - m_localBuf.buflen;
            memcpy((m_localBuf.buf + m_localBuf.buflen), data, copyLen);
            curPost     = data + copyLen;
            remainLen   = len - copyLen;
            prcoessData = (uint8_t*)m_localBuf.buf;
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
            payloadLen  = BigLittleSwap16(*((uint16_t*)(data + 3))) + 5;
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
                prcoessData   = NULL;
            }
            else if (payloadLen == len)
            {

            }
            else
            {
                curPost   = data + payloadLen;
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
                prcoessData   = NULL;
            }
        }
    }
    if (NULL == prcoessData)
    {
        return 0;
    }

    m_localBuf.buflen =0;
    partSSLlen = BigLittleSwap16(*((uint16_t*)(prcoessData + 3))) + 5;
    if (*prcoessData != 0x17)
    {
        return 0;
    }
    if (partSSLlen > 2048)
    {
        return 0;
    }

    g_ecn->decrypt_decrypt(prcoessData + 5, partSSLlen - 5, m_deBuf);
    ret = hub->addData(m_deBuf + 2 , partSSLlen - 7, m_linkParm);

    //NOTICE("write data: " << partSSLlen << "  line  " << __LINE__);
    //NOTICE("write data id : " << (uint16_t)*m_deBuf << "  line  " << __LINE__);

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
            partLen = BigLittleSwap16(*((uint16_t*)(curPost + 3))) + 5;
            if (remainLen >= partLen)
            {
                g_ecn->decrypt_decrypt(curPost + 5, partLen - 5, m_deBuf);
                ret = hub->addData(m_deBuf + 2, partLen - 7, m_linkParm);
                //NOTICE("write data id : " << (uint16_t)*m_deBuf << "  line  " << __LINE__);
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
    return len;
}

int32_t CNetPort::regtoUp(void *mgr)
{
    CHub *hub = (CHub*)m_hub;
    int ret = hub->addData(NULL, -1, m_linkParm);
    return ret;
}

void CNetPort::set(void *mgr, void *peer)
{
    m_linkParm->linkMgr   = (CNetworkMgr *)mgr;
    m_linkParm->link      = (CLinkPeer *)peer;
    m_linkParm->interFace = this; 
}
