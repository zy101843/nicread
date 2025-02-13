#pragma once 
#include "../interface.h"
#include "../NetModeBase.h"
#include <vector>
#include <atomic>
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
    int32_t regtoUp(void *mgr);
public:
    void set(void *mgr, void *peer);
private:
    LinkParam   *m_linkParm;
    loaclbuf    m_localBuf;
    uint8_t     *m_deBuf;
    uint8_t     *m_enBuf;
    uint16_t     m_count;
};

