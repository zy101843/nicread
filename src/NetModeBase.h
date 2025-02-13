#pragma once
#include "common.h"

#include "network/linkpeer.h"
#include "network/networkMgr.h"
#include "interface.h"
#include "tcpiphead.h"
#include <memory.h>
#include <atomic>

struct LeveParam
{
    void *param;
    void *base;
    int  leve;
    bool topLeve;
};




struct LinkParam
{
    CLinkPeer   *link;
    CNetworkMgr *linkMgr;
    void        *route;
    int         total;
    LeveParam   leve[10];
    std::atomic<int> m_ref;
    Interface   *interFace;
    std::unordered_set<uint64_t> macList;
    int         linkType;
    LinkParam()
    {
        addRef();
        link    = NULL;
        linkMgr = NULL;
        route   = NULL;
        total   = 0;
        memset(leve, 0, sizeof(leve));
        interFace = NULL;
    }
    int addRef();
    int delRef();
};

class CNetModeBase
{

public:
    CNetModeBase();
    virtual ~CNetModeBase();
    virtual bool init();
public:
    virtual int32_t processFromDown(CByteStream::CBufferItem* pItem, int leve) = 0;
    virtual int32_t processFromUP(CByteStream::CBufferItem* pItem, int leve)   = 0;
    virtual int32_t processFromDown(LinkParam *param, int leve, uint8_t *data, int len) = 0;
    virtual int32_t processFromUP(LinkParam *param,   int leve, uint8_t *data, int len) = 0;
    
    virtual int32_t clean(void *param) = 0;
    virtual void    *getParam(int leve, void *param) = 0;
    virtual void     notifLinkeClose(void *param, int leve);
public:
    int sendToDown(CByteStream::CBufferItem* pItem, int leve);
    int sendToDown(LinkParam  *param, int leve, uint8_t *data, uint32_t len, uint8_t *append, int applen);
    int sendToUP(LinkParam    *param, int leve,  uint8_t *data, uint32_t len, uint8_t *append, int applen);
    int cleanLinke(LinkParam  *param);
public:
    uint32_t m_outPutLen;
    uint8_t  m_outLen;
};
