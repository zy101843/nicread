#pragma once 
#include "../NetModeBase.h"
#include "portLink.h"

class CNetLink : public CNetModeBase
{
public:

public:
    CNetLink();
    virtual ~CNetLink();
    virtual bool init();
public:
    virtual int32_t processFromDown(CByteStream::CBufferItem* pItem, int leve);
    virtual int32_t processFromUP(CByteStream::CBufferItem* pItem, int leve);
    virtual int32_t processFromDown(LinkParam *param, int leve, uint8_t *data, int len);
    virtual int32_t processFromUP(LinkParam *param, int leve, uint8_t *data, int len);
    virtual int32_t clean(void *param);
    virtual void    *getParam(int leve, void *param);
    virtual void     notifLinkeClose(void *param, int leve);
private:
    void *m_netHub;

};
