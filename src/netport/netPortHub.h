#pragma once
#include "../common.h"
#include <stdint.h>
#include "netPort.h"
#include "../NetModeBase.h"
#include <thread>
#include <unordered_map>
#include <unordered_set>


class CNetPortHub :public Interface
{
public:
    typedef std::unordered_map<uint64_t, void *> MACMAPLINK;
    typedef MACMAPLINK::iterator                 MACMAPITER;
    typedef std::unordered_map<void*, std::unordered_set<uint64_t>*> LINKMAC;
public:
    CNetPortHub();
   virtual ~CNetPortHub();
public:
    int32_t processFromNet(LinkParam *param, int leve, uint8_t *data, int len);
public:
   virtual int writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam);
public:
    int cleanLink(void *param);
public:
    static CNetPortHub *getItem();
private:
    int  sendToLink(void *port, uint8_t *data, int len);
private:
    CNetPort    *m_netPort;
    MACMAPLINK  *m_mapLink;
    LINKMAC     *m_linkMac;
private:
    std::mutex        m_critical;

};
