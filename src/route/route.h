#pragma once
#include <stdint.h>
#include "../interface.h"
#include "../NetModeBase.h"
#include "routetable.h"
#include "arpMap.h"

struct ipMap
{
    IPTYPE   ip;
    uint8_t  mac[6];
};  

class Route :public Interface
{
public:
    Route();
    ~Route();

public:
    int readCof();
    int start();

public:
    virtual int writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam);
private:
    void icmpV4(uint8_t *data, int len);
    void arpV4(uint8_t *data, int len);

public:
    LinkParam   m_linkParm;
    std::vector<ipMap *> m_gwList;
    routetable *m_routeTable;
    CArpMap    *m_arpMap;
    uint32_t    m_Ip;
    uint32_t    m_IpHost;
    uint32_t    m_IpHostMask;

    uint32_t m_Mask;
    uint32_t m_MaskHost;

    uint8_t   m_mac[6];
    uint8_t   m_defaultMac[6];
    uint32_t  m_defaultGWIP;
    NetInfo   m_netnetInfo;
    uint8_t   *m_sendData;
    uint32_t  m_count;
        
};
