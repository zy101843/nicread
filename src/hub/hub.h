#pragma once 
#include "../common.h"
#include "../tcpiphead.h"
#include <unordered_map>
#include <unordered_set>


struct NetInfo
{
    IPANDPORT4ITEM    tuple;
    uint32_t          otherLen;
    compact_ip_hdr   *ipv4Head;
    compact_ipv6_hdr *ipv6Head;
    uint32_t          l3HeadLen;
    uint32_t          totalLen;
    uint32_t          ipv4Len;
    TCPHDR           *tcpHead;
    UDPHDR           *udpHead;
    uint16_t          l4headlLen;
    uint8_t           nextProtocol;
    bool              isV4Broadcast;
    bool              isV6Multicast;
    bool              isARP;
};

class Filter
{
public:
    Filter();
    virtual ~Filter();
public:
    virtual bool process(NetInfo *netinf, uint8_t *data, int len) = 0;
};


class FilterMac : public Filter
{
public:
    FilterMac();
    virtual ~FilterMac();
public:
    virtual bool process(NetInfo *netinf, uint8_t *data, int len);
public:
    void addMac(std::unordered_set<uint64_t> &set);
private:
    std::unordered_set<uint64_t>  m_macSet;
   
};


class mac_inter
{
public:
    mac_inter()
    {

    }
    mac_inter(uint8_t *src)
    {
        *((uint32_t*)(mac)) = *((uint32_t*)(src));
        *((uint16_t*)(mac + 4)) = *((uint16_t*)(src + 4));
    }
public:
    bool operator()(const mac_inter *s1, const mac_inter *s2) const
    {
        bool ret =  *((uint32_t*)(s1->mac)) == *((uint32_t*)(s2->mac)) &&
            *((uint16_t*)(s1->mac + 4)) == *((uint16_t*)(s2->mac + 4));
        return ret;
    }
    std::size_t operator()(const mac_inter *s) const 
    {
        std::size_t seed =0;
        std::hash<uint32_t> hasher;
        uint32_t a =  *((uint32_t*)(s->mac));
        uint32_t b =  *((uint16_t*)(s->mac+4));
        seed ^= hasher(a) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= hasher(b) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
    }
private:
    uint8_t mac[6];
public:
    void    *p;
};

class CHub
{
public:
    typedef std::unordered_set<mac_inter *, mac_inter, mac_inter> MACMAPPORT;
    typedef MACMAPPORT::iterator                 MACMAPITER;
    typedef std::unordered_set<void*>            PORTSET;
public:
    CHub();
    ~CHub();
public:
    void setfilter(Filter *f) { m_filter =f; }
public:
    int addData(uint8_t *data, int len, void *param);
    int sendToAllPort(uint8_t *data, int len, void *param);
    int cleanLink(void *param);
    int updateMac(uint8_t *data, void *param);
private:
    //int   updateMac(uint8_t *data, void *param);
    void *findPort(uint8_t *data);
    void  justAddPort(void *param);
private:
    int  analysisIPHead(uint8_t *data, int len, NetInfo *netInfo);
    int  analysisL4Head(NetInfo *netInfo, uint8_t *data, int len);

    int  icmp6PacketTooBig(NetInfo *netInfo, uint8_t *recData, uint8_t *sendData);
    int  icmpPacketTooBig(NetInfo *netInfo, uint8_t *recData, uint8_t *sendData);
    void AdjustIPHeadV4(NetInfo *netInfo, uint8_t *data);
  

    void AdjustUPDCheckSumV4(NetInfo *netInfo, uint8_t *data, int len);
    void AdjustTcpCheckSumV4(NetInfo *netInfo, uint8_t *data, int len);
    void AdjustUPDCheckSumV6(NetInfo *netInfo, uint8_t *data, int len);
    void AdjustTcpCheckSumV6(NetInfo *netInfo, uint8_t *data, int len);
private:
    int  findMSS(NetInfo *netInfo, uint8_t *data);
    int  tcpFragmentation(void *dstParam, NetInfo *netInfo, uint8_t *data, int len, void *param);
    int  sendData(void *dstParam, NetInfo *netInfo, uint8_t *data, int len, void *param);
private:
    MACMAPPORT             m_macMap;
    PORTSET                m_portSet;
    std::mutex             m_critical;
    Filter                 *m_filter;
};

