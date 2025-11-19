#pragma once 
#include "../common.h"
#include "../tcpiphead.h"
#include "../interface.h"
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <semaphore.h>
#include <queue> 
#include <stack>
#include <list>


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
        *((uint32_t*)(mac))     = *((uint32_t*)(src));
        *((uint16_t*)(mac + 4)) = *((uint16_t*)(src + 4));
    }
public:
    bool operator()(const mac_inter *s1, const mac_inter *s2) const
    {
        bool ret =  *((uint32_t*)(s1->mac)) == *((uint32_t*)(s2->mac)) &&
            *((uint16_t*)(s1->mac + 4))     == *((uint16_t*)(s2->mac + 4));
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





struct HubMidBuf
{
    void   *param;
    int     type;
    int     len ;
    uint8_t buf[1600];  
};

class IdMapPort
{
public:
    typedef std::vector<void *>   IDMAPLIST;
    typedef IDMAPLIST::iterator IDMAPITER;
public:
    IdMapPort()
    {
        m_id         = 0;
        m_size       = 0;
        m_fristCount = 0;
    }

public:
    bool operator()(const IdMapPort *s1, const IdMapPort *s2) const
    {
        bool ret = s1->m_id == s2->m_id;
        return ret;
    }
    std::size_t operator()(const IdMapPort *s) const
    {
        std::size_t seed = s->m_id;
        seed ^=  0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
    }
public:
    bool find(void *param)
    {
        IDMAPITER iter = m_portList.begin();
        IDMAPITER end = m_portList.end();
        for (; iter != end; ++iter)
        {
            if (*iter == param)
            {
                return true;
            }
        }
        return false;
    }
    bool addPort(void *param)
    {
        m_portList.push_back(param);
        m_size++;
        return true;
    }
    int  delPort(void *param)
    {
        IDMAPITER iter = m_portList.begin();
        IDMAPITER end = m_portList.end();
        for (; iter != end; ++iter)
        {
            if (*iter == param)
            {
                m_portList.erase(iter);
                m_size--;
                return 1;
            }
        }
        return 0;
    } 
    void* getFrist()
    {
        void *ret = m_portList[m_fristCount];
        m_fristCount = (m_fristCount +1)%m_size;
        return ret;

    } 
    void* getItem(std::size_t size)
    {
        if(size == 0)
        {
            return getFrist();
        }
        size = size%m_size;
        return m_portList[size];
    } 
    bool isEmpty()
    {
        return m_size == 0;
    } 
public:
    IDMAPLIST    m_portList;
    uint32_t     m_id;
    std::size_t  m_size;
    uint32_t     m_fristCount; 
};

class CHub : public midInterface
{
public:
    typedef std::unordered_set<mac_inter *, mac_inter, mac_inter> MACMAPPORT;
    typedef MACMAPPORT::iterator                 MACMAPITER;
    typedef std::unordered_set<void*>            PORTSET;
    typedef std::unordered_set<IdMapPort *, IdMapPort, IdMapPort> IDMAPPORT;
public:
    CHub();
    ~CHub();
public:
    void setfilter(Filter *f) { m_filter =f; }
    void setVnicNat(uint32_t, uint32_t);
    void setDropMac(std::vector<uint8_t *> *drop);
    void start();
public:
    virtual int addData(uint8_t *data, int len, void *param);
    int addData1(uint8_t *data, int len, void *param);
    int sendToAllPort(uint8_t *data, int len, void *param);

private:
    int   updateMac(uint8_t *data, void *param);
    //void *findPort(uint8_t *data);
    void *findPort(uint8_t *data, std::size_t  hashCode);
    void  justAddPort(void *param);
    int   cleanLink(void *param);
private:

    int  icmp6PacketTooBig(NetInfo *netInfo, uint8_t *recData, uint8_t *sendData);
    int  icmpPacketTooBig(NetInfo *netInfo, uint8_t *recData, uint8_t *sendData);
  

    void AdjustUPDCheckSumV4(NetInfo *netInfo, uint8_t *data, int len);
    void AdjustTcpCheckSumV4(NetInfo *netInfo, uint8_t *data, int len);
    void AdjustUPDCheckSumV6(NetInfo *netInfo, uint8_t *data, int len);
    void AdjustTcpCheckSumV6(NetInfo *netInfo, uint8_t *data, int len);
private:
    int  findMSS(NetInfo *netInfo, uint8_t *data);
    int  tcpFragmentation(void *dstParam, NetInfo *netInfo, uint8_t *data, int len, void *param);
    int  sendData(void *dstParam, NetInfo *netInfo, uint8_t *data, int len, void *param);
public:
    void workThread();
private:
    int  initData();
    int  sendArp(uint8_t *data,  int len, void *param, NetInfo *netinfo);
private:
    int  addIDPort(void *param);
    int  rmIDPort(void *param);
    IdMapPort *findIDPort(void *param);
    void *getOneLikelyPort(void *param, std::size_t size);
private:
    MACMAPPORT             m_macMap;
    PORTSET                m_portSet;
    IDMAPPORT              m_idMap; 
    std::mutex             m_critical;
    Filter                 *m_filter;
    uint32_t                m_vip;
    uint32_t                m_vmask;
    bool                    m_haveVirNic;
    uint8_t                 *m_aut;
    std::size_t             m_dropLen;
    std::vector<uint8_t *>  *m_dropVec;
private:
    std::thread     *m_monitorTread;
    sem_t           m_sem;
    pthread_mutex_t m_mutex;
    pthread_mutex_t m_mutexBuf;
private:
    std::queue<HubMidBuf *> m_listBuf;
    std::stack<HubMidBuf *> m_freeList;
    int                     m_PackCount;
    IdMapPort               m_tmpIdMap;
};

