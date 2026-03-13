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
        m_NotStatic = false;
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
    uint8_t *getMac()
    {
        return mac;
    }
private:
    uint8_t mac[6];
public:
    void    *p;
    std::time_t                      lastTime;
    std::list<mac_inter *>::iterator m_ListIter;
    bool                             m_NotStatic;
};


class IdMapPort
{
public:
    typedef std::vector<void *>   IDMAPLIST;
    typedef IDMAPLIST::iterator IDMAPITER;
    typedef void* (IdMapPort::*getone)();
    typedef void* (IdMapPort::*getoneByHash)(std::size_t size);
public:
    IdMapPort()
    {
        m_id         = 0;
        m_size       = 0;
        m_fristCount = 0;
        m_fristFunc  = &IdMapPort::frist;
        m_moreFun    = &IdMapPort::getItemOne;
    }
    ~IdMapPort()
    {
        printf("del id port %d HUB.h::%s %d\n", m_id, __FUNCTION__, __LINE__);
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
        IDMAPITER end  = m_portList.end();
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
        if(m_size >1)
        {
            m_fristFunc = &IdMapPort::getBySeq;
            m_moreFun   = &IdMapPort::getItemMore;
        }
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
                if(m_size <=1)
                {
                    m_fristFunc = &IdMapPort::frist;
                    m_moreFun   = &IdMapPort::getItemOne;
                }
                return 1;
            }
        }
        return 0;
    } 

    void *frist()
    {
        return m_portList[0];
    }
    void *getBySeq()
    {
        void *ret = m_portList[m_fristCount];
        m_fristCount++; 
        if(m_fristCount >=m_size)
        {
           m_fristCount = 0; 
        }
        return ret;
    }

    void* getFrist()
    {
        return (this->*m_fristFunc)();
    }

    void *getItemOne(std::size_t )
    {
        return m_portList[0];
    }
    void *getItemMore(std::size_t size)
    {
        size = size % m_size;
        return m_portList[size];
    }

    void *getItem(std::size_t size)
    {
        return (this->*m_moreFun)(size);
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
    getone       m_fristFunc;
    getoneByHash m_moreFun;   
};

class CHub : public midInterface
{
public:
    typedef std::unordered_set<mac_inter *, mac_inter, mac_inter> MACMAPPORT;
    typedef MACMAPPORT::iterator                 MACMAPITER;
    typedef std::list<mac_inter *>               MACMAPLIST;
    typedef MACMAPLIST::iterator                 MACMAPLISTITER;    
    typedef std::unordered_set<void*>            PORTSET;
    typedef std::unordered_set<IdMapPort *, IdMapPort, IdMapPort> IDMAPPORT;
    typedef int (CHub::*porcFun)(uint8_t *data, int len, void *param);
public:
    CHub();
    ~CHub();
public:
    void setfilter(Filter *f) { m_filter =f; }
    void setVnicNat(uint32_t, uint32_t);
    void setDropMac(std::vector<uint8_t *> *drop);
    void start();
public:
    virtual int reg(int len, void *param);
    virtual int addData(uint8_t *data, int len, void *param);
    virtual int addData(HubMidBuf *buf, void *param);
    virtual HubMidBuf *getMidBuf();
    virtual void  returnMidBuf(HubMidBuf *buf);

    int porcData(uint8_t *data, int len, void *param);
    int procLink(uint8_t *data, int len, void *param);
    int sendToAllPort(uint8_t *data, int len, void *param);

private:
    int   updateMac(uint8_t *data, void *param);
    int   updateMac(uint8_t *data, void *param, bool staticMac);
    void *findPort(uint8_t *data, std::size_t  hashCode);
    void  justAddPort(void *param);
    int   cleanLink(void *param);
    int   postData(HubMidBuf *buf);
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
    int  cleanMac(void *param);
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
    MACMAPLIST             m_macList;
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
    std::thread    *m_monitorTread;
    sem_t           m_sem;
    pthread_mutex_t m_mutex;
    pthread_mutex_t m_mutexBuf;
private:
    std::queue<HubMidBuf *> m_listBuf;
    std::stack<HubMidBuf *> m_freeList;
    int                     m_PackCount;
    IdMapPort               m_tmpIdMap;
    std::time_t             m_curTime;
    porcFun                 m_processData[2];
};

