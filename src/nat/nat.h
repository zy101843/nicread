#pragma once
#include <stdint.h>
#include <time.h>
#include <queue>
#include "../interface.h"
#include "../NetModeBase.h"
#include "../stdhashtimeout.h"
#include "../niread/readnic.h"
#include <thread>
#include <mutex>
#include <unordered_set>
#include "nat_up_checksum.h"

class portNatInfo
{
public:
    std::size_t operator()(const portNatInfo *t) const
    {
        return t->natPort;
    }
    bool operator()(const portNatInfo *t1, const portNatInfo *t2) const
    {
        return (t1->natPort == t2->natPort);
    }
public:
    uint16_t natPort;
    uint32_t gwIp;
    uint32_t internalIp;
    uint16_t internalPort;
    uint32_t externalIp;
    uint16_t externalPort;
    uint16_t protocol; // 17 udp 6 tcp
    time_t   lastTime;
    uint8_t  srcMac[6];
};


class innerHash
{
public:
    std::size_t operator()(const portNatInfo *t) const
    {
        std::hash<uint16_t> h;
        std::hash<uint32_t> h1;
        std::size_t size = h(t->internalPort);
        size ^= h1(t->internalIp) + 0x9e3779b9 + (size << 6) + (size >> 2);
        return size;
    }
    bool operator()(const portNatInfo *t1, const portNatInfo *t2) const
    {
        return (t1->internalPort == t2->internalPort) && (t1->internalIp == t2->internalIp) ;
    }
};


class Nat :public Interface , public midInterface
{
public:
    typedef CHashTOContainerSTD<portNatInfo *, portNatInfo, portNatInfo> NatPortMap;
    typedef std::unordered_set<portNatInfo *, innerHash, innerHash>     INNERMAP;
    typedef INNERMAP::iterator INNERITER;
    typedef std::queue<uint16_t> PORTQUEUE;
public:
    Nat();
    virtual ~Nat();
public:
    virtual int writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam);
    virtual int reg(int len, void *param);
    virtual int addData(uint8_t *data, int len, void *param);
    virtual int addData(HubMidBuf *buf, void *param);
    virtual HubMidBuf *getMidBuf();
    virtual void  returnMidBuf(HubMidBuf *buf);
public:
    void start();
    void workThread();
public:
    uint16_t getFreePort(uint16_t portType, std::size_t &freeCount);
    void     addFreePort(uint16_t port, uint16_t portType);
    void     *freeNatPort(portNatInfo *info, time_t curTime);
    int      updateCheckSum(uint8_t *iphead, uint8_t *outherHea, int type, int dir, uint32_t new_ip, uint16_t new_port);
private:
    uint8_t *process(uint8_t *data, int dir, int &len,  bool &arp);
    int      readConf();
    void     icmpV4(uint8_t *data, int len);
    void     arpV4(uint8_t *data, int len);
private:
    uint32_t m_gwIp;
    uint32_t m_netMask;
    uint32_t m_outip;
    uint8_t  m_macNa[6];
    uint8_t  m_macGw[6];
    upCheckSum m_updateCheckSum;
    std::string m_nicName;

    uint32_t m_gwIpHost;
    uint32_t m_netMaskHost;
    uint32_t m_TCPTimeout;
    uint32_t m_UDPTimeout;
private:
    NatPortMap  m_natTcpMap;
    INNERMAP    m_innerTCPMap;

    NatPortMap  m_natUDPMap;
    INNERMAP    m_innerUDPMap;

    PORTQUEUE   m_portTcpFree;
    PORTQUEUE   m_portUdpFree;
    portNatInfo m_tempInfo;
    std::mutex  m_critical;

private:
    LinkParam m_linkParm;
private:
    std::thread *m_monitorTread;
    nic_proc    *m_nic;
    bool         m_stop;
private:
    uint8_t     *m_sendData;
    NetInfo      m_nicnetInfo;
    NetInfo      m_netnetInfo;
};
