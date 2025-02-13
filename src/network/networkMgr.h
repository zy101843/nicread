#pragma once 
#include "ByteStream.h"
#include "linkpeer.h"
#include "epollMgr.h"
#include <unordered_set>
#include <list>
#include <unordered_map>
#include <thread>
#include <arpa/inet.h>
#include "ByteBufMgn.h"

class CNetworkCallBack
{
public:
    virtual ~CNetworkCallBack() {}
    virtual bool operator()(void *link) = 0;
};

struct ADDNETPort
{
    uint32_t    ip;
    uint16_t    port;
    int         type;
    void        *dist;
    int          linkType;
    std::time_t lastTime;
};

class CNetworkMgr
{
public:
    CNetworkMgr();
    virtual ~CNetworkMgr();
public:
    void start();
    void stop();
    void *addListen(const char *ip, uint16_t port);
    void *addUdpRec(const char *ip, uint16_t port);
    void *addConnect(ADDNETPort *item);
    void *addConnect(const char *ip, uint16_t port, int type, void *dist);
    void *addConnect(uint32_t ip, uint16_t port, int type, void *dist);
    void *addUDPConnect(ADDNETPort *item);
    void *addUDPConnect(const char *ip, uint16_t port, int type, void *dist);
    void *addUDPConnect(uint32_t ip, uint16_t port, int type, void *dist);
    int  sendData(CLinkPeer *linkPeer, uint8_t *data, uint32_t len, uint8_t *append=NULL, int applen=0);
    int  sendData(void *fd, uint8_t *data, uint32_t len, uint8_t *append=NULL, int applen=0);
    int  sendData(CLinkPeer *linkPeer, CByteStream::CBufferItem* item, bool app);
    int  decRefLink(CLinkPeer *linkPeer);
    void setCallBack(void *callBack);
    void setRouteMessage(void *route);
    int  clean(CLinkPeer *linkPeer, int type);
private:
    void MonitorThread();
    void TimeOutThread();
    int  readData(CLinkPeer *linkPeer);
    int  sendData(CLinkPeer *linkPeer, CByteStream::CBufferItem* item);
    int  sendUDPData(CLinkPeer *linkPeer, CByteStream::CBufferItem* item);
    int  sendDataInter(CLinkPeer *linkPeer);
    int  handSendData(CLinkPeer *linkPeer);
    int  handAccep(CLinkPeer *linkPeer);
    int  handConnect(CLinkPeer *linkPeer);
    int  readUdpData(CLinkPeer *linkPeer);
    int  readUdpClinet(CLinkPeer *linkPeer);

    int  handEPOLLRDHUP(CLinkPeer *linkPeer, int type=1, bool istimeOut = false);
    int  cleanLineBuf(CLinkPeer *linkPeer);
    int  handErr(CLinkPeer *linkPeer);
    bool SetNonBlocking(int sockfd);
    void upTimeLink(CLinkPeer *linkPeer);
    int  delTimeLink(CLinkPeer *linkPeer);
public:
    typedef std::unordered_set<int>          INTSET;
    typedef INTSET::iterator                 INTSETITER;
    typedef std::unordered_set<CLinkPeer*>   CLINENTLIST;
    typedef std::list<CLinkPeer *>           CLINETIMELIST;
    typedef CLINENTLIST::iterator            CLINENTLISTITER;
    typedef std::unordered_map<std::size_t, CLinkPeer*> CUDPCLIENT;
    typedef std::list<void *>                LISTVOID;

    int     m_links;
private:
    ByteBufMgn       *m_BufMgn;
    CEpollMgr         m_epoll;
    bool              m_stop;
    void              *m_distri;

    INTSET            m_listenfd;
    INTSETITER        m_end;
    std::thread       *m_monitorTread;
    std::thread       *m_monitorTimeOut;
    std::mutex        m_CriticalUdp;
    std::mutex        m_CriticalLink;
    std::mutex        m_CriticalEpoll;
    CLINENTLIST       m_client;
    CUDPCLIENT        m_udpClinet;
    CLINETIMELIST     m_timeOut;
    CNetworkCallBack *m_callBack;
    LISTVOID          m_addConnect;
};