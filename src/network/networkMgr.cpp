#include "networkMgr.h"
//#include "distributionToThr.h"
#include <unistd.h>
#include <cstring>
#include <netinet/tcp.h>
#include <functional>
#include <iostream>
#include "../common.h"
#include "../tcpiphead.h"
//#include "log.h"


CNetworkMgr::CNetworkMgr()//: m_ByteStrem(1000, 64*1024)
{
    m_epoll.init();
    m_stop     = true;
    m_callBack = NULL;
    m_links    = 0;
    m_BufMgn   = ByteBufMgn::getByteBufMgn(); 
}

CNetworkMgr::~CNetworkMgr()
{

}
void CNetworkMgr::start()
{
    m_monitorTread   = new std::thread(std::bind(&CNetworkMgr::MonitorThread, this));
    m_monitorTimeOut = new std::thread(std::bind(&CNetworkMgr::TimeOutThread, this));
}
void CNetworkMgr::stop()
{
    m_stop = false;
}
bool CNetworkMgr::SetNonBlocking(int sockfd)
{
    int opts = fcntl(sockfd, F_GETFL);
    if (opts < 0)
    {
        return false;
    }

    opts = (opts | O_NONBLOCK);
    if (fcntl(sockfd, F_SETFL, opts) < 0)
    {
        return false;
    }
    return true;
}
void CNetworkMgr::setCallBack(void *callBack)
{
    m_callBack = (CNetworkCallBack*)callBack;
}

void CNetworkMgr::setRouteMessage(void *route)
{
    m_distri = route;
}

void *CNetworkMgr::addListen(const char *ip, uint16_t port)
{
    int  listenfd;
    struct sockaddr_in servaddr;
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ip);
    servaddr.sin_port        = htons(port);

    int reeuseport_On = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &reeuseport_On, sizeof(reeuseport_On)) < 0)
    {
        printf("setsockopt error: errno=%d, errorinfo:%s. \n", errno, strerror(errno));
        return NULL;
    }
    bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    listen(listenfd, 20);
    if (!SetNonBlocking(listenfd))
    {
        printf( "SetNonBlocking error listenfd.\n");
        return NULL;
    }
    uint32_t  flag  = EPOLLIN;
    CLinkPeer *peer = new CLinkPeer();
    peer->setMessageRoute(m_distri);
    m_links++;
   
    peer->m_fd         = listenfd;
    peer->m_linkType   = IP_TCP_TYPE;
    m_epoll.addEnv(flag, listenfd, peer);
    peer->m_peerTyep    = PEERTYPE_LINST;
    peer->m_ipaddr.ipv4 = servaddr.sin_addr.s_addr;
    m_listenfd.insert(listenfd);

    return peer;
}
void *CNetworkMgr::addConnect(ADDNETPort *item)
{
    return addConnect(item->ip, item->port, item->type, item->dist);
}

void *CNetworkMgr::addConnect(const char *ip, uint16_t port,  int type, void *dist)
{
    uint32_t addr = inet_addr(ip);
    uint16_t nport =  htons(port);
    return addConnect(addr,  nport, type, dist);
}

void *CNetworkMgr::addConnect(uint32_t ip, uint16_t port, int type, void *dist)
{
     struct sockaddr_in servaddr;
    int sock_cli        = socket(AF_INET, SOCK_STREAM, 0);
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ip;
    servaddr.sin_port        = port;

    if (!SetNonBlocking(sock_cli))
    {
        printf("SetNonBlocking error listenfd.\n");
        return NULL;
    }
    
    int syncnt = 3;
    setsockopt(sock_cli, IPPROTO_TCP, TCP_SYNCNT, &syncnt, sizeof(syncnt));
    connect(sock_cli, (struct sockaddr *) & servaddr, sizeof(servaddr));
    CLinkPeer *peer = new CLinkPeer();
    peer->setMessageRoute(m_distri);
    m_links++;

    uint32_t  flag      = EPOLLOUT | EPOLLRDHUP;
    peer->m_linkType    = IP_TCP_TYPE;
    peer->m_fd          = sock_cli;
    peer->m_step        = PEERSTEP::PEERSTEP_CONECT;
    peer->m_peerTyep    = PEERTYPE_CLIENT;
    peer->m_ipaddr.ipv4 = ip;
    peer->m_port        = port;
    peer->m_proto       = type;
    peer->setMessageRoute(dist);
    peer->addRef();


    m_CriticalEpoll.lock();
    m_epoll.addEnv(flag, sock_cli, peer);
    m_CriticalEpoll.unlock();

    return peer;
}


void *CNetworkMgr::addUDPConnect(ADDNETPort *item)
{
    return addUDPConnect(item->ip, item->port, item->type, item->dist);
}

void *CNetworkMgr::addUDPConnect(const char *ip, uint16_t port, int type, void *dist)
{
    uint32_t addr  = inet_addr(ip);
    uint16_t nport =  htons(port);
    return addUDPConnect(addr, nport, type, dist);
}

static uint8_t databuf_UDP_frist[] ={ 
0x3c,0x00,0x66,0xa4,0x64,0xa5,0x9a,0x5b,0x65,0xa4,0xce,0xf9,0xdc,0xe8,0xa3,0xae,
0x90,0x5f,0x60,0xa0,0x97,0x5e,0x67,0xa4,0x9e,0x5e,0xca,0xfd,0xd8,0xec,0xa7,0xaa,
0x5c,0xf5,0x08,0x8c,0x93,0x52,0x6d,0xac,0x92,0x53,0xae,0x07,0xf5,0xb9,0x6f,0xae,
0x90,0x51,0x68,0xa9,0x97,0x56,0x69,0xa8,0x96,0x57,0x6a,0xab,0x95,0x54,0x6b,0xaa,

};

void *CNetworkMgr::addUDPConnect(uint32_t ip, uint16_t port, int type, void *dist)
{
    int sock_cli        = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  
    CLinkPeer *peer = new CLinkPeer();
    peer->setMessageRoute(m_distri);
    m_links++;

 
    peer->m_linkType    = IP_UDP_TYPE;
    peer->m_fd          = sock_cli;
    peer->m_step        = PEERSTEP::PEERSTEP_CONECT;
    peer->m_peerTyep    = PEERTYPE_UDPCLINENT;
    peer->m_ipaddr.ipv4 = ip;
    peer->m_port        = port;
    peer->m_proto       = type;
    peer->setMessageRoute(dist);
    peer->addRef();
    upTimeLink(peer);
;
    struct sockaddr_in  servaddr ={ 0 };
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ip;
    servaddr.sin_port        = port;

    sendto(sock_cli, databuf_UDP_frist, 64, MSG_DONTWAIT, (struct sockaddr *) & servaddr, sizeof(servaddr));
    uint32_t  flag      = EPOLLIN | EPOLLRDHUP;
    m_CriticalEpoll.lock();
    m_epoll.addEnv(flag, sock_cli, peer);
    m_CriticalEpoll.unlock();

    return peer;
}

void *CNetworkMgr::addUdpRec(const char *ip, uint16_t port)
{
    
    int server_fd;
    int ret;
    struct sockaddr_in ser_addr;

    server_fd = socket(AF_INET, SOCK_DGRAM, 0); //AF_INET:IPV4;SOCK_DGRAM:UDP
    if (server_fd < 0)
    {
        printf("create socket fail!\n");
        return NULL;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = inet_addr(ip);
    ser_addr.sin_port        = htons(port); 

    int reeuseport_On = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reeuseport_On, sizeof(reeuseport_On)) < 0)
    {
        printf("setsockopt error: errno=%d, errorinfo:%s. \n", errno, strerror(errno));
        return NULL;
    }
    ret = bind(server_fd, (struct sockaddr*) & ser_addr, sizeof(ser_addr));
    if (ret < 0)
    {
        printf("socket bind fail!\n");
        return NULL;
    }
    if (!SetNonBlocking(server_fd))
    {
        printf("SetNonBlocking error listenfd.\n");
        return NULL;
    }
  
    uint32_t  flag   = EPOLLIN | EPOLLRDHUP; /*|EPOLLOUT|EPOLLRDHUP | EPOLLONESHOT*/;
    CLinkPeer *peer  = new CLinkPeer();
    peer->setMessageRoute(m_distri);
    m_links++;
    peer->m_linkType    = IP_UDP_TYPE;
    peer->m_fd          = server_fd;
    peer->m_peerTyep    = PEERTYPE_UDPSERVERLIS;
    peer->m_ipaddr.ipv4 = ser_addr.sin_addr.s_addr;
    peer->m_port        = htons(ser_addr.sin_port);
    peer->setConnect(true);
    peer->addRef();

    m_CriticalEpoll.lock();
    m_epoll.addEnv(flag, server_fd, peer);
    m_CriticalEpoll.unlock();

    return peer;

}

void CNetworkMgr::TimeOutThread()
{
   
    CLINETIMELIST::iterator begin;  
    CLINETIMELIST::iterator end; 
    CLINENTLISTITER         setIter;
    CLinkPeer *item;
    int count = 0;
    int countclint = 0;

    LISTVOID::iterator conniter;
    LISTVOID::iterator connEnd;
    ADDNETPort *addConn;

    std::vector<ADDNETPort *>  udpClinetList;
    std::vector<CLinkPeer *>   linkTime;
    while (m_stop)
    {
        std::time_t times=time(NULL);
        m_CriticalLink.lock();
        if (m_timeOut.size() > 0)
        {
            begin = m_timeOut.begin();
            end   = m_timeOut.end();
            for (; begin != end; begin++)
            {
                item = *begin;
                if ((times - item->m_lastTime) < 60)
                {
                    break;
                }
                count++;
                setIter = m_client.find(item);
                if (setIter != m_client.end())
                {
                    m_client.erase(setIter);
                    linkTime.push_back(item);
                }
                else
                {
                    printf("link mem error %s \n ", __FUNCTION__);
                }
            }
            if (count > 0)
            {
                m_timeOut.erase(m_timeOut.begin(), begin);
            }
        }

        countclint = 0;
        if (m_addConnect.size() > 0)
        {
            conniter = m_addConnect.begin();
            connEnd  = m_addConnect.end();

            for (; conniter != connEnd; conniter++)
            {
                addConn = (ADDNETPort *)*conniter;
                if ((times - addConn->lastTime) < 10)
                {
                    break;
                }
                countclint++;
                udpClinetList.push_back(addConn);
            }

            if (countclint > 0)
            {
                m_addConnect.erase(m_addConnect.begin(), conniter);
            }
        }
        m_CriticalLink.unlock();

        if (count > 0)
        {
            std::vector<CLinkPeer *>::iterator  iter = linkTime.begin();
            std::vector<CLinkPeer *>::iterator  end =  linkTime.end();
            for (; iter != end; iter++)
            {
                handEPOLLRDHUP(*iter, 1, true);
            }
            linkTime.clear();
            count = 0;
        }
        
        if (countclint > 0)
        {
            std::vector<ADDNETPort *>::iterator  iter = udpClinetList.begin();
            std::vector<ADDNETPort *>::iterator  end =  udpClinetList.end();
            for (; iter != end; iter++)
            {
                addConn = (ADDNETPort *)*iter;
                if (IP_TCP_TYPE == addConn->linkType)
                {
                    addConnect(addConn);
                }
                else if (IP_UDP_TYPE == addConn->linkType)
                {
                    addUDPConnect(addConn);
                }
                delete addConn;
            }
            udpClinetList.clear();
            countclint = 0;
        }

        sleep(5);
    }
   
}

void CNetworkMgr::MonitorThread()
{
    epoll_event *env;
    int  ret;
    while (m_stop)
    {
        int get = m_epoll.getEnv(env, 10);
        for (int i = 0; i < get; i++)
        {
            int fd = env[i].data.fd;
            CLinkPeer *fdper = (CLinkPeer *)(env[i].data.ptr);
            if (EPOLLERR == (env[i].events & EPOLLERR))
            {
                ret = handErr(fdper);
                if (-2 == ret)
                {
                    continue;
                }
            }
            if (EPOLLOUT == (env[i].events & EPOLLOUT))
            {
                if (PEERTYPE_CLIENT == fdper->m_peerTyep)
                {
                    if (PEERSTEP::PEERSTEP_CONECT == fdper->m_step)
                    {
                        ret = handConnect(fdper);
                    }
                    else
                    {
                        ret = handSendData(fdper);
                    }
                }
                else
                {
                    ret = handSendData(fdper);
                }

            }
            if (EPOLLIN == (env[i].events & EPOLLIN))
            {
                if (PEERTYPE_LINST == fdper->m_peerTyep)
                {
                    handAccep(fdper);
                }
                else if(PEERTYPE_SERVICE == fdper->m_peerTyep)
                {
                    ret = readData(fdper);
                    if (ret < 0)
                    {
                        continue;
                    }
                }
                else if (PEERTYPE_CLIENT == fdper->m_peerTyep)
                {
                    ret = readData(fdper);
                    if (ret < 0)
                    {
                        continue;
                    }
                }
                else if (PEERTYPE_UDPSERVERLIS == fdper->m_peerTyep)
                {
                    readUdpData(fdper);
                }
                else if (PEERTYPE_UDPCLINENT == fdper->m_peerTyep)
                {
                    readUdpClinet(fdper);
                }
            }
            if (EPOLLRDHUP == (env[i].events & EPOLLRDHUP))
            {
                handEPOLLRDHUP(fdper);
                continue;
            }

        }
    }
}

int  CNetworkMgr::handAccep(CLinkPeer * linkPeer)
{
    sockaddr_in cliaddr;
    socklen_t   clilen = sizeof(cliaddr);
    int connfd = -1;
    while (-1 == connfd)
    {
        connfd = accept(linkPeer->m_fd, (struct sockaddr*) & cliaddr, &clilen);
        if (-1 == connfd)
        {
            //printf("accept error: errno=%d, errorinfo:%s. \n", errno, strerror(errno));
        }
    }
    if (!SetNonBlocking(connfd))
    {
        close(connfd);
        //printf("SetNonBlocking error accept.\n");
        return -1; 
    }
    
    uint32_t  flag      = EPOLLIN | EPOLLRDHUP; /*|EPOLLOUT|EPOLLRDHUP | EPOLLONESHOT*/;
    CLinkPeer *peer     = new CLinkPeer();
    peer->setMessageRoute(m_distri);
    m_links++;
    
    peer->m_fd          = connfd;
    peer->m_peerTyep    = PEERTYPE_SERVICE;
    peer->m_ipaddr.ipv4 = cliaddr.sin_addr.s_addr;
    peer->m_port        = htons(cliaddr.sin_port);
    peer->setConnect(true);
    peer->m_proto       = linkPeer->m_proto;
    peer->m_linkType    = IP_TCP_TYPE;
    peer->addRef();  

    uint8_t *pi = (uint8_t *)&(peer->m_ipaddr.ipv4);
    NOTICE("socket rec: " << (uint32_t)pi[0]<<","<< (uint32_t)pi[1]<<","<< (uint32_t)pi[2]<<"," << (uint32_t)pi[3] <<" port: "<< peer->m_port<< " new socket!");

    upTimeLink(peer);

    int ref = peer->regtoUp(this);
    m_CriticalEpoll.lock();
    m_epoll.addEnv(flag, connfd, peer);
    m_CriticalEpoll.unlock();
    return 1;

}

int CNetworkMgr::handConnect(CLinkPeer *linkPeer)
{
    bool connect= 0;
    linkPeer->lock();
    linkPeer->setConnect(true);
    linkPeer->m_step = PEERSTEP::PEERSTEP_NORMAL;
    linkPeer->unlock();

    uint8_t *pi = (uint8_t *) & (linkPeer->m_ipaddr.ipv4);
    NOTICE("socket connect success: " << (uint32_t)pi[0] << "," << (uint32_t)pi[1] << "," << (uint32_t)pi[2] << "," << (uint32_t)pi[3] << " port: " << linkPeer->m_port << " new socket!");
    uint32_t  flag   = EPOLLIN | EPOLLRDHUP;
    upTimeLink(linkPeer);
    
    int ref = linkPeer->regtoUp(this);


    m_CriticalEpoll.lock();
    m_epoll.modEnv(flag, linkPeer->m_fd, linkPeer);
    m_CriticalEpoll.unlock();
    return 1;
}

int CNetworkMgr::handErr(CLinkPeer *linkPeer)
{
    handEPOLLRDHUP(linkPeer ,2);
    return -2;
}
#define LINKMASKREF 100
int CNetworkMgr::readData(CLinkPeer *linkPeer)
{
    int ref =0;
    bool hans = false;
    CByteStream::CBufferItem *item;
    while (true)
    {

        int totalLen = 0;
        item = m_BufMgn->getBufItem();//getBufItem();
        int readLen = recv(linkPeer->m_fd, (char *)(item->m_pBuffer), 2048, MSG_DONTWAIT);
        if (readLen < 0)
        {
            if (errno == EINTR)
            {
                m_BufMgn->FreeBufItem(item);
            }
            else if (errno == EAGAIN)
            {
                m_BufMgn->FreeBufItem(item);
                return 0;
            }
            else
            {
                m_BufMgn->FreeBufItem(item);
                handEPOLLRDHUP(linkPeer);
                return (-2);
            }
        }
        else if (readLen == 0)
        {
            //FreeBufItem(item);
            m_BufMgn->FreeBufItem(item);
            handEPOLLRDHUP(linkPeer);
            return (-1);
        }
        if (readLen < 2048)
        {
            item->m_iPos    =  readLen;
            item->m_linkMgr = this; 
            item->m_fd      = linkPeer;
            item->addRef();
            linkPeer->lock();         
            ref  = linkPeer->prepare(item);
            linkPeer->unlock();
            uint8_t *pi = (uint8_t *) & (linkPeer->m_ipaddr.ipv4);
            /*
            if (ref > LINKMASKREF)
            {
                NOTICE("socket rec: " << (uint32_t)pi[0] << "," << (uint32_t)pi[1] << "," << (uint32_t)pi[2] << "," << (uint32_t)pi[3]
                    << " port: " << linkPeer->m_port << " len:" << readLen << "  ref: " << ref);
            }
            */
            if (0 == item->delRef())
            {
                m_BufMgn->FreeBufItem(item);
            }
            upTimeLink(linkPeer);
            return readLen;
        }
        else if (readLen == 2048)
        {
          
            item->m_iPos    =  readLen;
            item->m_linkMgr = this; 
            item->m_fd      = linkPeer;
            item->addRef();
            linkPeer->lock();
            ref  = linkPeer->prepare(item);
            /*if (ref > LINKMASKREF)
            {
                uint8_t *pi = (uint8_t *) & (linkPeer->m_ipaddr.ipv4);
                NOTICE("socket rec: " << (uint32_t)pi[0] << "," << (uint32_t)pi[1] << "," << (uint32_t)pi[2] << "," << (uint32_t)pi[3] 
                   << " port: " << linkPeer->m_port << " len:" << readLen << "  ref: " << ref);
            }
            */
            linkPeer->unlock();
            if (0 == item->delRef())
            {
                m_BufMgn->FreeBufItem(item);
            }
        }
    }
    return 0;
}

int  CNetworkMgr::decRefLink(CLinkPeer *linkPeer)
{
    int ret = linkPeer->delRef();
    if ( ret == 0)
    {
        cleanLineBuf(linkPeer);
        uint8_t *pi = (uint8_t *) & (linkPeer->m_ipaddr.ipv4);
        NOTICE("clean socket close type: "<<linkPeer->m_linkType<<" ip:"<< (uint32_t)pi[0] << "," << (uint32_t)pi[1] << "," << (uint32_t)pi[2] << "," << (uint32_t)pi[3] << " port: " << htons(linkPeer->m_port) <<"  function: " << __FUNCTION__);
        delete linkPeer;
        m_links--;
    }
    return ret;
}
int  CNetworkMgr::sendData(void* fd, uint8_t *data, uint32_t len,  uint8_t *append, int applen)
{
    CLinkPeer *linkPeer = (CLinkPeer *)fd;
    int senlen = sendData(linkPeer, data, len, append, applen);
    return senlen;
}

int CNetworkMgr::sendData(CLinkPeer *linkPeer, uint8_t *data, uint32_t len, uint8_t *append, int applen)
{
    bool isConnect =false;

    CLINENTLISTITER iter;
    m_CriticalLink.lock();
    iter = m_client.find(linkPeer);
    if (iter != m_client.end())
    {
        linkPeer->addRef();
    }
    else
    {
        m_CriticalLink.unlock();
        return -1;
    }
    m_CriticalLink.unlock();

    linkPeer->lock();
    isConnect = linkPeer->isConnect();
    linkPeer->unlock();

    if (false ==  isConnect)
    {  
        return -1;
    }

    CByteStream::CBufferItem* item = NULL;
    uint32_t total   = len + applen + 4;
    uint8_t *curPost = append;
    uint32_t leftlen = applen;
    uint8_t *head    = data;
    uint32_t headlen = len;
    uint32_t copyLen;
    
    while (true)
    {
        item = m_BufMgn->getBufItem();
        item->m_iPos = 0;
        uint8_t *post = item->m_pBuffer + item->m_iPos;
        std::size_t sizeleft = item->m_iBufferSize - item->m_iPos;
        if (headlen > 0)
        {
            copyLen = headlen > sizeleft ? sizeleft : headlen;
            memcpy(post, head, copyLen);
            head         += copyLen;
            item->m_iPos += copyLen;
            headlen      -= copyLen;
            sizeleft     -= copyLen;
            post         += copyLen;
            total        -= len;
        }
        if (leftlen > 0 && sizeleft>0)
        {
            copyLen = leftlen > sizeleft ? sizeleft : leftlen;
            memcpy(post, curPost, copyLen);
            curPost      += copyLen;
            item->m_iPos += copyLen;
            leftlen      -= copyLen;
            sizeleft     -= copyLen;
            post         += copyLen;
            total        -= len;
        }
        if ((0 == headlen) && (0 == leftlen))
        {
            item->m_last = 0;
        }

        item->addRef();
        int sendRet = -1;
        if (IP_UDP_TYPE == linkPeer->m_linkType)
        {
            sendRet = sendUDPData(linkPeer, item);
        }
        else
        {
            sendRet = sendData(linkPeer, item);
        }

        if(-1 == sendRet)
        {
            m_BufMgn->FreeBufItem(item);
            break;
        }

        if ((0 == headlen) && (0 == leftlen))
        {
            break;
        }
    }
    decRefLink(linkPeer);
    return 0;
}
int CNetworkMgr::sendData(CLinkPeer *linkPeer, CByteStream::CBufferItem *item, bool app)
{
    (void)app;
    CLINENTLISTITER iter;
    item->m_iOffset = 0;
    
    m_CriticalLink.lock();
    iter = m_client.find(linkPeer);
    if (iter != m_client.end())
    {
        linkPeer->addRef();
    }
    else
    {
        m_CriticalLink.unlock();
        return -1;
    }
    m_CriticalLink.unlock();

    int ret = -1;
    if (IP_TCP_TYPE == linkPeer->m_linkType)
    {
        ret = sendData(linkPeer, item);
    }
    else if(IP_UDP_TYPE == linkPeer->m_linkType)
    {
        ret = sendUDPData(linkPeer, item);
    }
    decRefLink(linkPeer);
    return ret;
}

int CNetworkMgr::sendData(CLinkPeer *linkPeer, CByteStream::CBufferItem *item)
{
    uint8_t *post = NULL;
    bool isConnet = false;

    linkPeer->lock();
    isConnet = linkPeer->isConnect();
    if (false == isConnet)
    {
        if (linkPeer->delRef() == 0)
        {
           linkPeer->unlock();
           cleanLineBuf(linkPeer);
           delete linkPeer; 
        }
        else
        {
            linkPeer->unlock();
        }
        return -1;
    }

    linkPeer->addItem(item);
    linkPeer->unlock();

    uint32_t flag = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
    m_CriticalEpoll.lock();
    m_epoll.modEnv(flag, linkPeer->m_fd, linkPeer);
    m_CriticalEpoll.unlock();
    return 1;
}

int CNetworkMgr::sendDataInter(CLinkPeer *linkPeer)
{
    CByteStream::CBufferItem *item = (CByteStream::CBufferItem*)(linkPeer->m_curSend);
    int totallen  = item->m_iPos - item->m_iOffset;
    uint8_t *post = item->m_pBuffer;
    int ret = -1;
    if (IP_TCP_TYPE == linkPeer->m_linkType)
    {
        ret = send(linkPeer->m_fd, post + item->m_iOffset, totallen, MSG_DONTWAIT);
    }
    else if (IP_UDP_TYPE == linkPeer->m_linkType)
    {
        IPTYPE ip;
        memcpy(&ip, item->m_ip, 16);
        struct sockaddr_in  addr ={ 0 };
        addr.sin_family = AF_INET;
        addr.sin_port = item->m_port;
        addr.sin_addr.s_addr =ip.ip.v4;
        ret = sendto(linkPeer->m_fd, post + item->m_iOffset, totallen, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
    }
    if (ret > 0)
    {
        item->m_iOffset += ret;
    }
    else if( -1 == ret)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        {
            ret = 0;
        }
        else
        {
            //CLogger::GetInstance()->WriteLog(2, "Connect error: %s", strerror(errno));
            //m_connet = false;
            //close(m_socketfd);
            //m_socketfd = -1;
            //ret = -1;
            handEPOLLRDHUP(linkPeer);
        }  
    }
    else
    {
        NOTICE("send error ");
    }
    return ret;
}
int CNetworkMgr::handSendData(CLinkPeer *linkPeer)
{
    CByteStream::CBufferItem* item      = NULL;
    CByteStream::CBufferItem* localitem = NULL;

    bool connect = false;
    bool send    = false;
    linkPeer->lock();
    connect = linkPeer->isConnect();
    item = (CByteStream::CBufferItem *)(linkPeer->m_curSend);
    if (NULL != item)
    {
        if (item->m_iOffset != item->m_iPos)
        {
            send = true;
            item = NULL;
        }
        else
        {
            localitem = linkPeer->getItem();
            if (NULL == localitem)
            {
                linkPeer->m_curSend = NULL;
                linkPeer->m_sending = false;
            }
            else
            {
                linkPeer->m_curSend = localitem;
                linkPeer->m_sending = true;
                send = true;
            }
        }
    }
    else
    {
        localitem = linkPeer->getItem();
        if (NULL == localitem)
        {
            linkPeer->m_curSend  = NULL;
            linkPeer->m_sending  = false;
        }
        else
        {
            linkPeer->m_curSend = localitem;
            linkPeer->m_sending = true;
            send                = true;
        }
    }
    if (send)
    {
        sendDataInter(linkPeer);
    }
    linkPeer->unlock();

    if (IP_TCP_TYPE == linkPeer->m_linkType)
    {
        upTimeLink(linkPeer);
    }

    if (false == send)
    {
        uint32_t  flag      = EPOLLIN;
        m_CriticalEpoll.lock();
        m_epoll.modEnv(flag, linkPeer->m_fd, linkPeer);
        m_CriticalEpoll.unlock();
    }
    
    if (NULL != item)
    {
        if (0 == item->delRef())
        {
            m_BufMgn->FreeBufItem(item);
        }
    }
    return 0;
}

int  CNetworkMgr::cleanLineBuf(CLinkPeer *linkPeer)
{
    std::vector<CByteStream::CBufferItem *> list;
    CByteStream::CBufferItem  *item = NULL;

    bool hava = false;
    int ret   = 0;
    item = (CByteStream::CBufferItem*)linkPeer->m_curSend;
    if (NULL != item)
    {
        list.push_back(item);
        ret++;
    }
    while (true)
    {
        item = linkPeer->getItem();
        if (item)
        {
            list.push_back(item);
            ret++;
        }
        else
        {
            break;
        }
    }
    if (ret > 0)
    {
        return 0;
    }
    std::vector<CByteStream::CBufferItem *>::iterator iter = list.begin();
    std::vector<CByteStream::CBufferItem *>::iterator end  = list.end();
   
    for (; iter != end; iter++)
    {
        item = *iter;
        uint8_t *pi = (uint8_t *) & (linkPeer->m_ipaddr.ipv4);
        NOTICE("socket del item" << (uint32_t)pi[0] << "," << (uint32_t)pi[1] << "," << (uint32_t)pi[2] << "," << (uint32_t)pi[3] << " port: " << linkPeer->m_port << " function:" << __FUNCTION__);
        if (0 == item->delRef())
        {
            m_BufMgn->FreeBufItem(item);
        }
    }
    if (m_callBack)
    {
        if (NULL != linkPeer->m_otherParam)
        {
            (*m_callBack)(linkPeer->m_otherParam);
             linkPeer->m_otherParam = NULL;
        }
    }
    return ret;
}


int CNetworkMgr::handEPOLLRDHUP(CLinkPeer *linkPeer, int type, bool istimeOut)
{
    int ret = 1;

    if (-1 != linkPeer->m_fd)
    {
        m_CriticalEpoll.lock();
        m_epoll.delEnv(linkPeer->m_fd);
        m_CriticalEpoll.unlock();
        close(linkPeer->m_fd);
    }

    //if (!istimeOut)
    {
        int del = delTimeLink(linkPeer);
        if (3 == type && del <= 0)
        {
            printf("Link memort Erro\n");
        }
    }

    if (PEERTYPE_CLIENT == linkPeer->m_peerTyep || PEERTYPE_UDPCLINENT == linkPeer->m_peerTyep)
    {
        ADDNETPort *newADD = new ADDNETPort;

        newADD->ip   = linkPeer->m_ipaddr.ipv4;
        newADD->port = linkPeer->m_port;
        newADD->type = linkPeer->m_proto;
        newADD->dist = linkPeer->m_messageRoute;
        newADD->linkType  = linkPeer->m_linkType;
        newADD->lastTime = time(NULL);
        m_CriticalLink.lock();
        m_addConnect.push_back(newADD);
        m_CriticalLink.unlock();
    }

    if (PEERTYPE_UDPSERVER == linkPeer->m_peerTyep)
    {
        std::size_t seed = 0;
        std::hash<int> hashfun;
        hash_combine(seed,linkPeer->m_ipaddr.ipv4);
        uint32_t  port  = linkPeer->m_port;
        hash_combine(seed, port);
        CUDPCLIENT::iterator iter;
       
        m_CriticalUdp.lock();
        iter =  m_udpClinet.find(seed);
        if (iter != m_udpClinet.end())
        {
            m_udpClinet.erase(iter);
        }
        m_CriticalUdp.unlock();
    }

    linkPeer->lock();
    linkPeer->setConnect(false);
    linkPeer->unlock();

    bool alreadDel = true;
    uint8_t *pi = (uint8_t *) & (linkPeer->m_ipaddr.ipv4);
    

    int linkRef = decRefLink(linkPeer);
    if (linkRef <= 0)
    {
        alreadDel = false;
    }
    else
    {
        NOTICE("socket close: " << (uint32_t)pi[0] << "." << (uint32_t)pi[1] << "." << (uint32_t)pi[2] << "." << (uint32_t)pi[3] <<" type:"<< type << " function:" << __FUNCTION__ << "LINE:" << __LINE__);
    }

    if (type == 2)
    {
        if (alreadDel && (linkPeer->m_sending == true))
        {
            linkRef = decRefLink(linkPeer);
            if(linkRef > 0)
            {
                NOTICE("socket close: " << (uint32_t)pi[0] << "." << (uint32_t)pi[1] << "." << (uint32_t)pi[2] << "." << (uint32_t)pi[3] << " type:" << type << " function:" << __FUNCTION__ << "LINE:" << __LINE__);
            }
        }
    }
    return 0;
}

int CNetworkMgr::clean(CLinkPeer *linkPeer, int type)
{
    return handEPOLLRDHUP(linkPeer, type);
}

void CNetworkMgr::upTimeLink(CLinkPeer *linkPeer)
{

    CLINENTLISTITER iter;
    m_CriticalLink.lock();
    iter = m_client.find(linkPeer);
    if (PEERTYPE_CLIENT == linkPeer->m_peerTyep)
    {
        if (iter == m_client.end())
        {
            m_client.insert(linkPeer);
        }
    }
    else
    {
        if (iter != m_client.end())
        {
            m_timeOut.erase(linkPeer->m_iter);
            linkPeer->m_iter = m_timeOut.insert(m_timeOut.end(), linkPeer);
        }
        else
        {
            linkPeer->m_iter  = m_timeOut.insert(m_timeOut.end(), linkPeer);
            m_client.insert(linkPeer);
        }
    }
    linkPeer->m_lastTime = time(NULL);
    m_CriticalLink.unlock();
}

int CNetworkMgr::delTimeLink(CLinkPeer *linkPeer)
{
    int ret = 0;
    m_CriticalLink.lock();
    CLINENTLISTITER iterLink = m_client.find(linkPeer);
    if (iterLink != m_client.end())
    {
        m_client.erase(iterLink);
        if (PEERTYPE_CLIENT != linkPeer->m_peerTyep)
        {
            m_timeOut.erase(linkPeer->m_iter);
        }
        ret++;
    }
    m_CriticalLink.unlock();
    return ret;
}

int CNetworkMgr::readUdpData(CLinkPeer *linkPeer)
{
  
    int  ret;
    int  new_fd;
    struct sockaddr_in client_addr;
    socklen_t cli_len=sizeof(client_addr);
    new_fd = linkPeer->m_fd;
    CLinkPeer *peer = NULL;

    CByteStream::CBufferItem  *item = m_BufMgn->getBufItem();
    int readLen = recvfrom(new_fd, (char *)(item->m_pBuffer), 2048, 0, (struct sockaddr *) & client_addr, &cli_len);
    ret = readLen;
    if (readLen > 0)
    {
        std::size_t seed = 0;
        hash_combine(seed, client_addr.sin_addr.s_addr);
        uint32_t  port  =client_addr.sin_port;
        hash_combine(seed, port);
        CUDPCLIENT::iterator iter;

        bool find = false;
        m_CriticalLink.lock();
        iter =  m_udpClinet.find(seed);
        if (iter != m_udpClinet.end())
        {
            peer = iter->second;
            peer->addRef();
            find = true;
        }
        m_CriticalLink.unlock();

        if (NULL == peer)
        {
            peer     = new CLinkPeer();
            peer->setMessageRoute(m_distri);
            m_links++;
            peer->m_fd          = -1;
            peer->m_peerTyep    = PEERTYPE_UDPSERVER;
            peer->m_ipaddr.ipv4 = client_addr.sin_addr.s_addr;
            peer->m_port        = client_addr.sin_port;
            peer->setConnect(true);
            peer->m_proto       = linkPeer->m_proto;
            peer->m_linstUDP    = (void *)linkPeer;
            peer->m_linkType    = IP_UDP_TYPE;
            peer->addRef();

            m_CriticalUdp.lock();
            m_udpClinet.insert(std::pair<std::size_t, CLinkPeer*>(seed, peer));
            m_CriticalUdp.unlock();

            upTimeLink(peer);
            uint8_t *pi = (uint8_t *) & (peer->m_ipaddr.ipv4);
            NOTICE("UDP connect success: " << (uint32_t)pi[0] << "." << (uint32_t)pi[1] << "." << (uint32_t)pi[2] << "." << (uint32_t)pi[3] << " port: " << linkPeer->m_port << " new socket!");
        } 
        else
        {
            upTimeLink(peer);
        }

        peer->addRef();
        item->m_iPos    =  readLen;
        item->m_linkMgr = this;
        item->m_fd      = peer;
        item->addRef();
        //bool add = ((DistributionToThr*)m_distri)->addItem(item);
    }
    else
    {
        m_BufMgn->FreeBufItem(item);
        printf("udp rec error  error code %d  error info  %s /n",  errno, strerror(errno));
    }
    return ret;
}

int  CNetworkMgr::readUdpClinet(CLinkPeer *linkPeer)
{
    int  ret;
    int  new_fd;
    
    struct sockaddr_in client_addr;
    socklen_t cli_len=sizeof(client_addr);
    new_fd = linkPeer->m_fd;
   
    CLinkPeer *peer = linkPeer;
    CByteStream::CBufferItem  *item = m_BufMgn->getBufItem();
    int readLen = recvfrom(new_fd, (char *)(item->m_pBuffer), 2048, 0, (struct sockaddr *) & client_addr, &cli_len);
    ret = readLen;
    if (readLen > 0)
    {
        upTimeLink(linkPeer);
        peer->addRef();
        peer->setConnect(true);
        item->m_iPos    =  readLen;
        item->m_linkMgr = this;
        item->m_fd      = peer;
        peer->m_step    = PEERSTEP::PEERSTEP_NORMAL;
        if (client_addr.sin_addr.s_addr == linkPeer->m_ipaddr.ipv4 && client_addr.sin_port == linkPeer->m_port)
        {
            //bool add = ((DistributionToThr*)m_distri)->addItem(item);
        }
        else
        {
            m_BufMgn->FreeBufItem(item);
        }
    }
    else
    {
        m_BufMgn->FreeBufItem(item);
        printf("udp rec error  error code %d  error info  %s /n", errno, strerror(errno));
    }
    return ret;
}

int CNetworkMgr::sendUDPData(CLinkPeer *userLin, CByteStream::CBufferItem* item)
{

    CLinkPeer *linkPeer = NULL;
    if (PEERTYPE_UDPCLINENT == userLin->m_peerTyep)
    {
        linkPeer = userLin;
    }
    else
    {
        linkPeer  = (CLinkPeer *)(userLin->m_linstUDP);
    }
    memcpy(item->m_ip, userLin->m_ipaddr.ipv6, 16);
    item->m_port = userLin->m_port;
    int ret = sendData(linkPeer, item);

    return  ret;
}

