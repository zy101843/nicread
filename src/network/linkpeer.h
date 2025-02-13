#pragma once 
#include <queue>
#include <list>
#include <mutex>
#include "ByteStream.h"

union IPADDR
{
    uint32_t ipv6[4];
    uint32_t ipv4;
};
enum PEERTYPE
{
    PEERTYPE_LINST = 1,
    PEERTYPE_SERVICE,
    PEERTYPE_CLIENT,
    PEERTYPE_UDPSERVERLIS,
    PEERTYPE_UDPSERVER,
    PEERTYPE_UDPCLINENT,
    PEERTYPE_UNKNOW
};

enum PEERSTEP
{
    PEERSTEP_CONECT = 1,
    PEERSTEP_NORMAL,
    PEERSTEP_UNKNOW
};

class CLinkPeer
{
public:
    CLinkPeer();
    virtual ~CLinkPeer();
public :
    void setMessageRoute(void *messageRoute);
public:
    void lock() { m_Critical.lock(); };
    void unlock() { m_Critical.unlock(); }
    bool addItem(CByteStream::CBufferItem* pItem);
    int  prepare(CByteStream::CBufferItem* pItem);
    int  regtoUp(void *mgr);
    CByteStream::CBufferItem* getItem();
    int addRef();
    int delRef();
    bool isConnect()
    {
        return m_connect;
    }
    bool setConnect(bool connet);
public:
    enum 
    {
        PEER_MAX_READ_BUF = 2048
    };
public:
    typedef std::queue<CByteStream::CBufferItem*>  ITEMLIST;
    ITEMLIST      m_itemList;
public:
    void         *m_curSend;
    void         *m_messageRoute;
    void         *m_linkPort;
    int           m_fd;
    IPADDR        m_ipaddr;
    uint16_t      m_port;
    bool          m_isV6;
    PEERTYPE      m_peerTyep;
    int           m_linkType;
    PEERSTEP      m_step;
    int           m_proto;
    uint8_t      *m_readBuf;
    uint8_t      *m_readTotal;
    uint8_t      *m_leftData;
    uint32_t      m_lefLen;
    uint32_t      m_curLen;
    bool          m_sending;
    bool          m_connect;
    int           m_curMsgLen;
    std::mutex  m_Critical;
    std::atomic<int> m_ref;
    void          *m_linstUDP;
    void          *m_otherParam;
public:
    std::list<CLinkPeer*>::iterator m_iter;
    std::time_t                     m_lastTime;
};