#pragma once 
#include <queue>
#include <list>
#include <mutex>
#include <string>
#include "ByteStream.h"
#include "ByteBufMgn.h"

union IPADDR
{
    uint32_t ipv6[4];
    uint16_t ipv6s[8];
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
    void setUpClose();
public:
    void lock() { m_Critical.lock(); };
    void unlock() { m_Critical.unlock(); }
    bool addItem(CByteStream::CBufferItem* pItem);
    int  prepare(int len);
    int  regtoUp(void *mgr, int type);
    int  setBufMgn(ByteBufMgn *bufMgn);
    CByteStream::CBufferItem* getItem();
    int addRef();
    int delRef();
    bool isConnect()
    {
        return m_connect.load();
    }
    bool setConnect(bool connet)
    {
        m_connect.store(connet);
        if(connet == false)
        {
            setUpClose();
        }
        return connet;
    }
    bool getOther()
    {
        return m_outherSet.load();
    }
    bool setother(bool connet)
    {
        m_outherSet.store(connet);
        return connet;
    }
public:
    std::size_t getItemSize();
    int cleanLineBuf();
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
    uint16_t      m_bindport;  
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
    int           m_curMsgLen;
    std::mutex    m_Critical;
    std::mutex       m_SendCritical;
    std::atomic<int> m_ref;
    void           *m_linstUDP;
    void           *m_otherParam;
    uint8_t         m_mac[6];
    uint32_t        m_id;  
    std::string     m_keyPath;

private:
    std::atomic<bool> m_connect;
    std::atomic<bool> m_outherSet; //for sendata flag 
    ByteBufMgn        *m_BufMgn;   
public:
    std::list<CLinkPeer *>::iterator m_iter;
    bool                             m_alreInser;
    std::time_t m_lastTime;
};