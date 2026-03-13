#include <memory.h>
#include "linkpeer.h"
#include "../netport/netPort.h"

CLinkPeer::CLinkPeer()
{
    m_fd         = -1;
    m_isV6       = false;
    m_peerTyep   = PEERTYPE_UNKNOW;
    m_readBuf    = new uint8_t[PEER_MAX_READ_BUF];
    m_curLen     = 0;
    m_curSend    = NULL;
    m_ref.store(0);
    m_lefLen     = 0;
    m_curMsgLen  = 0;
    m_otherParam = 0;  
    memset(m_ipaddr.ipv6, 0, 16);
    m_linkPort   = new CNetPort();
    m_alreInser  = false;
    m_outherSet.store(false);
    m_connect.store(false);
    m_mac[0] = 0;
    m_linkType = 0;
}

CLinkPeer::~CLinkPeer()
{
    delete m_readBuf;
    cleanLineBuf();
    m_linkPort = NULL;
}

void CLinkPeer::setUpClose()
{
    if (m_linkPort)
    {
        ((CNetPort *)m_linkPort)->cleanPort(1);
        m_linkPort = NULL;
    }
}

void CLinkPeer::setMessageRoute(void *messageRoute)
{
    m_messageRoute = messageRoute;
    midInterface *mid = (midInterface *)messageRoute;
    ((CNetPort*)m_linkPort)->setHub(mid);
}

bool CLinkPeer::addItem(CByteStream::CBufferItem* pItem)
{   
    m_SendCritical.lock();
    m_itemList.push(pItem);
    m_SendCritical.unlock();
    return true;
}

CByteStream::CBufferItem* CLinkPeer::getItem()
{
    CByteStream::CBufferItem* pItem = NULL;
    m_SendCritical.lock();
    if (!m_itemList.empty())
    {
        pItem = m_itemList.front();
        m_itemList.pop();
    }
    m_SendCritical.unlock();
    return pItem;
}
std::size_t CLinkPeer::getItemSize()
{
    std::size_t size = 0;
    m_SendCritical.lock();
    size = m_itemList.size();
    m_SendCritical.unlock();
    return size;
}

int CLinkPeer::addRef()
{
    int ret = ++m_ref;
    return ret;
}
int CLinkPeer::delRef()
{
    int ret = --m_ref;
    if (0 == ret)
    {
        if (m_isV6)
        {
            char client_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, m_ipaddr.ipv6, client_ip, sizeof(client_ip));
            printf("clean socket close type:%d ip:[%s] port:%u CLinkPeer::%s line:%d\n", m_linkType, client_ip , htons(m_port), __FUNCTION__, __LINE__);
        }
        else
        {
            uint8_t *pi = (uint8_t *)&(m_ipaddr.ipv4);
            printf("clean socket close type:%d ip:%u.%u.%u.%u port:%u CLinkPeer::%s line:%d\n", m_linkType, pi[0] ,pi[1] ,pi[2],pi[3], htons(m_port), __FUNCTION__, __LINE__);
        }
        delete this;
    }
    return ret;
}

int CLinkPeer::prepare(int len)
{
    int ret = ((CNetPort*)m_linkPort)->processFromNet(m_readBuf, len);
    return ret;
}

int CLinkPeer::regtoUp(void *mgr, int type)
{ 
    addRef();
    if(type == 2)
    {
        ((CNetPort*)m_linkPort)->setId(m_id);
    }
    ((CNetPort*)m_linkPort)->setKeyPath(m_keyPath);
    ((CNetPort*)m_linkPort)->set(mgr ,this);
    int ret = ((CNetPort*)m_linkPort)->regtoUp(mgr, type);
    return ret;
}

int CLinkPeer::setBufMgn(ByteBufMgn *bufMgn)
{
    m_BufMgn = bufMgn;
    return 0;
}

int CLinkPeer::cleanLineBuf()
{
    std::vector<CByteStream::CBufferItem *> list;
    CByteStream::CBufferItem *item = (CByteStream::CBufferItem*)m_curSend;
    
    int ret = 0;
    if (NULL != item)
    {
        list.push_back(item);
        ret++;
    }
    m_SendCritical.lock();
    while (!m_itemList.empty())
    {
        item = m_itemList.front();
        m_itemList.pop();
        list.push_back(item);
        ret++;
    }
    m_SendCritical.unlock();
    printf("CLinkPeer::cleanLineBuf item num:%d line:%d \n", ret, __LINE__);
    if (ret > 0)
    {
        return 0;
    }
    std::vector<CByteStream::CBufferItem *>::iterator iter = list.begin();
    std::vector<CByteStream::CBufferItem *>::iterator end = list.end();
    for (; iter != end; iter++)
    {
        item = *iter;
        m_BufMgn->delBufRef(item);
    }
    return ret;
}
