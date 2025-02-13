#include <memory.h>
#include "linkpeer.h"
#include "../netport/netPort.h"

CLinkPeer::CLinkPeer()
{
    m_fd         = -1;
    m_isV6       = false;
    m_peerTyep   = PEERTYPE_UNKNOW;
    m_readBuf    = new uint8_t[PEER_MAX_READ_BUF];
    m_sending    = false;
    m_connect    = false;
    m_curLen     = 0;
    m_curSend    = NULL;
    m_ref        = 0;
    m_lefLen     = 0;
    m_curMsgLen  = 0;
    m_otherParam = 0;  
    memset(m_ipaddr.ipv6, 0, 16);
    m_linkPort   = new CNetPort();
}

CLinkPeer::~CLinkPeer()
{
    delete m_readBuf;
    delete  ((CNetPort*)m_linkPort);
}
void CLinkPeer::setMessageRoute(void *messageRoute)
{
    m_messageRoute = messageRoute;
    ((CNetPort*)m_linkPort)->setHub(messageRoute);
}

bool CLinkPeer::addItem(CByteStream::CBufferItem* pItem)
{
    m_itemList.push(pItem);
    return true;
}

CByteStream::CBufferItem* CLinkPeer::getItem()
{
    CByteStream::CBufferItem* pItem = NULL;
    if (!m_itemList.empty())
    {
        pItem = m_itemList.front();
        m_itemList.pop();
    }
    return pItem;
}
int CLinkPeer::addRef()
{
    int ret = ++m_ref;
    return ret;
}
int CLinkPeer::delRef()
{
    int ret = --m_ref;
    return ret;
}

int CLinkPeer::prepare(CByteStream::CBufferItem* pItem)
{
    int ret = ((CNetPort*)m_linkPort)->processFromNet(pItem->m_pBuffer, pItem->m_iPos);
    return ret;
}

int CLinkPeer::regtoUp(void *mgr)
{
    ((CNetPort*)m_linkPort)->set(mgr ,this);
    int ret = ((CNetPort*)m_linkPort)->regtoUp(mgr);
    return ret;
}

bool CLinkPeer::setConnect(bool connet)
{
    m_connect = connet;
    return m_connect;
}

