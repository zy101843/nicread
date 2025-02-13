#include "arpMap.h"

CArpMap::CArpMap()
{
}


CArpMap::~CArpMap()
{

}

bool CArpMap::addItemV4(IPTYPE &ip, uint8_t* mac)
{
    m_iter  = m_v4Arp.find(&ip);
    if (m_v4Arp.end() != m_iter)
    {
        memcmp(m_iter->second, mac, 6);
        return true;
        /* if (0 == memcmp(m_iter->second, mac, 6))
         {
             return true;
         }
         else
         {
             delete (m_iter->first);
             delete[](m_iter->second);
             m_v4Arp.erase(m_iter);
         }*/
    }
    uint8_t *localMac = new uint8_t[6];
    memcpy(localMac, mac, 6);
    IPTYPE *localip = new IPTYPE;
    memset(localip->ip.v6, 0, 16);
    localip->ip.v4   = ip.ip.v4;
    localip->isV6 = false;
    std::pair<ARPMAPITER, bool > ret = m_v4Arp.insert(std::pair<IPTYPE *, uint8_t *>(localip, localMac));
    if (!ret.second)
    {
        delete[]localMac;
        delete localip;
    }
    return ret.second;
}
bool CArpMap::addItemV6(IPTYPE &ip, uint8_t* mac)
{
    m_iter  = m_v6Arp.find(&ip);
    if (m_v6Arp.end() != m_iter)
    {
        memcpy(m_iter->second, mac, 6);
        return true;
    }
    uint8_t *localMac = new uint8_t[6];
    memcpy(localMac, mac, 6);
    IPTYPE *localip = new IPTYPE;
    memcpy(localip->ip.v6, ip.ip.v6, 16);
    localip->isV6 = true;
    std::pair<ARPMAPITER, bool > ret = m_v6Arp.insert(std::pair<IPTYPE *, uint8_t *>(localip, localMac));
    if (!ret.second)
    {
        delete[]localMac;
        delete localip;
    }
    return ret.second;
}
uint8_t *CArpMap::findV4(IPTYPE &ip)
{
    uint8_t *ret = NULL;
    m_iter = m_v4Arp.find(&ip);
    if (m_iter != m_v4Arp.end())
    {
        ret = m_iter->second;
    }
    return ret;
}
uint8_t *CArpMap::findV6(IPTYPE &ip)
{
    uint8_t *ret = NULL;
    m_iter = m_v6Arp.find(&ip);
    if (m_iter != m_v6Arp.end())
    {
        ret = m_iter->second;
    }
    return ret;
}