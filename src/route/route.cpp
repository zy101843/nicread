#include "route.h"
#include "../xml/pugixml.hpp"
#include <netinet/in.h>
#include "../tcpiphead.h"
#include "../util/utility_net.h"
#include <arpa/inet.h>

unsigned char route_arpData[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x06,
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0x70, 0x2b, 0x80, 0x40, 0x91, 0x9e,
    0xc0, 0xa8, 0x00, 0xfd,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0xa8, 0x0, 0xbe,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

Route::Route(/* args */)
{
    m_linkParm.interFace   = this;
    m_linkParm.linkType    = 1;
    m_linkParm.linkSubType = 3;
    m_linkParm.id          = 4;
    m_routeTable = new routetable();
    m_arpMap     = new CArpMap();
    m_sendData   = new uint8_t[2000];
    m_count      = 0;
}

Route::~Route()
{
}

int Route::readCof()
{
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_file("route.xml");
    if (!result)
    {
        return -1;
    }
    pugi::xml_node root = doc.child("config");
    pugi::xml_node node = root.first_child();
    pugi::xml_attribute attr;
    std::string path;
    uint8_t m_macGw[6];
    for (; node; node = node.next_sibling())
    {
        if (0 == strcmp(node.name(), "filename"))
        {
            path = node.attribute("name").value();
            path = node.attribute("name").value();

            sscanf(node.attribute("gateway").value(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m_macGw[0], &m_macGw[1], &m_macGw[2], &m_macGw[3], &m_macGw[4], &m_macGw[5]);

            char *mac = NULL;
            for (std::size_t i = 0; i < m_gwList.size(); i++)
            {
                if (0 == memcmp(m_macGw, m_gwList[i]->mac, 6))
                {
                    mac = (char *)m_gwList[i]->mac;
                    break;
                }
            }
            if (mac == NULL)
            {
                ipMap *ipm = new ipMap;
                attr = node.attribute("ip");
                if (attr)
                {
                    ipm->ip.isV6 = false;
                    ipm->ip.ip.v4 = inet_addr(attr.value());
                }
                else
                {
                    ipm->ip.ip.v4 = 0;
                }
                m_gwList.push_back(ipm);
                mac = (char *)ipm->mac;
                memcpy(ipm->mac, m_macGw, 6);
            }
            m_routeTable->addRoute(path, (const char *)mac);
        }
        else if (0 == strcmp(node.name(), "default"))
        {
            sscanf(node.attribute("gateway").value(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m_defaultMac[0], &m_defaultMac[1], &m_defaultMac[2], &m_defaultMac[3], &m_defaultMac[4], &m_defaultMac[5]);
            m_defaultGWIP = inet_addr(node.attribute("ip").value());
            uint8_t *ipbuf = (uint8_t *)&m_defaultGWIP;
            printf("gw ip:%u.%u.%u.%u \n", ipbuf[0], ipbuf[1], ipbuf[2], ipbuf[3]);
        }
        else if (0 == strcmp(node.name(), "local"))
        {
            m_Ip = inet_addr(node.attribute("ip").value());
            m_Mask = inet_addr(node.attribute("mask").value());
            m_IpHost = ntohl(m_Ip);
            m_MaskHost = ntohl(m_Mask);
            m_IpHostMask = m_IpHost & m_MaskHost;
            sscanf(node.attribute("mac").value(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m_mac[0], &m_mac[1], &m_mac[2], &m_mac[3], &m_mac[4], &m_mac[5]);
            memcpy(route_arpData + 6, m_mac, 6);
            memcpy(route_arpData + 22, m_mac, 6);
            memcpy(route_arpData + 28, &m_Ip, 4);
        }
    }
    return 0;
}

int Route::start()
{  
    m_linkParm.m_ext = m_mac;
    m_hub->addData(NULL, -1, &m_linkParm);
    return 1;
}

int Route::writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam)
{
    uint16_t port = 0;
    int ret = 0;
    NetInfo *netInfo = &m_netnetInfo;
    bool arp = false;
    ret = analysisIPHead(data, len, netInfo);
    if (0 == ret)
    {
        return 0;
    }
    if (netInfo->tuple.isIPV6)
    {
        return 0;
    }
    int buflen = netInfo->totalLen + 14 + netInfo->otherLen;
    if (len < buflen)
    {
        return 0;
    }
    arp = netInfo->isARP;
    if (arp)
    {
        arpV4(data, len);
        return len;
    }
    if(netInfo->isV4Broadcast)
    {
        return 0;
    }  
    if (m_netnetInfo.tuple.dstIP.v4 == m_IpHost)
    {
        if (1 == m_netnetInfo.nextProtocol)
        {
            icmpV4(data, len);
            return len;
        }
        return 0;
    }
    if (netInfo->tuple.protcol != 6 && (netInfo->tuple.protcol != 17) && (netInfo->tuple.protcol != 1))
    {
        return 0;
    }
    char *mac = NULL;
    mac = m_routeTable->findRoute(netInfo->tuple.dstIP.v4);
    if (mac == NULL)
    {
        mac = (char *)m_defaultMac;
    }
    memcpy(data, mac, 6);
    memcpy(data + 6, m_mac, 6);
    m_hub->addData(data, len, &m_linkParm);
    return 1;
}

void Route::icmpV4(uint8_t *data, int len)
{
    uint32_t headLen = 14 + m_netnetInfo.l3HeadLen;
    compact_eth_hdr *pEth = (compact_eth_hdr *)(data);
    ICMPhead *icmp = (ICMPhead *)(data + headLen);
    bool needReplay = false;

    if (8 == icmp->type)
    {
        memcpy(m_sendData, data, len);
        memcpy(m_sendData, pEth->h_source, 6);
        memcpy(m_sendData + 6, pEth->h_dest, 6);
        compact_ip_hdr *ipv4Head;
        ipv4Head = (compact_ip_hdr *)(m_sendData + 14);
        ipv4Head->saddr = m_netnetInfo.ipv4Head->daddr;
        ipv4Head->daddr = m_netnetInfo.ipv4Head->saddr;

        AdjustIPHeadV4(&m_netnetInfo, m_sendData);

        ICMPhead *dicmp = (ICMPhead *)(m_sendData + headLen);
        dicmp->type     = 0;
        dicmp->checkSum = 0;
        dicmp->checkSum = inet_chksum(dicmp, len - 14 - m_netnetInfo.otherLen - m_netnetInfo.l3HeadLen);
        int sendLen = len;
        m_hub->addData(m_sendData, sendLen, &m_linkParm);
    }
}

void Route::arpV4(uint8_t *data, int len)
{
    compact_eth_hdr *pEth = (compact_eth_hdr *)(data);
    uint32_t headLen = 14;
    arp_hdr *psArp = (arp_hdr *)(data + headLen);
    bool needReplay = false;
    IPTYPE ip;
    switch (ntohs(psArp->optype))
    {
    case 1:
    {
        /*
        ip.ip.v4 = ntohl(psArp->srcip);
        if ((ip.ip.v4 & m_MaskHost) == m_IpHostMask)
        {
            m_arpMap->addItemV4(ip, psArp->srcmac);
        }
        */
        if (m_Ip != psArp->dstip)
        {
            needReplay = true;
            if (psArp->dstip == psArp->srcip)
            {
                for (std::size_t i = 0; i < m_gwList.size(); i++)
                {
                    if (m_gwList[i]->ip.ip.v4 == psArp->srcip)
                    {
                        if (0 != memcmp(m_gwList[i]->mac, psArp->srcmac, 6))
                        {
                            memcpy(m_gwList[i]->mac, psArp->srcmac, 6);
                        }
                        break;
                    }
                }
            }
            if (psArp->srcip == m_defaultGWIP)
            {
                if (0 != memcmp(m_defaultMac, psArp->srcmac, 6))
                {
                    memcpy(m_defaultMac, psArp->srcmac, 6);
                }
            }
            break;
        }
        memcpy(m_sendData, data, len);
        memcpy(m_sendData, pEth->h_source, 6);
        memcpy(m_sendData + 6, m_mac, 6);

        arp_hdr *pArp = (arp_hdr *)(m_sendData + headLen);
        pArp->optype = htons(2);
        std::swap(pArp->srcip, pArp->dstip);
        memcpy(pArp->dstmac, pArp->srcmac, 6);
        memcpy(pArp->srcmac, m_mac, 6);
        m_hub->addData(m_sendData, len, &m_linkParm);

        if (m_count < 100)
        {
            for (std::size_t i = 0; i < m_gwList.size(); i++)
            {
                if (m_gwList[i]->ip.ip.v4 != 0)
                {
                    memcpy(route_arpData + 38, m_gwList[i]->ip.ip.v6c, 4);
                    m_hub->addData(route_arpData, 60, &m_linkParm);
                }
            }
            memcpy(route_arpData + 38, &m_defaultGWIP, 4);
            m_hub->addData(route_arpData, 60, &m_linkParm);
            m_count++;
        }
        break;
    }
    case 2:
    {
        if (m_Ip != psArp->dstip)
        {
            /*
            ip.ip.v4 = ntohl(psArp->srcip);
            if ((ip.ip.v4 & m_MaskHost) == m_IpHostMask)
            {
                m_arpMap->addItemV4(ip, psArp->srcmac);
            }
            */
        }
        else
        {
            if (m_defaultGWIP == psArp->srcip)
            {
                if (0 != memcmp(m_defaultMac, psArp->srcmac, 6))
                {
                    memcpy(m_defaultMac, psArp->srcmac, 6);
                }
            }
            else
            {
                for (std::size_t i = 0; i < m_gwList.size(); i++)
                {
                    if (m_gwList[i]->ip.ip.v4 == psArp->srcip)
                    {
                        if (0 != memcmp(m_gwList[i]->mac, psArp->srcmac, 6))
                        {
                            memcpy(m_gwList[i]->mac, psArp->srcmac, 6);
                        }
                        break;
                    }
                }
            }
        }
        break;
    }
    default:
    {
        return;
    }
    }
    return;
}
