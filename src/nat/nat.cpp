#include <netinet/in.h>
#include "../tcpiphead.h"
#include "../util/utility_net.h"
#include "../xml/pugixml.hpp"
#include "nat.h"
#include <functional>
// you need to enable the following two rules on your own machine to prevent RST packets and ICMP port unreachable packets sent by the 
// local machine from affecting NAT translation
//iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
//iptables -A OUTPUT -p icmp --icmp-type port-unreachable -j DROP
Nat::Nat()
{
    m_type = 1;
    m_linkParm.interFace = this;
    m_linkParm.linkType = 1;
    m_linkParm.linkSubType = 2;
    m_linkParm.id = 3;
    m_stop = true;
    m_sendData = new uint8_t[2000];
}

Nat::~Nat()
{
    printf("abc\n");
}

void timeoutFunThis(portNatInfo *param, void *pThis, time_t curtime)
{
    Nat *nat = (Nat *)pThis;
    nat->freeNatPort(param, curtime);
}

int Nat::readConf()
{
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_file("nat.xml");
    if (!result)
    {
        return false;
    }
    pugi::xml_node root = doc.child("config");
    pugi::xml_node node = root.first_child();
    pugi::xml_attribute attr;
    for (; node; node = node.next_sibling())
    {
        if (0 == strcmp(node.name(), "nic"))
        {
            m_nicName = node.attribute("name").value();
            sscanf(node.attribute("gateway").value(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m_macGw[0], &m_macGw[1], &m_macGw[2], &m_macGw[3], &m_macGw[4], &m_macGw[5]);
            m_outip = inet_addr(node.attribute("ip").value());
        }
        else if (0 == strcmp(node.name(), "nat"))
        {
            m_gwIp = inet_addr(node.attribute("ip").value());
            m_netMask = inet_addr(node.attribute("mask").value());
            sscanf(node.attribute("mac").value(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m_macNa[0], &m_macNa[1], &m_macNa[2], &m_macNa[3], &m_macNa[4], &m_macNa[5]);
            m_netMaskHost = ntohl(m_netMask);
            m_gwIpHost = ntohl(m_gwIp);
            m_gwIpHost &= m_netMaskHost;
        }
        else if (0 == strcmp(node.name(), "port"))
        {
            uint16_t start = node.attribute("start").as_uint();
            uint16_t end = node.attribute("end").as_uint();
            uint16_t protocol = node.attribute("protocol").as_uint();
            for (uint16_t i = start; i <= end; i++)
            {
                addFreePort(htons(i), protocol);
            }
        }
        else if (0 == strcmp(node.name(), "timeout"))
        {
            m_TCPTimeout = node.attribute("tcp").as_uint();
            m_UDPTimeout = node.attribute("udp").as_uint();
        }   
    }
    return 1;
}

void Nat::start()
{
    readConf();
    m_nic = new nic_proc(m_nicName);
    m_natTcpMap.SetTOFun(timeoutFunThis, this);
    m_natUDPMap.SetTOFun(timeoutFunThis, this);
    m_nic->disableCheckMac();
    if (m_nic->open() >= 0)
    {
        m_monitorTread = new std::thread(std::bind(&Nat::workThread, this));
    }
}

uint16_t Nat::getFreePort(uint16_t portType, std::size_t &freeCount)
{
    uint16_t port = 0;
    if (portType == 6)
    {
        if (!m_portTcpFree.empty())
        {
            port = m_portTcpFree.front();
            m_portTcpFree.pop();
            freeCount = m_portTcpFree.size();
        }
    }
    else if (portType == 17)
    {
        if (!m_portUdpFree.empty())
        {
            port = m_portUdpFree.front();
            m_portUdpFree.pop();
            freeCount = m_portTcpFree.size();
        }
    }
    return port;
}
void Nat::addFreePort(uint16_t port, uint16_t portType)
{
    if (portType == 6)
    {
        m_portTcpFree.push(port);
    }
    else if (portType == 17)
    {
        m_portUdpFree.push(port);
    }
}
void *Nat::freeNatPort(portNatInfo *info, time_t curTime)
{
    bool localDel = false;
    if (info->protocol == 6)
    {
        INNERITER iter = m_innerTCPMap.find(info);
        if (iter != m_innerTCPMap.end())
        {
            m_innerTCPMap.erase(iter);
            localDel = true;
        }
        m_portTcpFree.push(info->natPort);
    }
    else if (info->protocol == 17)
    {
        INNERITER iter = m_innerUDPMap.find(info);
        if (iter != m_innerUDPMap.end())
        {
            m_innerUDPMap.erase(iter);
            localDel = true;
        }
        m_portUdpFree.push(info->natPort);
    }
    uint8_t *detip = (uint8_t *)&(info->internalIp);

    printf("free nat port %d sip %u.%u.%u.%u  sport %d dport %d  %d %d %ld %ld %ld\n",
           ntohs(info->natPort),
           detip[0], detip[1], detip[2], detip[3],
           ntohs(info->internalPort),
           ntohs(info->externalPort),
           localDel,
           info->protocol,
           info->lastTime,
           curTime,
           curTime - info->lastTime);
    delete info;
    return NULL;
}

int Nat::updateCheckSum(uint8_t *iphead, uint8_t *outherHea, int type, int dir, uint32_t new_ip, uint16_t new_port)
{
    return m_updateCheckSum.updateCheckSum(iphead, outherHea, type, dir, new_ip, new_port);
}

uint8_t *Nat::process(uint8_t *data, int dir, int &len, bool &arp)
{
    uint16_t port = 0;
    int ret       = 0;
    NetInfo *netInfo;
    if (1 == dir)
    {
        netInfo = &m_netnetInfo;
    }
    else
    {
        netInfo = &m_nicnetInfo;
    }
    ret = analysisIPHead(data, len, netInfo);
    if (0 == ret)
    {
        return 0;
    }
    if(netInfo->tuple.isIPV6)
    {
        return 0;
    }
    int buflen = netInfo->totalLen + 14 + netInfo->otherLen;
    if (len < buflen)
    {
        return 0;
    }
    analysisL4Head(netInfo, data, len);
    arp = netInfo->isARP;
    NatPortMap *natMap;
    INNERMAP *innerMap;
    uint32_t  timeout = 60;
    if (netInfo->tuple.protcol == 6)
    {
        natMap = &m_natTcpMap;
        innerMap = &m_innerTCPMap;
        timeout = m_TCPTimeout;
    }
    else if (netInfo->tuple.protcol == 17)
    {
        natMap = &m_natUDPMap;
        innerMap = &m_innerUDPMap;
        timeout = m_UDPTimeout;
    }
    else
    {
        return NULL;
    }

    m_tempInfo.natPort = port;
    portNatInfo *local = NULL;
    time_t curTime = time(NULL);
    bool find = false;

    m_critical.lock();
    if (dir == 1)
    {
        m_tempInfo.natPort = port;
        m_tempInfo.internalIp = netInfo->ipv4Head->saddr;
        m_tempInfo.internalPort = netInfo->tuple.srcPort;
        INNERITER iter = innerMap->find(&m_tempInfo);
        if (iter != innerMap->end())
        {
            local = *iter;
            find = true;
        }
    }
    else
    {
        m_tempInfo.natPort = netInfo->tuple.dstPort;
        find = natMap->Find(&m_tempInfo, local, curTime, true);
    }
    m_critical.unlock();

    if (find)
    {
        if (dir == 1)
        {
            m_updateCheckSum.updateCheckSum(netInfo->l3head, netInfo->l4head, local->protocol, 1, local->gwIp, local->natPort);
            memcpy(data, m_macGw, 6);
            memcpy(data + 6, m_macNa, 6);
        }
        else
        {
            m_updateCheckSum.updateCheckSum(netInfo->l3head, netInfo->l4head, local->protocol, 2, local->internalIp, local->internalPort);
            memcpy(data, local->srcMac, 6);
            memcpy(data + 6, m_macNa, 6);
        }
        local->lastTime = curTime;
    }
    else
    {
        if (1 == dir)
        {
            if ((netInfo->tuple.srcIP.v4 & m_netMaskHost) != m_gwIpHost)
            {
                return NULL;
            }
            uint8_t proctol = netInfo->tuple.protcol;
            std::size_t freeCount = 0;
            m_critical.lock();
            uint16_t natPort = getFreePort(proctol, freeCount);
            m_critical.unlock();
            if (natPort == 0)
            {
                return NULL;
            }
            portNatInfo *newInfo = new portNatInfo();
            newInfo->natPort = natPort;
            newInfo->internalIp = netInfo->ipv4Head->saddr;
            newInfo->internalPort = netInfo->tuple.srcPort;
            newInfo->externalIp = netInfo->ipv4Head->daddr;
            newInfo->externalPort = netInfo->tuple.dstPort;
            memcpy(newInfo->srcMac, data + 6, 6);
            newInfo->protocol = proctol;
            newInfo->gwIp = m_outip;
            newInfo->lastTime = curTime;

            m_critical.lock();
            natMap->Timeout(curTime, timeout);
            natMap->Add(newInfo, curTime);
            innerMap->insert(newInfo);
            m_critical.unlock();

            m_updateCheckSum.updateCheckSum(netInfo->l3head, netInfo->l4head, newInfo->protocol, 1, newInfo->gwIp, newInfo->natPort);
            memcpy(data, m_macGw, 6);
            memcpy(data + 6, m_macNa, 6);

            uint8_t *detip = (uint8_t *)&(newInfo->internalIp);
            printf("new nat port %d sip %u.%u.%u.%u  sport %d dport %d  %d %ld\n",
                   ntohs(newInfo->natPort),
                   detip[0], detip[1], detip[2], detip[3],
                   ntohs(newInfo->internalPort),
                   ntohs(newInfo->externalPort),
                   newInfo->protocol,
                   freeCount
                );
        }
        else
        {
            return NULL;
        }
    }
    return data;
}

int Nat::writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam)
{
    bool arp = false;
    uint8_t *outdata = process(data, 1, len, arp);
    if (arp)
    {
        arpV4(data, len);
        return len;
    }
    if (1 == m_netnetInfo.nextProtocol)
    {
        icmpV4(data, len);
        return len;
    }

    if (outdata == NULL)
    {
        return 0;
    }
    m_nic->writeData(data, len);
    return len;
}

int Nat::addData(uint8_t *data, int len, void *param)
{
    bool arp = false;
    uint8_t *outdata = process(data, 2, len, arp);
    if (outdata == NULL)
    {
        return 0;
    }
    m_hub->addData(data, len, &m_linkParm);
    return len;
}

void Nat::workThread()
{
    uint8_t *data;
    int len;
    midInterface *mid = this;
    m_linkParm.m_ext = NULL;
    m_hub->addData(NULL, -1, &m_linkParm);
    while (m_stop)
    {
        len = -1;
        m_nic->readDataMap(len, mid, &m_linkParm);
        if (len > 1514)
        {
            printf("read len error %d  %s %d  \n", len, __FILE__, __LINE__);
        }
    }
}

void Nat::icmpV4(uint8_t *data, int len)
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
        dicmp->type = 0;
        dicmp->checkSum = 0;
        dicmp->checkSum = inet_chksum(dicmp, len - 14 - m_netnetInfo.otherLen - m_netnetInfo.l3HeadLen);
        int sendLen = len;
        m_hub->addData(m_sendData, sendLen, &m_linkParm);
    }
}

void Nat::arpV4(uint8_t *data, int len)
{
    compact_eth_hdr *pEth = (compact_eth_hdr *)(data);
    uint32_t headLen  = 14;
    arp_hdr *psArp    = (arp_hdr *)(data + headLen);
    bool needReplay   = false;

    switch (ntohs(psArp->optype))
    {
    case 1:
    {
        uint8_t *detip = (uint8_t *)&(psArp->dstip);
        uint8_t *srcip = (uint8_t *)&(psArp->srcip);
        if (m_gwIp == psArp->dstip)
        {
            needReplay = true;
        }
        if (false == needReplay)
        {
            break;
        }
        memcpy(m_sendData, data, len);
        memcpy(m_sendData, pEth->h_source, 6);
        memcpy(m_sendData + 6, m_macNa, 6);

        arp_hdr *pArp = (arp_hdr *)(m_sendData + headLen);
        pArp->optype = htons(2);
        std::swap(pArp->srcip, pArp->dstip);
        memcpy(pArp->dstmac, pArp->srcmac, 6);
        memcpy(pArp->srcmac, m_macNa, 6);
        m_hub->addData(m_sendData, len, &m_linkParm);
        break;
    }
    case 2:
    {
        break;
    }
    default:
    {
        return;
    }
    }
    return;
}
