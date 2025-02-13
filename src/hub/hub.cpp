#include "hub.h"
#include "../interface.h"
#include "../util/utility_net.h"
#include "../NetModeBase.h"
//#include "../network/netMessageRoute.h"

Filter::Filter()
{
}
Filter::~Filter()
{
}

FilterMac::FilterMac()
{
}
FilterMac::~FilterMac()
{
}

bool FilterMac::process(NetInfo *netinf, uint8_t *data, int len)
{
    uint64_t mac = 0;
    memcpy(&mac, data, 6);

    if (m_macSet.find(mac) != m_macSet.end())
    {
        return true;
    }
    memcpy(&mac, data + 6, 6);
    if (m_macSet.find(mac) != m_macSet.end())
    {
        return true;
    }
    return false;
}
void FilterMac::addMac(std::unordered_set<uint64_t> &set)
{
    std::unordered_set<uint64_t>::iterator iter = set.begin();
    std::unordered_set<uint64_t>::iterator end = set.end();
    for (; iter != end; iter++)
    {
        m_macSet.insert(*iter);
    }
}

CHub::CHub()
{
    m_filter = NULL;
}

CHub::~CHub()
{
}

void arpV4(uint8_t *data, int len, void *param)
{
    compact_eth_hdr *pEth = (compact_eth_hdr *)(data);
    uint32_t headLen = 14 + 0;
    arp_hdr *psArp = (arp_hdr *)(data + headLen);

    bool needReplay = false;

    char buf[128];
    char buf2[128];
    LinkParam *localParam = (LinkParam *)param;
    switch (ntohs(psArp->optype))
    {
    case 1:
    {
        arp_hdr *pArp = (arp_hdr *)(data + headLen);
        inet_ntop(AF_INET, &(psArp->srcip), buf, 128);
        inet_ntop(AF_INET, &(psArp->dstip), buf2, 128);
        if (NULL == param)
        {
            //printf("req ip %s  %s  ", buf, buf2);
            //printf("mac: %02x:%02x:%02x:%02x:%02x:%02x \n", data[6], data[7], data[8], data[9], data[10], data[11]);
        }
        break;
    }
    case 2:
    {

        arp_hdr *pArp = (arp_hdr *)(data + headLen);

        inet_ntop(AF_INET, &(psArp->srcip), buf, 128);
        inet_ntop(AF_INET, &(psArp->dstip), buf2, 128);
        if (1 == localParam->interFace->m_type)
        {
            printf("rep  %s  %s arp :", buf, buf2);
            printf("mac: %02x:%02x:%02x:%02x:%02x:%02x \n", data[6], data[7], data[8], data[9], data[10], data[11]);
        }
        break;
    }
    default:
    {
        //printf("error \n");
        break;
    }
    }
    return;
}
void CHub::AdjustIPHeadV4(NetInfo *netInfo, uint8_t *data)
{
    uint8_t *sendData = data;
    compact_ip_hdr *ip = (compact_ip_hdr *)(sendData + 14 + netInfo->otherLen);
    ip->check = 0;
    ip->check = (uint16_t)(~(uint32_t)lwip_standard_chksum(ip, ip->ihl * 4));
}

void CHub::AdjustUPDCheckSumV4(NetInfo *netInfo, uint8_t *data, int len)
{
    uint8_t *sendData = data;
    compact_ip_hdr *ip = (compact_ip_hdr *)(sendData + 14 + netInfo->otherLen);
    uint32_t headLen = 14 + netInfo->otherLen + netInfo->l3HeadLen;
    UDPHDR *udpHead = (UDPHDR *)(sendData + headLen);
    udpHead->CheckSum = 00;

    uint32_t l4Len = 0;
    uint8_t *UDPHeader = (uint8_t *)sendData + headLen;

    uint32_t totalLen = netInfo->totalLen;
    l4Len = len - netInfo->l3HeadLen;
    uint16_t chk1 = inet_chksum_pseudo(UDPHeader, IP_UDP_TYPE, l4Len, &(ip->saddr), &(ip->daddr));
    udpHead->CheckSum = chk1;
}

void CHub::AdjustTcpCheckSumV4(NetInfo *netInfo, uint8_t *data, int len)
{
    uint8_t *sendData = data;
    compact_ip_hdr *ip = (compact_ip_hdr *)(sendData + 14 + netInfo->otherLen);
    uint32_t headLen = 14 + netInfo->otherLen + netInfo->l3HeadLen;
    TCPHDR *tcpHead = (TCPHDR *)(sendData + headLen);
    tcpHead->CheckSum = 00;
    uint8_t *TCPHeader = (uint8_t *)sendData + headLen;

    uint32_t totalLen = htons(ip->tot_len); //netInfo->totalLen;
    uint32_t l4Len = 0;
    l4Len = totalLen - netInfo->l3HeadLen;
    uint16_t chk1 = inet_chksum_pseudo(TCPHeader, IP_TCP_TYPE, l4Len, &(ip->saddr), &(ip->daddr));
    tcpHead->CheckSum = chk1;
}
void CHub::AdjustUPDCheckSumV6(NetInfo *netInfo, uint8_t *data, int len)
{
    uint8_t *sendData = data;
    compact_ipv6_hdr *ip = (compact_ipv6_hdr *)(sendData + 14 + netInfo->otherLen);
    uint32_t headLen = 14 + netInfo->otherLen + netInfo->l3HeadLen;
    UDPHDR *udpHead = (UDPHDR *)(sendData + headLen);
    udpHead->CheckSum = 00;
    uint8_t *UDPHeader = (uint8_t *)sendData + headLen;
    uint32_t udpLen = netInfo->totalLen; /*- m_l3HeadLen*/
    ;
    // l4Len = totalLen - m_l3HeadLen
    uint16_t chk1 = ip6_chksum_pseudo(UDPHeader, udpLen, IP_UDP_TYPE, udpLen, (uint32_t *)&(ip->saddr), (uint32_t *)&(ip->daddr));
    udpHead->CheckSum = chk1;
}
void CHub::AdjustTcpCheckSumV6(NetInfo *netInfo, uint8_t *data, int len)
{
    uint8_t *sendData = data;
    compact_ipv6_hdr *ip = (compact_ipv6_hdr *)(sendData + 14 + netInfo->otherLen);
    uint32_t headLen = 14 + netInfo->otherLen + netInfo->l3HeadLen;
    TCPHDR *tcpHead = (TCPHDR *)(sendData + headLen);
    tcpHead->CheckSum = 00;
    uint8_t *TCPHeader = (uint8_t *)sendData + headLen;
    uint32_t tcpLen = netInfo->totalLen /*- m_l3HeadLen*/;
    uint16_t chk1 = ip6_chksum_pseudo(TCPHeader, tcpLen, IP_TCP_TYPE, tcpLen, (uint32_t *)&(ip->saddr), (uint32_t *)&(ip->daddr));
    tcpHead->CheckSum = chk1;
}

static uint8_t BroadcastMac[] ={ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t V6Multicast[] ={ 0x33, 0x33 };

int CHub::analysisIPHead(uint8_t *data, int len, NetInfo *netInfo)
{
    netInfo->isARP = false;
    netInfo->isV4Broadcast = (memcmp(BroadcastMac, data, 6) == 0 ? true : false);
    netInfo->isV6Multicast = (memcmp(V6Multicast, data, 2) == 0 ? true : false);
    uint32_t l3_offset = sizeof(compact_eth_hdr);
    uint16_t eth_type;
    uint8_t *buffer = data;
    uint32_t buffer_len = len;

    eth_type = (buffer[12] << 8) + buffer[13];
    uint32_t otherHeadLen = 0;
    while (eth_type == 0x8100)
    {
        l3_offset += 4;
        otherHeadLen += 4;
        eth_type = (buffer[l3_offset - 2] << 8) + buffer[l3_offset - 1];
    }
    if (eth_type == 0x8864)
    {
        l3_offset += 8;
        otherHeadLen += 8;
        if (0x21 == buffer[l3_offset - 1])
        {
            eth_type = 0x0800;
        }
    }
    netInfo->otherLen = otherHeadLen;
    
    //memset(netInfo->tuple.srcIP.v6, 0, 16);
    //memset(netInfo->tuple.dstIP.v6, 0, 16);

    netInfo->tuple.restIp();
    switch (eth_type)
    {
    case 0x0800:
    {
        if (buffer_len < (l3_offset + sizeof(struct compact_ip_hdr)))
        {
            printf("ipv4  error %d\n", buffer_len);
            return 0;
        }
        netInfo->ipv4Head = (struct compact_ip_hdr *)&buffer[l3_offset];
        netInfo->tuple.srcIP.v4 = ntohl(netInfo->ipv4Head->saddr);
        netInfo->tuple.dstIP.v4 = ntohl(netInfo->ipv4Head->daddr);
        netInfo->tuple.isIPV6 = false;
        netInfo->nextProtocol = netInfo->ipv4Head->protocol;
        netInfo->tuple.protcol = netInfo->nextProtocol;
        netInfo->l3HeadLen = netInfo->ipv4Head->ihl * 4;
        netInfo->totalLen = htons(netInfo->ipv4Head->tot_len);
        netInfo->ipv4Len = len - netInfo->l3HeadLen;
        break;
    }
    case 0x86DD:
    {
        if (buffer_len < (l3_offset + sizeof(struct compact_ipv6_hdr)))
        {
            // printf("ipv6  error %d\n", buffer_len);
            return 0;
        }
        netInfo->ipv6Head = (struct compact_ipv6_hdr *)&buffer[l3_offset];
        memcpy(netInfo->tuple.srcIP.v6, &(netInfo->ipv6Head->saddr), 16);
        memcpy(netInfo->tuple.dstIP.v6, &(netInfo->ipv6Head->daddr), 16);
        netInfo->nextProtocol = netInfo->ipv6Head->nexthdr;
        netInfo->tuple.protcol = netInfo->nextProtocol;
        netInfo->totalLen = htons(netInfo->ipv6Head->payload_len);
        netInfo->ipv4Len = netInfo->totalLen;
        netInfo->tuple.isIPV6 = true;
        netInfo->l3HeadLen = 40;
        break;
    }
    case 0x0806:
    {
        netInfo->l3HeadLen = 0;
        netInfo->isARP = true;
        netInfo->totalLen = 20;
        break;
    }
    default:
    {
        netInfo->totalLen = 20;
        netInfo->nextProtocol =  0;
        netInfo->l3HeadLen = 0;
        return 0;
    }
    }
    if (netInfo->l3HeadLen > 40)
    {
        //printf("error \n");
    }
    return 1;
}

int CHub::analysisL4Head(NetInfo *netInfo, uint8_t *data, int len)
{
    uint32_t headLen = 14 + netInfo->otherLen + netInfo->l3HeadLen;
    uint32_t local;
    uint32_t truelen;
    uint8_t *recData = data;
    
    switch (netInfo->nextProtocol)
    {
    case IP_UDP_TYPE:
    {
        netInfo->udpHead = (UDPHDR *)(recData + headLen);
        netInfo->tuple.srcPort = netInfo->udpHead->SrcPort;
        netInfo->tuple.dstPort = netInfo->udpHead->DesPort;
        netInfo->l4headlLen = 8;
        // truelen  =   netInfo->totalLen - 8;
        ////local    =  len - headLen - 8;
        // if (truelen > local)
        //{
        //     return 0;
        // }
        break;
    }
    case IP_TCP_TYPE:
    {
        netInfo->tcpHead = (TCPHDR *)(recData + headLen);
        netInfo->tuple.srcPort = netInfo->tcpHead->SrcPort;
        netInfo->tuple.dstPort = netInfo->tcpHead->DesPort;
        netInfo->l4headlLen = (netInfo->tcpHead->hdLen * 4);
        /* truelen  =  netInfo->totalLen - netInfo->tcpHead->hdLen * 4;
         if (truelen > local)
         {
             return 0;
         }*/
        break;
    }
    default:
    {

        break;
    }
    }
    return 1;
}

const uint8_t MCASET_MAC[4] ={ 0x01, 0x00, 0x5e, 0x00};
int CHub::addData(uint8_t *data, int len, void *param)
{

    if (len < 0)
    {
        justAddPort(param);
        return 0;
    }
    if (len < 30)
    {
        return 0;
    }

    LinkParam *srcparam = (LinkParam *)param;
    uint32_t local = *(uint32_t*)data;
    if (srcparam->linkType == 1)
    {
        local &= 0x00ffffff;
        if (local == 0x5e0001)
        {
            return 0;
        }
    }

    int ret = 0;
    LinkParam *localParam = (LinkParam *)param;
    Interface *portint = localParam->interFace;
    NetInfo    netInfo;
    void      *locapPort;
    netInfo.nextProtocol = 0;
    netInfo.l3HeadLen    = 0;
    ret  = analysisIPHead(data, len, &netInfo);
    if (0 == ret)
    {
        return 0;
    }
    int buflen =  netInfo.totalLen + 14 + netInfo.otherLen;
    if (len < buflen)
    {
        return 0;
    }
    analysisL4Head(&netInfo, data, len);
    if (NULL != m_filter)
    {
        if (m_filter->process(&netInfo, data, len))
        {
            return 0;
        }
    }

    bool sendtoAll = false;
    if (ICMPV6 == netInfo.nextProtocol && netInfo.isV6Multicast)
    {
        sendtoAll = true;
    }
    if (netInfo.isV4Broadcast && netInfo.isARP)
    {
        sendtoAll = true;
    }
    
    //f (netInfo.isARP)
    //{
        //if(NULL==param)
        //arpV4(data, len, param);
    //}

    updateMac(data + 6, param);
    if (sendtoAll)
    {
        //if (srcparam->linkType == 2)
        //{
        sendToAllPort(data, len, param);
        //}
    }
    else
    {
        if (srcparam->linkType == 2)
        {
            printf("error \n");
        }
        locapPort = findPort(data);
        if (nullptr != locapPort && locapPort != portint)
        {
            tcpFragmentation(locapPort, &netInfo, data, len, param);
            //sendData(locapPort, &netInfo, data, len, param);
        }
    }
    return len;
}

static uint8_t SYNOPT[] = {0x02, 0x04, 0x05, 0x1d, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02};
static uint8_t ACKOPT[] = {0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x03, 0x03, 0x07};

int CHub::findMSS(NetInfo *netInfo, uint8_t *data)
{
    uint8_t *opt = (uint8_t *)(netInfo->tcpHead) + 20;
    int optLen = netInfo->l4headlLen - 20;
    int leftLen = optLen;
    uint8_t *end = opt + leftLen;
    uint8_t typelen = 0;

    uint16_t intemLen = 0;
    bool notnedd = false;
    bool find = true;
    while (opt < end && find)
    {
        uint8_t type = *opt;
        switch (type)
        {
        case 1:
            opt++;
            break;
        case 2:
            typelen = opt[1];
            intemLen = *((uint16_t *)(opt + 2));
            intemLen = htons(intemLen);
            if (intemLen != 1309)
            {
                *(opt + 2) = 0x05;
                *(opt + 3) = 0x1d;
                notnedd = true;
            }
            find = false;
            opt += typelen;
            break;
        default:
        {
            typelen = opt[1];
            opt += typelen;
            break;
        }
        }
    }
    int totallen = 14 + netInfo->otherLen + netInfo->l3HeadLen + netInfo->l4headlLen;
    if (find)
    {
        netInfo->tcpHead->hdLen++;
        uint8_t *add = (uint8_t *)(netInfo->tcpHead) + netInfo->l4headlLen;
        memcpy(add, SYNOPT, 4);
        netInfo->ipv4Head->tot_len = htons(netInfo->totalLen + 4);
        AdjustIPHeadV4(netInfo, data);

        totallen += 4;
        AdjustTcpCheckSumV4(netInfo, data, totallen);
    }
    else
    {
        if (notnedd)
        {
            AdjustTcpCheckSumV4(netInfo, data, totallen);
        }
    }
    return totallen;
}

#define BODYMAX_LEN 1309

int CHub::tcpFragmentation(void *dstParam, NetInfo *netInfo, uint8_t *data, int len, void *param)
{
    LinkParam *loacalParam = (LinkParam *)dstParam;
    LinkParam *src = (LinkParam *)param;
    Interface *inter = loacalParam->interFace;
    bool find = true;


    if (src->linkType == 2)
    {
        inter->writeData(data, len, 2, param, dstParam);
    }
    else
    {
        switch (netInfo->nextProtocol)
        {
            case IP_UDP_TYPE:
            {
                if (len < 1514)
                {
                    inter->writeData(data, len, 2, param, dstParam);
                }
                else
                {
                    printf("the udp sen is error %d %s %d\n", len, __FUNCTION__, __LINE__);
                }
                break;
            }
            case IP_TCP_TYPE:
            {
                uint8_t flag = netInfo->tcpHead->FLAG;
                uint8_t ack  = netInfo->tcpHead->FLAG;

                if (0x02 == flag)
                {
                    int adjlen = findMSS(netInfo, data);
                    inter->writeData(data, adjlen, 2, param, dstParam);
                }
                else if (0x12 == flag)
                {

                    int adjlen = findMSS(netInfo, data);
                    inter->writeData(data, adjlen, 2, param, dstParam);
                }
                else
                {
                    /*
                    uint32_t headLen = 14 + netInfo->otherLen + netInfo->l3HeadLen + netInfo->l4headlLen;
                    int bodylen = len - headLen;
                    if (bodylen > BODYMAX_LEN)
                    {
                        uint32_t seq = 0;
                        uint16_t id = 0;
                        uint16_t l3total = 0;
                        uint32_t l3l4Head = netInfo->l3HeadLen + netInfo->l4headlLen;

                        int leftlen = bodylen;

                        seq = htonl(netInfo->tcpHead->ulSeq);
                        id  = htons(netInfo->ipv4Head->id);

                        int count = 0;
                        uint8_t *bodybuf = data + headLen;
                        uint8_t *frisbuf = bodybuf;
                        int sendLen;
                        int copylen;
                        do
                        {

                            l3total = l3l4Head;
                            copylen = leftlen > BODYMAX_LEN ? BODYMAX_LEN : leftlen;
                            if (bodybuf != frisbuf)
                            {
                                memcpy(frisbuf, bodybuf, copylen);
                            }
                            l3total += copylen;
                            netInfo->ipv4Head->id = htons(id);
                            netInfo->ipv4Head->tot_len = htons(l3total);
                            netInfo->tcpHead->ulSeq = htonl(seq);
                            //inter->writeData(data, len, 2, param);
                            seq += copylen;
                            id++;
                            leftlen -= copylen;
                            bodybuf += copylen;

                            sendLen = l3total + 14 + netInfo->otherLen;
                            AdjustIPHeadV4(netInfo, data);
                            AdjustTcpCheckSumV4(netInfo, data, sendLen);

                            inter->writeData(data, sendLen, 2, param, loacalParam);

                            find = false;
                            if (leftlen > 0)
                            {
                                m_critical.lock();
                                if (m_portSet.end() != m_portSet.find(loacalParam))
                                {
                                    find = true;
                                    loacalParam->addRef();
                                }
                                m_critical.unlock();
                            }

                            if (false == find)
                            {
                                break;
                            }
                        } while (leftlen);
                    }
                    else
                    {
                        inter->writeData(data, len, 2, param, dstParam);
                    }   */
                    inter->writeData(data, len, 2, param, dstParam);
                }
                break;
            }
            default:
            {
                if (len < 1514)
                {
                    inter->writeData(data, len, 2, param, dstParam);
                }
                else
                {
                    printf("unknow  sen is error %d %s %d\n", len, __FUNCTION__, __LINE__);
                }
                break;
            }
        }
    }

    loacalParam->delRef();
    return len;
}

int CHub::sendData(void *dstParam, NetInfo *netInfo, uint8_t *data, int len, void *param)
{
    LinkParam *loacalParam = (LinkParam *)dstParam;
    Interface *inter = loacalParam->interFace;
    bool find = true;
    int ret = -1;
    if (len < 1514)
    {
        ret = inter->writeData(data, len, 2, param, dstParam);
    }
    else
    {
        printf("the udp sen is error %d %s %d\n", len, __FUNCTION__, __LINE__);
    }
    loacalParam->delRef();
    return len;
}

int CHub::updateMac(uint8_t *data,void *param)
{
    mac_inter loc(data);
    m_critical.lock();

    MACMAPITER iter = m_macMap.find(&loc);
    if (m_macMap.end() == iter)
    {
        mac_inter *newmac =  new mac_inter(data);
        newmac->p = param;
        m_macMap.insert(newmac);
    }
    else
    {
        if (param != (*iter)->p)
        {
            (*iter)->p = param;
        }
    }
    m_critical.unlock();

    return 0;
}

int CHub::cleanLink(void *param)
{
    LinkParam *localparam = (LinkParam *)param;
  
    MACMAPITER iterFind;
    PORTSET::iterator postSet;
    int count = 0;
    bool findItem = false;
    m_critical.lock();

    postSet = m_portSet.find(param);
    if (m_portSet.end() != postSet)
    {
        m_portSet.erase(postSet);
        findItem = true;
    }
     /*
    std::unordered_set<uint64_t>::iterator iter = localparam->macList.begin();
    std::unordered_set<uint64_t>::iterator end  = localparam->macList.end();
    for (; iter != end; iter++)
    {
        iterFind = m_macMap.find(*iter);
        if (m_macMap.end() != iterFind)
        {
            LinkParam *localParam2 = ((LinkParam *)(iterFind->second));
            if (localparam == localParam2)
            {
                count++;
                m_macMap.erase(iterFind);
            }
        }
    }
    */
    m_critical.unlock();

    if (findItem)
    {
        ((LinkParam *)(param))->delRef();
    }
    return count;
}

void *CHub::findPort(uint8_t *data)
{
    mac_inter loc(data);
    LinkParam *linkParam = NULL;
    MACMAPITER iter;
    void *ret = NULL;

    m_critical.lock();
    iter = m_macMap.find(&loc);
    if (m_macMap.end() != iter)
    {
        linkParam = ((LinkParam *)((*iter)->p));
        if (m_portSet.end() != m_portSet.find(linkParam))
        {
            linkParam->addRef();
            ret = linkParam;
        }
    }
    m_critical.unlock();

    return ret;
}

void CHub::justAddPort(void *port)
{
    m_critical.lock();
    PORTSET::iterator iter = m_portSet.find(port);
    if (m_portSet.end() == iter)
    {
        ((LinkParam *)(port))->addRef();
        m_portSet.insert(port);
    }
    m_critical.unlock();
}

int CHub::sendToAllPort(uint8_t *data, int len, void *param)
{
    std::vector<void *> list;
    m_critical.lock();
    void *ret = NULL;
    PORTSET::iterator iter = m_portSet.begin();
    PORTSET::iterator end  = m_portSet.end();
    for (; iter != end; iter++)
    {
        list.push_back(*iter);
    }
    m_critical.unlock();

    std::vector<void *>::iterator iter1 = list.begin();
    std::vector<void *>::iterator end1 = list.end();

    int count = 0;
    bool find = false;
    for (; iter1 != end1; iter1++)
    {
        find = false;
        LinkParam *param1 = (LinkParam *)*iter1;
       
        m_critical.lock();
        if (m_portSet.end() != m_portSet.find(param1))
        {
            find = true;
            if (param != param1)
            {
                param1->addRef();
            }
        }
        m_critical.unlock();
       
        if (find)
        {
            Interface *inter = (Interface *)(param1->interFace);
            if (param != param1)
            {
                inter->writeData(data, len, 1, param, param1);
                param1->delRef();
            }
            else
            {
                //if (2 == param1->interFace->m_type)
                //{
                    //printf("find myself %s %d \n", __FILE__, __LINE__);
                //}
            }
        }
        count++;
    }
    return count;
}

int CHub::icmp6PacketTooBig(NetInfo *netInfo, uint8_t *recData, uint8_t *sendData)
{
    uint32_t headLen = 14 + netInfo->otherLen + netInfo->l3HeadLen;
    memcpy(sendData, recData, headLen);
    memcpy(sendData, recData + 6, 6);
    memcpy(sendData + 6, recData, 6);

    compact_ipv6_hdr *ipV6 = (compact_ipv6_hdr *)(sendData + 14 + netInfo->otherLen);

    memcpy(&(ipV6->daddr), &(netInfo->ipv6Head->saddr), 16);
    memcpy(&(ipV6->saddr), &(netInfo->ipv6Head->daddr), 16);
    ipV6->nexthdr = IP6_NEXTH_ICMP6;
    ipV6->payload_len = htons(56);

    icmp6_hdr *icmpTobig = (icmp6_hdr *)(sendData + headLen);
    icmpTobig->type = 2;
    icmpTobig->code = 0;
    icmpTobig->chksum = 0;
    icmpTobig->data = htonl(1514);

    uint8_t *curPost = (uint8_t *)sendData + headLen + sizeof(icmp6_hdr);
    memcpy(curPost, recData + 14 + netInfo->otherLen, 48);

    icmpTobig->chksum = ip6_chksum_pseudo((uint8_t *)icmpTobig, 56, IP6_NEXTH_ICMP6, 56, (uint32_t *)&(ipV6->saddr), (uint32_t *)&(ipV6->daddr));
    int sendLen = 14 + netInfo->otherLen + netInfo->l3HeadLen + 8 + 48;
    return sendLen;
}
int CHub::icmpPacketTooBig(NetInfo *netInfo, uint8_t *recData, uint8_t *sendData)
{
    uint32_t headLen = 14 + netInfo->otherLen + netInfo->l3HeadLen;
    memcpy(sendData, recData, headLen);
    memcpy(sendData, recData + 6, 6);
    memcpy(sendData + 6, recData, 6);

    compact_ip_hdr *ip = (compact_ip_hdr *)(sendData + 14 + netInfo->otherLen);
    ip->saddr = netInfo->ipv4Head->daddr;
    ip->daddr = netInfo->ipv4Head->saddr;
    ip->check = 0;
    ip->protocol = 1;
    ip->tot_len = htons(ip->ihl * 4 + 8 + 28);
    ip->check = (uint16_t)(~(uint32_t)lwip_standard_chksum(ip, ip->ihl * 4));

    icmp_mtu_hdr *icmpTobig = (icmp_mtu_hdr *)(sendData + headLen);
    icmpTobig->type = 3;
    icmpTobig->code = 4;
    icmpTobig->mtu = htonl(1514);
    icmpTobig->chksum = 0;

    uint8_t *curPost = (uint8_t *)sendData + headLen + sizeof(icmp_mtu_hdr);
    memcpy(curPost, recData + 14 + netInfo->otherLen, netInfo->l3HeadLen + 8);
    icmpTobig->chksum = (uint16_t) ~(uint32_t)lwip_standard_chksum(icmpTobig, 8 + netInfo->l3HeadLen + 8);
    int sendLen = 14 + netInfo->otherLen + netInfo->l3HeadLen + 8 + netInfo->l3HeadLen + 8;
    return sendLen;
}