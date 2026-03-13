#include "hub.h"
#include "../interface.h"
#include "../util/utility_net.h"
#include "../NetModeBase.h"
#include <functional>

extern std::time_t g_curTime;
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
    m_vip = 0;
    m_vmask = 0;
    m_dropLen = 0;
    m_dropVec = NULL;

    m_haveVirNic = false;
    m_aut = NULL;
    m_PackCount = 0;
    sem_init(&m_sem, 0, 1);
    pthread_mutex_init(&m_mutex, NULL);
    pthread_mutex_init(&m_mutexBuf, NULL);

    m_curTime = time(NULL);
    m_processData[0] = &CHub::porcData;
    m_processData[1] = &CHub::procLink;
    initData();
}

CHub::~CHub()
{
}

void CHub::start()
{
    m_monitorTread = new std::thread(std::bind(&CHub::workThread, this));
}

void CHub::setVnicNat(uint32_t ip, uint32_t mask)
{
    m_vip = ip;
    m_vmask = mask;
}

void CHub::setDropMac(std::vector<uint8_t *> *drop)
{
    m_dropVec = drop;
    m_dropLen = drop->size();
}

void arpV4(uint8_t *data, int len, void *param)
{
    compact_eth_hdr *pEth = (compact_eth_hdr *)(data);
    uint32_t headLen = 14 + 0;
    arp_hdr *psArp   = (arp_hdr *)(data + headLen);

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
        break;
    }
    }
    return;
}

uint32_t arpV4(uint8_t *data, int len, int &type)
{
    compact_eth_hdr *pEth = (compact_eth_hdr *)(data);
    uint32_t headLen = 14 + 0;
    arp_hdr *psArp = (arp_hdr *)(data + headLen);

    uint32_t local = 0;
    type = psArp->optype;
    switch (ntohs(psArp->optype))
    {
    case 1:
    {
        local = ntohl(psArp->dstip);
        break;
    }
    case 2:
    {
        local = ntohl(psArp->dstip);
        break;
    }
    default:
    {
        break;
    }
    }
    return local;
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

    uint32_t totalLen = htons(ip->tot_len); // netInfo->totalLen;
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

int CHub::reg(int len, void *param)
{
    if (len != -1 && len != -2)
    {
        return 0;
    }
    HubMidBuf *lo = getMidBuf();
    if (NULL == lo)
    {
        return 0;
    }
    lo->len   = len;
    lo->index = 1;
    lo->param = param;
    postData(lo);
    return len;
}

int CHub::addData(uint8_t *data, int len, void *param)
{
    if (len < 30 || len > 1580)
    {
        return 0;
    }
    if ((*data & 0x3) == 0x01)
    {
        return 0;
    }
    HubMidBuf *lo = getMidBuf();
    if (NULL == lo)
    {
        return 0;
    }
    
    memcpy(lo->buf, data, len);
    lo->len = len;
    lo->index = 0;
    lo->param = param;
    postData(lo);
    return len;
}

int CHub::addData(HubMidBuf *buf, void *param)
{
    if (buf->len > 1580 || buf->len < 30)
    {
        returnMidBuf(buf);
        return 0;
    }
    buf->index = 0;
    buf->param = param;
    postData(buf);
    return buf->len;
}
int  CHub::postData(HubMidBuf *buf)
{
    pthread_mutex_lock(&m_mutex);
    m_listBuf.push(buf);
    pthread_mutex_unlock(&m_mutex);
    sem_post(&m_sem);
    return 1;
}

HubMidBuf *CHub::getMidBuf()
{
    HubMidBuf *lo = NULL;
    pthread_mutex_lock(&m_mutexBuf);
    if (m_freeList.size() > 0)
    {
        lo = m_freeList.top();
        m_freeList.pop();
        pthread_mutex_unlock(&m_mutexBuf);
    }
    else
    {
        pthread_mutex_unlock(&m_mutexBuf);
        lo = new HubMidBuf;
        lo->type = 2;
    }
    return lo;
}
void CHub::returnMidBuf(HubMidBuf *buf)
{
    if (1 == buf->type)
    {
        pthread_mutex_lock(&m_mutexBuf);
        m_freeList.push(buf);
        pthread_mutex_unlock(&m_mutexBuf);
    }
    else
    {
        delete buf;
    }
}

void CHub::workThread()
{
    HubMidBuf *lo = NULL;
    bool condition = false;
    int index;
    while (true)
    {
        sem_wait(&m_sem);
        do
        {
            condition = false;
            lo = NULL;
           
            pthread_mutex_lock(&m_mutex);
            if (m_listBuf.size() > 0)
            {
                lo = m_listBuf.front();
                m_listBuf.pop();
                condition = !m_listBuf.empty();
            }
            pthread_mutex_unlock(&m_mutex);
            
            if (lo)
            {
                (this->*m_processData[lo->index])(lo->buf, lo->len, lo->param);
                returnMidBuf(lo);
            }
        } while (condition);
    }
}

int CHub::procLink(uint8_t *data, int len, void *param)
{
    LinkParam *srcparam = (LinkParam *)param;
    if (len == -1)
    {
        justAddPort(param);
        if (1 == srcparam->linkType)
        {
            uint8_t *ext = NULL;
            ext = (uint8_t *)(srcparam->m_ext);
            if (2 == srcparam->linkSubType)
            {
                m_haveVirNic = true;
                ext += 6;
            }
            if (NULL != ext)
            {
                updateMac(ext, param, true);
                printf("Add mac in nic: %02X:%02X:%02X:%02X:%02X:%02X\n", ext[0], ext[1], ext[2], ext[3], ext[4], ext[5]);
            }
        }
        else if (2 == srcparam->linkType)
        {
            if (m_haveVirNic)
            {
                if (NULL != m_aut)
                {
                    data = m_aut;
                    len = 60;
                    srcparam->addRef();
                    sendData(param, NULL, data, len, param);
                }
            }
            if (NULL != srcparam->m_ext)
            {
                updateMac((uint8_t *)(srcparam->m_ext), param);
            }
        }
        m_PackCount = 0;
    }
    else if (len == -2)
    {
        cleanLink(param);
    }
    return 0;
}

const uint8_t MCASET_MAC[4] = {0x01, 0x00, 0x5e, 0x00};
int CHub::porcData(uint8_t *data, int len, void *param)
{
    LinkParam *srcparam = (LinkParam *)param;
    uint8_t local = *data;
    local &= 0x03;
    if (local == 0x01)
    {
        return 0;
    }
    int ret = 0;
    LinkParam *localParam = (LinkParam *)param;
    NetInfo netInfo;
    void *locapPort;

    netInfo.nextProtocol = 0;
    netInfo.l3HeadLen = 0;
    netInfo.totalLen = 0;
    ret = analysisIPHead(data, len, &netInfo);
    if (0 == ret)
    {
        return 0;
    }

    int buflen = netInfo.totalLen + 14 + netInfo.otherLen;
    if (len < buflen)
    {
        return 0;
    }
    analysisL4Head(&netInfo, data, len);
    bool sendtoAll = false;
    if (netInfo.isARP)
    {
        if (m_vip != 0 || (srcparam->linkType == 1))
        {
            int optype = 0;
            uint32_t dip = arpV4(data, len, optype);
            dip &= m_vmask;
            if (dip != m_vip)
            {
                return 0;
            }
        }
    }
    if (ICMPV6 == netInfo.nextProtocol && netInfo.isV6Multicast)
    {
        sendtoAll = true;
    }
    if (netInfo.isV4Broadcast)
    {
        if (netInfo.isARP)
        {
            sendtoAll = true;
        }
        else if ((netInfo.tuple.srcPort == 0x4400) && (netInfo.tuple.dstPort == 0x4300)) // ipv4 dhcp
        {
            sendtoAll = true;
        }
        else
        {
            return 0;
        }
    }
    updateMac(data + 6, param);
    if (sendtoAll)
    {
        sendToAllPort(data, len, param);
    }
    else
    {
        locapPort = findPort(data, netInfo.hashValue);
        LinkParam *localParam = (LinkParam *)locapPort;
        if (localParam != nullptr)
        {
            if (3 == localParam->linkSubType)
            {
                Interface *inter = localParam->interFace;
                int lret = inter->writeData(data, len, &netInfo, 2, param, localParam);
                if (1 != lret)
                {
                    return 0;
                }
                locapPort = findPort(data, netInfo.hashValue);
                localParam->delRef();
                param = localParam;
                localParam = (LinkParam *)locapPort;
                if (localParam == nullptr)
                {
                    return 0;
                }
            }
            tcpFragmentation(localParam, &netInfo, data, len, param);
        }
    }
    if (g_curTime > m_curTime)
    {
        cleanMac(param);
        m_curTime = g_curTime;
    }
    return len;
}

static uint8_t SYNOPT[] = {0x02, 0x04, 0x05, 0x68, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02};
static uint8_t ACKOPT[] = {0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x03, 0x03, 0x07};

const uint16_t g_max_tcp_len = 1384;
const uint8_t *g_max_post = (uint8_t *)&g_max_tcp_len;
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
            if (intemLen > g_max_tcp_len)
            {
                *(opt + 2) = *(g_max_post + 1);
                *(opt + 3) = *g_max_post;
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
    if (notnedd)
    {
        TCPHDR *tcpHead = (TCPHDR *)(netInfo->tcpHead);
        uint16_t oldchecksumb = tcpHead->CheckSum;
        uint16_t neteck = csum_update16(oldchecksumb, htons(intemLen), htons(g_max_tcp_len));
        tcpHead->CheckSum = neteck;
    }
    return totallen;
}

int CHub::tcpFragmentation(void *dstParam, NetInfo *netInfo, uint8_t *data, int len, void *param)
{
    LinkParam *loacalParam = (LinkParam *)dstParam;
    Interface *inter = loacalParam->interFace;
    int adjlen = len;
    if ((1 != loacalParam->linkType) && (netInfo->nextProtocol == IP_TCP_TYPE) && (false == netInfo->tuple.isIPV6))
    {
        uint8_t flag = netInfo->tcpHead->FLAG;
        uint8_t ack = netInfo->tcpHead->FLAG;
        if (0x02 == flag)
        {
            adjlen = findMSS(netInfo, data);
        }
        else if (0x12 == flag)
        {
            adjlen = findMSS(netInfo, data);
        }
    }
    inter->writeData(data, adjlen, 2, param, dstParam);
    loacalParam->delRef();
    return len;
}

int CHub::sendData(void *dstParam, NetInfo *netInfo, uint8_t *data, int len, void *param)
{
    LinkParam *loacalParam = (LinkParam *)dstParam;
    Interface *inter = loacalParam->interFace;
    bool find = true;
    int ret = -1;
    if (len <= 1514)
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

int CHub::updateMac(uint8_t *data, void *param)
{
    if ((0xffffffff == *(uint32_t *)(data)) && (0xffff == (*(uint16_t *)(data + 4))))
    {
        return 0;
    }
    if ((0x0 == *(uint32_t *)(data)) && (0x0 == (*(uint16_t *)(data + 4))))
    {
        return 0;
    }
    IdMapPort *find = findIDPort(param);
    if (find == NULL)
    {
        return 0;
    }

    mac_inter loc(data);
    MACMAPITER iter = m_macMap.find(&loc);

    if (m_macMap.end() == iter)
    {
        mac_inter *newmac = new mac_inter(data);
        newmac->lastTime = g_curTime;
        newmac->m_NotStatic = true;
        newmac->m_ListIter = m_macList.insert(m_macList.end(), newmac);
        newmac->p = find;
        m_macMap.insert(newmac);
        printf("add mac %02X:%02X:%02X:%02X:%02X:%02X id:%d\n", data[0], data[1], data[2], data[3], data[4], data[5], find->m_id);
    }
    else
    {
        mac_inter *oldmac = *iter;
        if (false == oldmac->m_NotStatic)
        {
            return 0;
        }
        if (find != oldmac->p)
        {
            oldmac->p = find;
        }
        if (g_curTime > oldmac->lastTime)
        {
            oldmac->lastTime = g_curTime;
            m_macList.erase(oldmac->m_ListIter);
            oldmac->m_ListIter = m_macList.insert(m_macList.end(), oldmac);
        }
    }
    return 0;
}

int CHub::updateMac(uint8_t *data, void *param, bool staticMac)
{
    IdMapPort *find = findIDPort(param);
    (void)staticMac;
    if (find == NULL)
    {
        return 0;
    }
    mac_inter loc(data);
    MACMAPITER iter = m_macMap.find(&loc);
    if (m_macMap.end() == iter)
    {
        mac_inter *newmac = new mac_inter(data);
        newmac->lastTime = g_curTime;
        newmac->m_NotStatic = false;
        newmac->p = find;
        m_macMap.insert(newmac);
        printf("add static mac %02X:%02X:%02X:%02X:%02X:%02X id:%d\n", data[0], data[1], data[2], data[3], data[4], data[5], find->m_id);
    }
    else
    {
        printf("add static mac Error %02X:%02X:%02X:%02X:%02X:%02X id:%d\n", data[0], data[1], data[2], data[3], data[4], data[5], find->m_id);
    }
    return 0;
}
void *CHub::findPort(uint8_t *data, std::size_t hashCode)
{
    mac_inter loc(data);
    LinkParam *linkParam = NULL;
    MACMAPITER iter;
    void *ret = NULL;

    iter = m_macMap.find(&loc);
    if (m_macMap.end() != iter)
    {
        mac_inter *find = *iter;
        if (find->m_NotStatic && (g_curTime > find->lastTime))
        {
            find->lastTime = g_curTime;
            m_macList.erase(find->m_ListIter);
            find->m_ListIter = m_macList.insert(m_macList.end(), find);
        }
        IdMapPort *item = (IdMapPort *)(find->p);
        linkParam = (LinkParam *)(item->getFrist());
        linkParam->addRef();
        ret = linkParam;
    }
    return ret;
}

void CHub::justAddPort(void *port)
{
    PORTSET::iterator iter = m_portSet.find(port);
    if (m_portSet.end() == iter)
    {
        m_portSet.insert(port);
        LinkParam *localparam = (LinkParam *)port;
        printf("add id port HUB::%s %d\n", __FUNCTION__, __LINE__);
        addIDPort(port);
    }
    else
    {
        printf("alread hava link param HUB::%s %d\n", __FUNCTION__, __LINE__);
    }
}

int CHub::cleanLink(void *param)
{
    LinkParam *localparam = (LinkParam *)param;

    MACMAPITER iterFind;
    PORTSET::iterator postSet;
    int count = 0;
    int count2 = 0;
    bool findItem = false;
    bool findOneItem = false;
    postSet = m_portSet.find(param);
    int cleanma = 0;
    IdMapPort *idmap;
    if (m_portSet.end() != postSet)
    {
        m_portSet.erase(postSet);
        idmap = findIDPort(param);
        cleanma = rmIDPort(param);
        findOneItem = true;
        findItem = cleanma == 1;
    }

    if (findItem)
    {
        MACMAPITER iter = m_macMap.begin();
        MACMAPITER end  = m_macMap.end();
        std::list<mac_inter *> localList;
        for (; iter != end; ++iter)
        {
            IdMapPort *localParam2 = (IdMapPort *)((*iter)->p);
            if (idmap == localParam2)
            {
                count++;
                localList.push_back(*iter);
            }
        }

        std::list<mac_inter *>::iterator iter1 = localList.begin();
        std::list<mac_inter *>::iterator end1 = localList.end();
        for (; iter1 != end1; ++iter1)
        {
            iterFind = m_macMap.find(*iter1);
            if (m_macMap.end() != iterFind)
            {
                IdMapPort *localParam2 = (IdMapPort *)((*iter1)->p);
                if (idmap == localParam2)
                {
                    count2++;
                    if ((*iterFind)->m_NotStatic)
                    {
                        m_macList.erase((*iterFind)->m_ListIter);
                    }
                    m_macMap.erase(iterFind);
                    delete *iter1;
                }
            }
        }
    }
    if (findOneItem)
    {
        int ret = localparam->delRef();
        printf("delete link param %d HUB::%s %d\n", ret, __FUNCTION__, __LINE__);
    }
    return count;
}

int CHub::sendToAllPort(uint8_t *data, int len, void *param)
{
    void *ret = NULL;
    int count = 0;
    IDMAPPORT::iterator iter = m_idMap.begin();
    IDMAPPORT::iterator end = m_idMap.end();
    IdMapPort *find = findIDPort(param);
    if (find == NULL)
    {
        return 0;
    }

    for (; iter != end; ++iter)
    {
        LinkParam *localparam;
        IdMapPort *idmap = *iter;
        if (find != idmap)
        {
            localparam = (LinkParam *)idmap->getFrist();
            localparam->addRef();
            Interface *inter = localparam->interFace;
            inter->writeData(data, len, 1, param, localparam);
            localparam->delRef();
            count++;
        }
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
    icmpTobig->chksum = (uint16_t)~(uint32_t)lwip_standard_chksum(icmpTobig, 8 + netInfo->l3HeadLen + 8);
    int sendLen = 14 + netInfo->otherLen + netInfo->l3HeadLen + 8 + netInfo->l3HeadLen + 8;
    return sendLen;
}

int CHub::initData()
{
    int oneSize = sizeof(HubMidBuf);
    int count = 1000;
    uint8_t *buf = new uint8_t[count * oneSize];
    for (int i = 0; i < count; i++)
    {
        HubMidBuf *lo = (HubMidBuf *)buf;
        lo->len = 0;
        lo->type = 1;
        m_freeList.push(lo);
        buf += oneSize;
    }
    return count;
}

int CHub::sendArp(uint8_t *data, int len, void *param, NetInfo *netinfo)
{
    compact_eth_hdr *pEth = (compact_eth_hdr *)(data);
    uint32_t headLen = 14;
    headLen += netinfo->otherLen;
    arp_hdr *psArp = (arp_hdr *)(data + headLen);
    uint8_t srcmac[6];
    uint8_t dstmac[6];
    LinkParam *srcparam = (LinkParam *)param;
    if (1 == ntohs(psArp->optype))
    {
        memcpy(dstmac, data, 6);
        memcpy(srcmac, data + 6, 6);

        memcpy(data, srcmac, 6);
        memcpy(data + 6, dstmac, 6);

        psArp->optype = htons(2);
        std::swap(psArp->srcip, psArp->dstip);
        memcpy(psArp->dstmac, srcmac, 6);
        memcpy(psArp->srcmac, dstmac, 6);
        srcparam->addRef();
        sendData(srcparam, NULL, data, len, param);
        return 0;
    }
    return 1;
}

int CHub::addIDPort(void *param)
{
    LinkParam *localparam = (LinkParam *)param;
    m_tmpIdMap.m_id = localparam->id;

    IDMAPPORT::iterator it = m_idMap.find(&m_tmpIdMap);
    IdMapPort *item = NULL;
    if (it == m_idMap.end())
    {
        item = new IdMapPort;
        item->m_id = localparam->id;
        item->addPort(param);
        m_idMap.insert(item);
        printf("add id %d HUB::%s %d\n", m_tmpIdMap.m_id, __FUNCTION__, __LINE__);
    }
    else
    {
        item = *it;
        bool find = item->find(param);
        if (find == false)
        {
            item->addPort(param);
        }
        printf("exist id %d szie:%ld HUB::%s %d\n", m_tmpIdMap.m_id, item->m_size, __FUNCTION__, __LINE__);
    }
    return 0;
}

int CHub::rmIDPort(void *param)
{
    LinkParam *localparam = (LinkParam *)param;
    m_tmpIdMap.m_id = localparam->id;
    IDMAPPORT::iterator it = m_idMap.find(&m_tmpIdMap);
    IdMapPort *item = NULL;
    int ret = 0;
    if (it != m_idMap.end())
    {
        item = *it;
        bool find = item->find(param);
        if (find)
        {
            item->delPort(param);
            if (item->isEmpty())
            {
                m_idMap.erase(it);
                delete item;
                printf("clean id %d HUB::%s %d\n", m_tmpIdMap.m_id, __FUNCTION__, __LINE__);
                ret = 1;
            }
        }
    }
    return ret;
}

IdMapPort *CHub::findIDPort(void *param)
{
    LinkParam *localparam = (LinkParam *)param;
    m_tmpIdMap.m_id = localparam->id;
    IDMAPPORT::iterator it = m_idMap.find(&m_tmpIdMap);
    IdMapPort *item = NULL;
    if (it != m_idMap.end())
    {
        item = *it;
    }
    return item;
}

void *CHub::getOneLikelyPort(void *param, std::size_t size)
{
    LinkParam *localparam = (LinkParam *)param;
    m_tmpIdMap.m_id = localparam->id;
    IDMAPPORT::iterator it = m_idMap.find(&m_tmpIdMap);
    IdMapPort *item = NULL;
    if (it != m_idMap.end())
    {
        item = *it;
        return item->getFrist();
    }
    return NULL;
}

int CHub::cleanMac(void *param)
{
    if (m_macList.empty())
    {
        return 0;
    }
    MACMAPLISTITER iter = m_macList.begin();
    mac_inter     *item = *iter;

    if (g_curTime - item->lastTime > 1800)
    {
        IdMapPort *localparam = (IdMapPort *)(item->p);
        if (NULL == localparam)
        {
            return 0;
        }
        MACMAPITER it = m_macMap.find(item);
        uint8_t *mac = item->getMac();
        if (it != m_macMap.end())
        {
            m_macMap.erase(it);
            m_macList.erase(iter);
            printf("clean mac %02X:%02X:%02X:%02X:%02X:%02X id:%d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], localparam->m_id);
            delete item;
        }
        else
        {
            printf("error clean mac %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
        return 1;
    }
    return 0;
}