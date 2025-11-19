#include <netinet/in.h>
#include "tcpiphead.h"
#include "utility_net.h"
#include <arpa/inet.h>
#include <memory.h>

#ifndef SWAP_BYTES_IN_WORD
#define SWAP_BYTES_IN_WORD(w) (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8)
#endif 

#ifndef FOLD_U32T
#define FOLD_U32T(u)          ((uint32_t)(((u) >> 16) + ((u) & 0x0000ffffUL)))
#endif



uint16_t lwip_standard_chksum(const void *dataptr, int len)
{
    uint32_t acc;
    uint16_t src;
    const uint8_t *octetptr;

    acc = 0;
    octetptr = (const uint8_t *)dataptr;
    while (len > 1)
    {
        src = (*octetptr) << 8;
        octetptr++;
        src |= (*octetptr);
        octetptr++;
        acc += src;
        len -= 2;
    }
    if (len > 0) 
    {
       
        src = (*octetptr) << 8;
        acc += src;
    }
   
    acc = (acc >> 16) + (acc & 0x0000ffffUL);
    if ((acc & 0xffff0000UL) != 0) 
    {
        acc = (acc >> 16) + (acc & 0x0000ffffUL);
    }
    return htons((uint16_t)acc);
}
uint16_t inet_chksum(const void *dataptr, uint16_t len)
{
    return (uint16_t)~(unsigned int)lwip_standard_chksum(dataptr, len);
}
uint16_t inet_cksum_pseudo_base(uint8_t *p, uint32_t len, uint8_t proto, uint16_t proto_len, uint32_t acc)
{
    int swapped = 0;
    acc += lwip_standard_chksum(p, len);
    acc = FOLD_U32T(acc);
    if (len % 2 != 0)
    {
        swapped = !swapped;
        acc = SWAP_BYTES_IN_WORD(acc);
    }
    if (swapped)
    {
        acc = SWAP_BYTES_IN_WORD(acc);
    }
    acc += (uint32_t)htons((uint16_t)proto);
    acc += (uint32_t)htons(proto_len);
    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc);
    return (uint16_t)~(acc & 0xffffUL);
}

uint16_t ip6_chksum_pseudo(uint8_t *p, uint32_t len, uint8_t proto, uint16_t proto_len, const uint32_t *src, const uint32_t *dest)
{
    uint32_t acc = 0;
    uint32_t addr;
    uint8_t  addr_part;

    for (addr_part = 0; addr_part < 4; addr_part++) 
    {
        addr = src[addr_part];
        acc = (uint32_t)(acc + (addr & 0xffffUL));
        acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
       
        addr = dest[addr_part];
        acc = (uint32_t)(acc + (addr & 0xffffUL));
        acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    }
    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc);
    return inet_cksum_pseudo_base(p, len, proto, proto_len, acc);
}

uint16_t ip6_chksum_pseudo(uint8_t *p, uint8_t proto, uint16_t proto_len, const uint32_t *src, const uint32_t *dest)
{
    uint32_t acc = 0;
    uint32_t addr;
    uint8_t  addr_part;

    for (addr_part = 0; addr_part < 4; addr_part++)
    {
        addr = src[addr_part];
        acc  = (uint32_t)(acc + (addr & 0xffffUL));
        acc  = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));

        addr = dest[addr_part];
        acc  = (uint32_t)(acc + (addr & 0xffffUL));
        acc  = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    }
    acc = FOLD_U32T(acc);
    acc = FOLD_U32T(acc);

    return inet_cksum_pseudo_base(p, proto_len, proto, proto_len, acc);
}
uint16_t inet_chksum_pseudo(uint8_t *p, uint8_t proto, uint16_t proto_len,   const uint32_t *src, const uint32_t *dest)
{
    uint32_t acc;
    uint32_t addr;
    addr = *src;
    acc  = (addr & 0xffffUL);
    acc  = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    addr = *dest;
    acc  = (uint32_t)(acc + (addr & 0xffffUL));
    acc  = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
    acc  = FOLD_U32T(acc);
    acc  = FOLD_U32T(acc);
    return inet_cksum_pseudo_base(p, proto_len, proto, proto_len, acc);
}

int encrypt(uint8_t *data, int len)
{
    uint32_t cout1 = len;
    uint32_t midT  = cout1 & 0x03;
    cout1 >>= 2;
    if (0 != midT)
    {
        cout1++;
    }
    uint8_t *dataend = data + len;
    uint32_t oth;
    oth  = *((uint32_t *)(dataend));


    uint32_t *post    = (uint32_t *)data;

    uint32_t datalen  = (uint32_t)len;
    datalen <<=  16;
    datalen  |=  len;

    uint32_t key1 = 0x5AA5A55A;
    for (uint32_t i = 0; i < cout1; i++)
    {
        key1 = i;
        key1 <<= 8;
        key1 |= i;
        key1 <<= 8;
        key1 |= i;
        key1 <<= 8;
        key1 |= i;
        key1 ^=  0x5AA5A55A;
        *post  = *post ^ (key1 ^ datalen);
        key1++;
        post++;
    }

    *((uint32_t *)(dataend)) = oth;
    return len;
}

uint32_t fold_sum(uint32_t sum)
{
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return sum;
}

// 增量更新校验和（修改一个16位字段）
uint16_t csum_update16(uint16_t old_checksum,
                       uint16_t old_val,
                       uint16_t new_val)
{
    uint32_t sum = ~old_checksum & 0xFFFF;
    sum += (~old_val & 0xFFFF) + new_val;
    sum = fold_sum(sum);
    return ~sum;
}

uint16_t csum_update32(uint16_t old_checksum,
                       uint32_t old_val,
                       uint32_t new_val)
{
    uint32_t sum = ~old_checksum & 0xFFFF;
    sum += (~(old_val >> 16) & 0xFFFF) + (new_val >> 16);
    sum += (~(old_val & 0xFFFF) & 0xFFFF) + (new_val & 0xFFFF);
    sum = fold_sum(sum);
    return ~sum;
}


static uint8_t BroadcastMac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t V6Multicast[]  = {0x33, 0x33};
static uint8_t IPv4mcast[]    = {0x01, 0x00, 0x5e};

int analysisIPHead(uint8_t *data, int len, NetInfo *netInfo)
{
    netInfo->isARP = false;
    netInfo->isGood = false;
    netInfo->hashValue = 0;
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
    netInfo->tuple.restIp();
    switch (eth_type)
    {
    case 0x0800:
    {
        if (buffer_len < (l3_offset + sizeof(struct compact_ip_hdr)))
        {
            //printf("ipv4  error %d\n", buffer_len);
            return 0;
        }
        netInfo->ipv4Head = (struct compact_ip_hdr *)&buffer[l3_offset];
        netInfo->l3head   = (uint8_t *)(netInfo->ipv4Head);
        netInfo->tuple.srcIP.v4 = ntohl(netInfo->ipv4Head->saddr);
        netInfo->tuple.dstIP.v4 = ntohl(netInfo->ipv4Head->daddr);
        netInfo->tuple.isIPV6 = false;
        netInfo->nextProtocol = netInfo->ipv4Head->protocol;
        netInfo->tuple.protcol = netInfo->nextProtocol;
        netInfo->l3HeadLen = netInfo->ipv4Head->ihl * 4;
        netInfo->totalLen = htons(netInfo->ipv4Head->tot_len);
        netInfo->ipv4Len = len - netInfo->l3HeadLen;
        netInfo->isGood = true;
        break;
    }
    case 0x86DD:
    {
        if (buffer_len < (l3_offset + sizeof(struct compact_ipv6_hdr)))
        {
            return 0;
        }
        netInfo->ipv6Head = (struct compact_ipv6_hdr *)&buffer[l3_offset];
        netInfo->l3head   = (uint8_t *)(netInfo->ipv6Head);
        memcpy(netInfo->tuple.srcIP.v6, &(netInfo->ipv6Head->saddr), 16);
        memcpy(netInfo->tuple.dstIP.v6, &(netInfo->ipv6Head->daddr), 16);
        netInfo->nextProtocol = netInfo->ipv6Head->nexthdr;
        netInfo->tuple.protcol = netInfo->nextProtocol;
        netInfo->totalLen = htons(netInfo->ipv6Head->payload_len);
        netInfo->ipv4Len = netInfo->totalLen;
        netInfo->tuple.isIPV6 = true;
        netInfo->l3HeadLen = 40;
        netInfo->isGood =  true;
        break;
    }
    case 0x0806:
    {
        netInfo->l3HeadLen = 0;
        netInfo->isARP = true;
        netInfo->totalLen = 20;
        netInfo->isGood = true;
        break;
    }
    default:
    {
        return 0;
    }
    }
    return 1;
}

int analysisL4Head(NetInfo *netInfo, uint8_t *data, int len)
{
    uint32_t headLen = 14 + netInfo->otherLen + netInfo->l3HeadLen;
    uint32_t local;
    uint32_t truelen;
    uint8_t *recData = data;

    uint32_t seed1;
    uint32_t seed2;
    switch (netInfo->nextProtocol)
    {
    case IP_UDP_TYPE:
    {
        netInfo->udpHead = (UDPHDR *)(recData + headLen);
        netInfo->l4head   = (uint8_t *)(netInfo->udpHead);
        netInfo->tuple.srcPort = netInfo->udpHead->SrcPort;
        netInfo->tuple.dstPort = netInfo->udpHead->DesPort;
        
        seed1 = (netInfo->tuple.srcIP.v4) ^(netInfo->tuple.dstIP.v4);
        seed2 = (netInfo->tuple.srcPort) ^(netInfo->tuple.dstPort);
        netInfo->hashValue = seed1 ^ seed2 ;
        netInfo->l4headlLen = 8;
        break;
    }
    case IP_TCP_TYPE:
    {
        netInfo->tcpHead = (TCPHDR *)(recData + headLen);
        netInfo->l4head   = (uint8_t *)(netInfo->tcpHead);
        netInfo->tuple.srcPort = netInfo->tcpHead->SrcPort;
        netInfo->tuple.dstPort = netInfo->tcpHead->DesPort;
        
        seed1 = (netInfo->tuple.srcIP.v4) ^(netInfo->tuple.dstIP.v4);
        seed2 = (netInfo->tuple.srcPort) ^(netInfo->tuple.dstPort);
        netInfo->hashValue = seed1 ^ seed2 ;
    
        netInfo->l4headlLen = (netInfo->tcpHead->hdLen * 4);
        break;
    }
    default:
    {
        break;
    }
    }
    return 1;
}

void AdjustIPHeadV4(NetInfo *netInfo, uint8_t *data)
{
    uint8_t *sendData = data;
    compact_ip_hdr *ip = (compact_ip_hdr *)(sendData + 14 + netInfo->otherLen);
    ip->check = 0;
    ip->check = (uint16_t)(~(uint32_t)lwip_standard_chksum(ip, ip->ihl * 4));
}

