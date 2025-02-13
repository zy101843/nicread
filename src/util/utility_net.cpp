#include "utility_net.h"
#include <arpa/inet.h>

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