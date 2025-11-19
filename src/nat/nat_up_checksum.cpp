#include <netinet/in.h>
#include "../tcpiphead.h"
#include "../util/utility_net.h"
#include "nat_up_checksum.h"


void upCheckSum::nat_update_ip_checksum()
{
    uint16_t old_csum = *(uint16_t *)(ip_hdr + 10);
    uint32_t old_ip   = *(ipoffset);
    uint16_t new_csum = csum_update32(old_csum, old_ip, new_ip);
    *(uint16_t *)(ip_hdr + 10) = new_csum;
    *(ipoffset) = new_ip;
}

void upCheckSum::nat_update_checksum_ip_port()
{
    uint32_t old_ip   = *(ipoffset);
    uint16_t old_csum = *(sumOffset);
    uint16_t new_csum = csum_update32(old_csum, old_ip, new_ip);
    uint16_t old_port = *(portoffset);
    new_csum = csum_update16(new_csum, old_port, new_port);
    *(portoffset) = new_port;
    *(sumOffset)  =  new_csum;
}
// type is 1 chang src ; ip 2 change dst 
int upCheckSum::updateCheckSum(uint8_t *iphead, uint8_t *outherHea, int type, int dir, uint32_t new_ip, uint16_t new_port)
{
    this->ip_hdr             = iphead;
    this->l4_hdr_and_payload = outherHea;
    this->new_ip             = new_ip;
    this->new_port           = new_port;

    if (dir == 1)
    {
        ipoffset   = (uint32_t*)(iphead + 12);
        portoffset = (uint16_t*)outherHea;
    }
    else
    {
        ipoffset   = (uint32_t*)(iphead + 16);
        portoffset = (uint16_t*)(outherHea + 2);
    }
    bool port = false;
    if (type == 6)
    {
        sumOffset = (uint16_t*)(outherHea + 16);
        port = true;
    }
    else if (type == 0x11)
    {
        sumOffset = (uint16_t*)(outherHea + 6);
        port = true;
    }

    if (port)
    {
        nat_update_checksum_ip_port();
    }
    nat_update_ip_checksum();
    return 0;
}

int upCheckSum::operator()(uint8_t *iphead, uint8_t *outherHea, int type, int dir, uint32_t new_ip, uint16_t new_port)
{
    return updateCheckSum(iphead, outherHea, type, dir, new_ip, new_port);
}
