#pragma once
#include <cstdint>
class upCheckSum
{
public:
    int updateCheckSum(uint8_t *iphead, uint8_t *outherHea, int type, int dir, uint32_t new_ip, uint16_t new_port);
    int operator()(uint8_t *iphead, uint8_t *outherHea, int type, int dir, uint32_t new_ip, uint16_t new_port);
private:
    void nat_update_ip_checksum();
    void nat_update_checksum_ip_port();
private:
    uint8_t  *ip_hdr;
    uint32_t new_ip;
    uint32_t *ipoffset;
    uint8_t  *l4_hdr_and_payload;
    uint16_t new_port;
    uint16_t *portoffset;
    uint16_t *sumOffset;
};