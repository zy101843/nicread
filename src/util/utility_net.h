#pragma once
#include <stdint.h>
uint16_t inet_chksum(const void *dataptr, uint16_t len);
uint16_t lwip_standard_chksum(const void *dataptr, int len);
uint16_t ip6_chksum_pseudo(uint8_t *p, uint32_t len, uint8_t proto, uint16_t proto_len, const uint32_t *src, const uint32_t *dest);
uint16_t inet_chksum_pseudo(uint8_t *p, uint8_t proto, uint16_t proto_len, const uint32_t *src, const uint32_t *dest);
int encrypt(uint8_t *data, int len);
uint32_t fold_sum(uint32_t sum);
uint16_t csum_update16(uint16_t old_checksum, uint16_t old_val, uint16_t new_val);
uint16_t csum_update32(uint16_t old_checksum, uint32_t old_val, uint32_t new_val);
int analysisIPHead(uint8_t *data, int len, NetInfo *netInfo);
int analysisL4Head(NetInfo *netInfo, uint8_t *data, int len);  
void AdjustIPHeadV4(NetInfo *netInfo, uint8_t *data);