#pragma once 
#include <stdint.h>
#include "commtype.h"
char *refind(char find, char *buf, int len, int rebegin);
uint16_t ls_atoi(uint8_t *buf, int len);
uint32_t l_atoi(uint8_t *buf, int len);
uint64_t ll_atoi(uint8_t *buf, int len);
int buf_ipv6(uint8_t *buf, int len, ip_tr_addr &add);
int str_ip(uint8_t *buf, int len, ip_tr_addr &add);
uint32_t hashFun(ip_tr_addr *ip);
uint32_t hashFun(IPANDPORT &tuple, int &type);
void createDir(const char *pPath);
bool fileExits(char *fileName);
uint32_t alignment64bitSize(uint32_t t);
uint32_t getBit(uint32_t input, uint32_t &size);
int WriteFileAddStr(char *pFilePath, char *pData, int nDataLen);
