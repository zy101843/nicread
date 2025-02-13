#pragma once
#include <iostream>
#include <memory.h>
#include <mutex>
#include <vector>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>

#define  LOGCFGFILE  "./etc/log4cplus.properties"
#define  CONFIGFILE  "./etc/ConfigFile.xml"
#define  MIDBUFSIZE   10485760 //10M 
#define  LF (uint8_t) '\n'
#define  CR (uint8_t) '\r'
#define  CRLF         "\r\n"
#define  SLASH        '/'

#define MAX_IMSI_SIZE   24
#define MAX_BSID_SIZE   24
#define MAX_APN_SIZE    32
#define MAX_MSISDN_SIZE 24
#define ULI_SIZE        8
#ifndef MAX_ULI_SIZE
#define MAX_ULI_SIZE    24
#endif
#define MAX_RAI_SIZE    15
#define MAX_IMEI_SIZE   24

#define MAX_CELLIDLEN   8
#define MAX_USERZONELEN 8
#define MAX_PATH        255
#define IP6_ADDRSTR_LEN 48

#define BUF_TO_UINT(buf) ( (uint32_t)( (((uint8_t *)(buf))[0]<<24) | (((uint8_t *)(buf))[1]<<16) | (((uint8_t *)(buf))[2]<<8) | (((uint8_t *)(buf))[3]) ) )
#define BUF_TO_WORD(buf) ( (uint16_t)( (((uint8_t *)(buf))[0]<<8) | (((uint8_t *)(buf))[1]) ) )


#define NOTICE(p) {             \
    do{                         \
        std::cout << p;         \
        std::cout<< std::endl;  \
     }while(0);                 \
}

#define MESSAGEHEAD_LEN 4

template <typename T>
void hash_combine(std::size_t& seed, const T& v) {
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);  
}
