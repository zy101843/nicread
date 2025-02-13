#pragma once
#include "common.h"
#include "tcpiphead.h"

#define APP_LEN   900
#define LINK_INFO 901
#define DNS_ANS   902

enum PROTOTYPE
{
    PROTOTYPE_HTTP   = 1,
    PROTOTYPE_UPDATA = 2,
    PROTOTYPE_HTTPS  = 3,
    PROTOTYPE_NIC    = 4,
    PROTOTYPE_MAX
};

struct ListenItem
{
    ListenItem() {}
    ListenItem(const char *ip, uint16_t port, PROTOTYPE type) {
        this->ip   = ip;
        this->port = port;
        this->type = type;
    }
    std::string  ip;
    uint16_t     port;
    PROTOTYPE    type;
    int          linstType;
    bool         open;
};

struct DIRMONITOR
{
    std::string pathName;
    std::vector<std::string> skipformat;
    std::vector<std::string> skipdir;
    std::string backpath;
    int skipdep;
    int minfree;
};

struct LinkHashParam
{
    uint32_t size;
    uint32_t exitcount;
    uint32_t m_mask;
    uint32_t m_bit;
};


#pragma pack(1)
typedef union
{
    struct {
        uint16_t sport;
        uint16_t dport;
    } port;
    uint32_t sdport;
}conn_port;


struct IPANDPORT
{
    ip_tr_addr srcIP;
    ip_tr_addr dstIP;
    conn_port  port;
    uint16_t   protcol;
    bool       isIPV6;
    IPANDPORT()
    {
        isIPV6 = false;
    }
};
#pragma pack()
