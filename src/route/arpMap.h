#pragma once

#include "../common.h"
#include "../tcpiphead.h"
#include <unordered_map>

class CARPHash
{
public:
    std::size_t operator()(const IPTYPE *ip) const
    {
        std::size_t seed = 0u;
        hash_combine(seed, ip->ip.v6[0]);
        hash_combine(seed, ip->ip.v6[1]);
        hash_combine(seed, ip->ip.v6[2]);
        hash_combine(seed, ip->ip.v6[3]);
        return seed;
    }
};

class CIPArpCmp
{
public:
    bool operator()(const IPTYPE *ip1, const IPTYPE *ip2) const
    {
        bool res = false;
        res = (0 == memcmp(ip1->ip.v6, ip2->ip.v6, 16));
        return res;
    }
};

class CArpMap
{
public:
    CArpMap();
    ~CArpMap();
public:
    typedef std::unordered_map<IPTYPE *, uint8_t *, CARPHash, CIPArpCmp> ARPMAP;
    typedef ARPMAP::iterator                        ARPMAPITER;
public:
    bool addItemV4(IPTYPE &ip, uint8_t* mac);
    bool addItemV6(IPTYPE &ip, uint8_t* mac);
    uint8_t *findV4(IPTYPE &ip);
    uint8_t *findV6(IPTYPE &ip);
private:
    ARPMAP      m_v4Arp;
    ARPMAP      m_v6Arp;
    ARPMAPITER  m_iter;


};

