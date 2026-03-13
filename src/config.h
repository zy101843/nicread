#pragma once

#include <stdint.h>
#include <string>
#include <set>
#include <vector>

struct ipPort
{
    std::string ip;
    uint16_t    port;
    uint16_t    bindport;
    uint8_t     mac[6];
    int         count;
    uint32_t    id;
    std::string keyPath;
};

class config
{
private:

public:
    config();
    ~config();
public:
    bool readConfig(const char *path);
    public:
    std::set<ipPort*> m_serviceips;
    bool        m_sevice;
    std::set<ipPort*> m_clients;
    bool        m_clinet;

    bool         m_vir;
    bool         m_filter;
    std::string  m_nicname;
    std::string  m_virip;
    std::string  m_virmask;
    uint8_t      m_virMac[16];
    std::vector<uint8_t *> m_darpMac;
    bool         m_opennat;
    bool         m_openRoute;
};

