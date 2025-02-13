#pragma once

#include <stdint.h>
#include <string>
class config
{
private:

public:
    config();
    ~config();
public:
    bool readConfig(const char *path);
    public:
    std::string m_serviceip;
    uint16_t    m_sport;
    bool        m_sevice;

    std::string m_clientip;
    uint16_t    m_cport;
    bool        m_clinet;

    bool         m_vir;
    std::string  m_nicname;
    std::string  m_virip;
    std::string  m_virmask;
};

