#pragma once 
#include "trietree.h"
#include <vector>
#include <string>
#include <string.h>

class routetable
{
public:
    typedef std::vector<TrieTree *> ROUTEVECTOR;
    typedef ROUTEVECTOR::iterator   ROUTEITER;
    typedef std::vector<char *>     MACVECTOR;
    typedef MACVECTOR::iterator MACITER;

private:

public:
    routetable();
    ~routetable();
public:
    int   addRoute(std::string path, const char *mac);
    char *findRoute(uint32_t ip);

private:
    ROUTEVECTOR m_routeTable;
    MACVECTOR   m_macTable;
    char        m_defaultMac[6];
    ROUTEITER    m_end; 
};
