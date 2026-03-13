#include "routetable.h"
#include <fstream>
#include <arpa/inet.h>

routetable::routetable(/* args */)
{
}

routetable::~routetable()
{
}
int routetable::setDefaultMac(const char *mac, const char *lacolmac)
{
    memcpy(m_defaultMac, mac, 6);
    memcpy(m_Notfind,    mac, 6);
    memcpy(m_Notfind+6, lacolmac, 6);
     printf("default %hhx:%hhx:%hhx:%hhx:%hhx:%hhx  %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", m_Notfind[0], m_Notfind[1], m_Notfind[2], m_Notfind[3], m_Notfind[4], m_Notfind[5],
        m_Notfind[6], m_Notfind[7], m_Notfind[8], m_Notfind[9], m_Notfind[10], m_Notfind[11]);
    return 0;
}

std::size_t removeData(std::string &str)
{
    std::size_t len = str.length();
    std::string result;
    const char *p = str.c_str();
    const char *end = p + len;
    for (; p != end; p++)
    {
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p == '.' || *p == '/'))
        {
            result += *p;
        }
    }
    str = result;
    return result.length();
}

int routetable::addRoute(std::string path, const char *mac)
{
    std::fstream file(path);
    uint32_t gw = m_macTable.size();
    if (!file.is_open())
    {
        printf("open file error\n");
        return -1;
    }
    TrieTree *tree = new TrieTree();
    tree->m_path = path;
    int prefixlen = 0;
    std::string line;
    int count = 0;
    while (std::getline(file, line))
    {
        count++;
        removeData(line);
        if (line.empty())
        {
            continue;
        }
        size_t pos = line.find('/');
        if (pos == std::string::npos)
        {
            continue;
        }
        std::string ipstr  = line.substr(0, pos);
        std::string lenstr = line.substr(pos + 1);
        uint32_t ip = inet_addr(ipstr.c_str());
        int len = atoi(lenstr.c_str());
        if (len <= 0 || len > 32)
        {
            continue;
        }
        uint32_t  prefix = 0;
        uint32_t  locaIp = ntohl(ip);
        TrieNode *find   = tree->search(locaIp, prefixlen);
       
        if (find != nullptr && prefixlen <= len)
        {
            printf("have find %s\n", line.c_str());
            continue;
        }
        char *findmac = findRoute(ip);
        if (findmac != m_Notfind)
        {
            printf("have find same mac %s  %d %s\n", path.c_str(), count,  line.c_str());
            continue;
        }
        tree->insert(locaIp, len, gw);
    }
    file.close();
    m_macTable.push_back((char *)mac);
    m_routeTable.push_back(tree);
    m_end = m_routeTable.end();
    printf("%s  user %d \n", path.c_str(), tree->m_user);
    return 0;
}

char *routetable::findRoute(uint32_t ip)
{
    ROUTEITER iter = m_routeTable.begin();
    int prefixlen = 0;
    for (; iter != m_end; iter++)
    {
        TrieTree *node = *iter;
        TrieNode *ret  = node->search(ip, prefixlen);
        if (ret != nullptr)
        {
            if (prefixlen < 32 || (prefixlen == 32 && ip == ret->ip))
            {
                int gw = ret->gwip;
                if (gw < 0 || gw >= (int)m_macTable.size())
                {
                    return m_Notfind;
                }
                return m_macTable[gw];
            }
        }
    }
    return m_Notfind;
}
