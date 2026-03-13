#include "config.h"
#include "xml/pugixml.hpp"
#include <cstring>

config::config(/* args */)
{
    m_sevice = false;
    m_clinet = false;
    m_vir    = false;
    m_filter = false;
    m_opennat = false;
    m_openRoute = false;
}

config::~config()
{

}

void generate_random_mac(unsigned char *mac) {
    srand(time(NULL));
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() % 256;
    }
    mac[0] &= 0xFC; 
}

bool config::readConfig(const char *path)
{
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_file(path);
    if (!result)
    {
        return false;
    }
    pugi::xml_node root = doc.child("config");   
    pugi::xml_node node = root.first_child();
    pugi::xml_attribute attr;
    for(; node; node = node.next_sibling())
    {
        if(strcmp(node.name(), "service") == 0)
        {
            ipPort *cli = new ipPort;
            cli->ip   = node.attribute("ip").value();
            cli->port = node.attribute("port").as_uint();
            m_serviceips.insert(cli);
            m_sevice = true;
            attr = node.attribute("key");
            if(attr)
            {
                cli->keyPath = attr.value();
            }
            else 
            {
                cli->keyPath = "private_key.pem";
            }
        }
        else if (strcmp(node.name(), "client") == 0)
        {
            ipPort *cli = new ipPort;
            cli->ip   = node.attribute("ip").value();
            cli->port = node.attribute("port").as_uint();
            cli->bindport = 0;
            cli->count    = 1;
            cli->id       = 0;
            attr = node.attribute("mac");

            if (attr)
            {
                int ret = sscanf(attr.value(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &cli->mac[0], &cli->mac[1], &cli->mac[2], &cli->mac[3], &cli->mac[4], &cli->mac[5]);
                if (6 != ret)
                {
                    memset(cli->mac, 0, 6);
                }
            }
            else
            {
                memset(cli->mac, 0, 6);
            }

            if (node.attribute("bindport"))
            {
                cli->bindport = node.attribute("bindport").as_uint();
            }

            attr = node.attribute("id");
            if(attr)
            {
                cli->id = attr.as_uint();
                printf("client id :%u\n", cli->id);
            }
            else
            {
                srand(time(NULL));
                cli->id = rand();
                printf("client no id , generate random id:%u\n", cli->id);
            }
            while (cli->id < 1000)
            {
                cli->id = rand();
            }

            attr = node.attribute("count");
            if (attr)
            {
                cli->count = attr.as_uint();
            }
            attr = node.attribute("key");
           
            if(attr)
            {
                cli->keyPath = attr.value();
            }
            else 
            {
                cli->keyPath = "public_key.pem";
            }

            m_clients.insert(cli);
            m_clinet = true;
        }
        else if (strcmp(node.name(), "nic") == 0)
        {
            m_vir = node.attribute("vir").as_bool();
            m_nicname = node.attribute("name").value();
            attr = node.attribute("ip");
            if (attr)
            {
                m_virip = attr.value();
            }
            attr = node.attribute("mask");
            if(attr)
            {
                m_virmask = attr.value();
            }
            attr = node.attribute("filter");
            if(attr)
            {
                m_filter = attr.as_bool();
            }
            attr = node.attribute("mac");
            if(attr)
            {
               int ret = sscanf(attr.value(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m_virMac[0], &m_virMac[1], &m_virMac[2], &m_virMac[3], &m_virMac[4], &m_virMac[5]);  
               if(6 !=ret)
               {
                    generate_random_mac(m_virMac);
               }
            }
            else 
            {
                generate_random_mac(m_virMac);
            }
        }
        else if(strcmp(node.name(), "darp") ==0)
        {
            pugi::xml_node subnode = node.first_child();
            pugi::xml_attribute macattr;
            for (; subnode; subnode = subnode.next_sibling())
            {
                macattr = subnode.attribute("mac");
                if (macattr)
                {
                    unsigned char mac[6];
                    sscanf(macattr.value(), "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
                    uint8_t *buf = new uint8_t[6];
                    memcpy(buf ,mac, 6);
                    m_darpMac.push_back(buf);
                }
            }
        }
        else if(strcmp(node.name(), "nat") ==0)
        {
            m_opennat = node.attribute("open").as_bool();
        }
        else if(strcmp(node.name(), "route") ==0)
        {
            m_openRoute = node.attribute("open").as_bool();
        }
    }
    return true;
}
