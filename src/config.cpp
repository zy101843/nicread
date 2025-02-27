#include "config.h"
#include "xml/pugixml.hpp"
#include <cstring>

config::config(/* args */)
{
    m_sevice = false;
    m_clinet = false;
    m_vir    = false;
}

config::~config()
{

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
            m_serviceip = node.attribute("ip").value();
            m_sport     = node.attribute("port").as_uint();
            m_sevice    = true;
        }
        else if(strcmp(node.name(), "client") == 0)
        {
            client *cli = new client;
            cli->m_clientip = node.attribute("ip").value();
            cli->m_cport    = node.attribute("port").as_uint();
            m_clients.insert(cli);
            m_clinet   = true;
        }
        else if(strcmp(node.name(), "nic") == 0)
        {
            m_vir     = node.attribute("vir").as_bool();
            m_nicname = node.attribute("name").value();
            attr = node.attribute("ip");
            if(attr)
            {
                m_virip = attr.value();
            }
            attr = node.attribute("mask");
            if(attr)
            {
                m_virmask = attr.value();
            }
        }
    }
    return true;
}