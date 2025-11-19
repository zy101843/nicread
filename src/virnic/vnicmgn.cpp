#include "vnicmgn.h"
#include "../hub/hub.h"
#include <functional>




VNicMgn::VNicMgn()
{
    m_nic   = NULL;
    m_stop  = true;
    m_type  = 1;
    m_linkParm.interFace   = this;
    m_linkParm.linkType    = 1;
    m_linkParm.linkSubType = 2;
    m_linkParm.id           = 2;
}

VNicMgn::~VNicMgn()
{
}

void VNicMgn::start()
{
    if (-1 != m_nic->open())
    {
        m_monitorTread   = new std::thread(std::bind(&VNicMgn::workThread, this));
    }
}

void VNicMgn::stop()
{
    m_stop = false;
}


unsigned char g_map[] ={ 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0x84, 0x46, 0xfe, 0x66, 0xaf, 0xb3, 
    0x8,  0x6, 
    0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 
    0x84, 0x46, 0xfe, 0x66, 0xaf, 0xb3, 
    0xc0, 0xa8, 0xc8, 0x4, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0xc0, 0xa8, 0xc8, 0x04, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };


void VNicMgn::setName(const std::string &name, const std::string &ip, const std::string &mask, const uint8_t *mac)
{
    m_name = name;
    m_ip = ip;
    m_mask = mask;
    memcpy(m_mac, mac, 6);
    open();
}

void VNicMgn::open()
{
    m_nic = new CVirtualNic();
    m_nic->Create(m_name, m_ip, m_mask, m_mac);
    //m_nic->m_mac;

   uint32_t ip123 = inet_addr(m_ip.c_str());
   memcpy(g_map+6, m_nic->m_mac, 6);
   memcpy(g_map + 14 + 8, m_nic->m_mac, 6);

   *((uint32_t*)(g_map + 14 + 8 + 6))       = ip123;
   *((uint32_t*)(g_map + 14 + 8 + 6 +4 + 6)) = ip123;
}



void VNicMgn::workThread()
{
    uint8_t *data;
    int len;
    m_linkParm.m_ext = g_map;
    m_hub->addData(NULL, -1, &m_linkParm);
    int count = 0;
    while (m_stop)
    {
        len = -1;
        data =  m_nic->readData(len);
        if (len > 1514)
        {
            printf("read len error %d  %s %d  \n", len, __FILE__, __LINE__);
            continue;
        }
        if (len <= 0)
        {
            printf("read len error %d  %s %d  \n", len, __FILE__, __LINE__);
            delete m_nic;
            open();
            continue;
        }
        
        m_hub->addData(data, len, &m_linkParm);
        count++;

        if(count > 10000)
        {
            m_hub->addData(g_map, 60, &m_linkParm);
            count = 0;
        }
    }
}

int VNicMgn::writeData(uint8_t * data, int len, int type,  void *srcparam, void *dstParam)
{
    //return 0;
    int wlen;
    if (srcparam == dstParam)
    {
        return 0;
    }
    if(len > 1514)
    {
        printf("data len is %d\n", len);
        return 0;
    }
    wlen = m_nic->writeData(data, len);
    if (len != wlen)
    {
        printf("error writeData %d\n", wlen);
    }
    return wlen;
}