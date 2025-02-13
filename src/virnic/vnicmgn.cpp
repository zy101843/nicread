#include "vnicmgn.h"
#include "../hub/hub.h"
#include <functional>



VNicMgn::VNicMgn()
{
    m_nic   = NULL;
    m_stop  = true;
    m_type  = 1;
    m_linkParm.interFace = this;
    m_linkParm.linkType  = 1;
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

void VNicMgn::setName(const std::string &name, const std::string &ip, const std::string &mask)
{
    m_nic = new CVirtualNic();
    m_nic->Create(name, ip, mask);
}


void VNicMgn::workThread()
{
    uint8_t *data;
    int len;
    CHub *hub = (CHub*)m_hub;
    hub->addData(NULL, -1, &m_linkParm);
    while (m_stop)
    {
        len = -1;
        data =  m_nic->readData(len);
        if (len > 1514)
        {
            printf("read len error %d  %s %d  \n", len, __FILE__, __LINE__);
        }
        if (len < 0)
        {
            continue;
        }
        hub->addData(data, len, &m_linkParm);
    }
}

int VNicMgn::writeData(uint8_t * data, int len, int type,  void *srcparam, void *dstParam)
{
    //return 0;
    int wlen;
    if (type == 3)
    {
        wlen = m_nic->writeData(data, len);
        return wlen;
    }
    if (srcparam == dstParam)
    {
        return 0;
    }
    if(len > 1500)
    {
        printf("data len is %d\n", len);
    }
    wlen = m_nic->writeData(data, len);
    if (len != wlen)
    {
        printf("error writeData %d\n", wlen);
    }
    return wlen;
}