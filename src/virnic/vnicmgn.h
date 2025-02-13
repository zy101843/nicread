#pragma once 
#include "../common.h"
#include "../interface.h"
#include "../NetModeBase.h"
#include "CVirtualNic.h"
#include <thread>

class VNicMgn : public Interface
{
public:
    VNicMgn();
    virtual ~VNicMgn();
   
public:
    virtual int writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam);

public:
    void start();
    void stop();
    void setName(const std::string &name, const std::string &ip, const std::string &mask);

private:
    void workThread();

private:
    CVirtualNic *m_nic;
    std::thread *m_monitorTread;
    bool m_stop;
    LinkParam m_linkParm;
};
