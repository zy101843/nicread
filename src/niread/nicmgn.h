#pragma once 
#include "../common.h"
#include "../interface.h"
#include "readnic.h"
#include "../NetModeBase.h"
#include <thread>

class NicMgn :public Interface
{
public:
    NicMgn();
   virtual ~NicMgn();
public:
    virtual int writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam);
public:
    void start();
    void stop();
    void setName(const std::string &name);
private:
    void workThread();
private:
    nic_proc        *m_nic;
    std::thread     *m_monitorTread;
    bool            m_stop;
    LinkParam       m_linkParm;
};

