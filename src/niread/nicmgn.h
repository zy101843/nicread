#pragma once 
#include "../common.h"
#include "../interface.h"
#include "readnic.h"
#include "../NetModeBase.h"
#include <thread>
#include <semaphore.h>
#include <queue> 
#include <stack>

struct SendBufItem{
    int buflen;
    int type;
    uint8_t buf[1600]; 
};

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
    void setName(const std::string &name, uint8_t *mac);
private:
    void workThread();
    void setThread();
private:
    int  initData();
private:
    nic_proc        *m_nic;
    std::thread     *m_monitorTread;
    std::thread     *m_monitorTread1;
    bool            m_stop;
    LinkParam       m_linkParm;
    sem_t           m_sem;
    pthread_mutex_t m_mutex;
    uint8_t         m_mac[6];
private:
    std::queue<SendBufItem *> m_listBuf;
    std::stack<SendBufItem *> m_freeList;
};

