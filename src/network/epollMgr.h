#pragma once 
#include <sys/epoll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

class CEpollMgr
{
public:
    CEpollMgr();
    virtual ~CEpollMgr();
public:
    bool init();
    bool addEnv(uint32_t flag, int fd, void *ptr);
    bool modEnv(uint32_t flag, int fd, void *ptr);
    bool delEnv(int fd);
    int  getEnv(epoll_event *&reten, int time);
private:
    enum 
    {
        MAX_OPEN_FD = 1024
    };
    int          m_epollID;
    epoll_event *m_restultEnv;

};