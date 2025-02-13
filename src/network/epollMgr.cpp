#include "epollMgr.h"
#include <memory.h>

CEpollMgr::CEpollMgr() 
{
    m_restultEnv = new epoll_event[MAX_OPEN_FD];
}
CEpollMgr::~CEpollMgr()
{
}
bool CEpollMgr::init()
{
    m_epollID = epoll_create(MAX_OPEN_FD);
    if (0 == m_epollID)
    {
        return false;
    }
    return true;
}
bool CEpollMgr::addEnv(uint32_t flag, int fd, void *ptr)
{
    epoll_event  epe;
    epe.events  = flag;
    epe.data.fd = fd;
    epe.data.ptr = ptr;
    int ret = epoll_ctl(m_epollID, EPOLL_CTL_ADD, fd, &epe);
    if (0 != ret)
    {
        return false;
    }
    return true;
}
bool CEpollMgr::modEnv(uint32_t flag, int fd, void *ptr)
{
    epoll_event  epe;
    epe.events  = flag;
    epe.data.fd = fd;
    epe.data.ptr = ptr;
    int ret = epoll_ctl(m_epollID, EPOLL_CTL_MOD, fd, &epe);
    if (0 != ret)
    {
        return false;
    }
    return true;
}
bool CEpollMgr::delEnv(int fd)
{
    int ret = epoll_ctl(m_epollID, EPOLL_CTL_DEL, fd, NULL);
    if (0 != ret)
    {
        return false;
    }
    return true;
}
int CEpollMgr::getEnv(epoll_event *&reten, int time)
{
    int  nready = epoll_wait(m_epollID, m_restultEnv, MAX_OPEN_FD, -1);
    reten = m_restultEnv;
    if (-1 == nready)
    {
        printf("epoll_wait error: errno=%d, errorinfo:%s. \n", errno, strerror(errno));
    }
    return  nready;
}