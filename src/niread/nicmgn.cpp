#include "nicmgn.h"
#include "../hub/hub.h"
#include <functional>

NicMgn::NicMgn()
{
    m_nic = NULL;
    m_stop = true;
    m_type = 1;
    m_linkParm.interFace = this;
    m_linkParm.linkType = 1;
    m_linkParm.linkSubType = 1;
    m_linkParm.id = 1;
    sem_init(&m_sem, 0, 1);
    pthread_mutex_init(&m_mutex, NULL);
    initData();
}

NicMgn::~NicMgn()
{
}

void NicMgn::start()
{
    if (m_nic->open() >=0)
    {
        // m_monitorTread = new std::thread(std::bind(&NicMgn::setThread, this));
        m_monitorTread1 = new std::thread(std::bind(&NicMgn::workThread, this));
    }
}

void NicMgn::stop()
{
    m_stop = false;
}

void NicMgn::setName(const std::string &name, uint8_t *mac)
{
    memcpy(m_mac, mac, 6);
    m_nic = new nic_proc(name);
}

void NicMgn::workThread()
{
    uint8_t *data;
    int len;
    m_linkParm.m_ext = m_mac;
    m_hub->addData(NULL, -1, &m_linkParm);
    while (m_stop)
    {
        len = -1;
        m_nic->readDataMap(len, m_hub, &m_linkParm);
        if (len > 1514)
        {
            printf("read len error %d  %s %d  \n", len, __FILE__, __LINE__);
        }
    }
}

void NicMgn::setThread()
{
    SendBufItem *lo = NULL;
    bool condition = false;
    while (m_stop)
    {

        sem_wait(&m_sem);
        do
        {
            condition = false;
            lo = NULL;
            pthread_mutex_lock(&m_mutex);
            if (m_listBuf.size() > 0)
            {
                lo = m_listBuf.front();
                m_listBuf.pop();
                condition = !m_listBuf.empty();
            }
            pthread_mutex_unlock(&m_mutex);
            if (lo)
            {
                m_nic->writeData(lo->buf, lo->buflen);
                if (1 == lo->type)
                {
                    pthread_mutex_lock(&m_mutex);
                    m_freeList.push(lo);
                    pthread_mutex_unlock(&m_mutex);
                }
                else
                {
                    delete lo;
                }
            }
        } while (condition);
    }
}

int NicMgn::writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam)
{
    // return 0;
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
    if (len > 1514)
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

/*
int NicMgn::writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam)
{
    if (srcparam == dstParam)
    {
        return 0;
    }
    if (len <= 0 || len > 1600)
    {
        return 0;
    }
    SendBufItem *lo = NULL;
    pthread_mutex_lock(&m_mutex);
    if (m_freeList.size() > 0)
    {
        lo = m_freeList.top();
        m_freeList.pop();
        pthread_mutex_unlock(&m_mutex);
    }
    else
    {
        lo = new SendBufItem;
        lo->type = 2;
    }
    if (lo)
    {
        lo->buflen = len;
        memcpy(lo->buf, data, len);
        pthread_mutex_lock(&m_mutex);
        m_listBuf.push(lo);
        pthread_mutex_unlock(&m_mutex);
        sem_post(&m_sem);
    }
    return len;
}
*/
int NicMgn::initData()
{
    int oneSize = sizeof(SendBufItem);
    int count = 400;
    uint8_t *buf = new uint8_t[count * oneSize];
    for (int i = 0; i < count; i++)
    {
        SendBufItem *lo = (SendBufItem *)buf;
        lo->buflen = 0;
        lo->type = 1;
        m_freeList.push(lo);
        buf += oneSize;
    }
    return count;
}
