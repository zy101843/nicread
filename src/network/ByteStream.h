#pragma once
#include <vector>
#include <stdint.h>
#include <deque>
#include <atomic>
#include <stdlib.h>
class CByteStream
{
public:
    class CBufferItem
    {
    public:
        typedef std::vector<void *> PARMAMLIST;
    public:
        CBufferItem(std::size_t iMaxSize);
        ~CBufferItem();
        void Reset()
        {
            m_iPos = 0;
            m_iOffset = 0;
            m_ref = 0;
            m_last = 1;
            m_fd      = 0;
            m_linkMgr = 0;
            m_type    = 0;
            m_othP    = NULL;
        }
        std::size_t GetFreeSize() const
        {
            return m_iBufferSize - m_iPos;
        }
        int addRef()
        {
            int ret = ++m_ref;
            return ret;
        }
        int delRef()
        {
            int ret = --m_ref;
            return ret;
        }

        uint8_t    *m_pBuffer;
        uint32_t    m_last;
        std::size_t m_iBufferSize;

        int         m_iPos;
        std::size_t m_iOffset;
        std::atomic<int> m_ref;

    public:
        void *m_fd;
        void *m_linkMgr;
        int   m_type;
        void *m_othP;
        uint32_t m_ip[4];
        uint16_t m_port;
    };

public:
    CByteStream(std::size_t iMaxSize = 2 * 1024 * 1024);
    CByteStream(std::size_t iPoolSize, std::size_t iMaxSize);
    ~CByteStream(void);

    uint8_t *GetFreeBuffer(std::size_t &iBufferSize);
    bool AddDataLen(std::size_t iLen);
    bool ParseBlock(uint8_t *&pBuffer, std::size_t &iSize);
    void Init();

protected:
    std::size_t GetBlockSize();
    CBufferItem *m_pReadBuffer;

public:
    CBufferItem *GetWaitSendItem();
    CBufferItem *GetFreeBufferItem(std::size_t iMinLen);
    CBufferItem *GetFreeBufferItem();
    void FreeBufferItem(CBufferItem *pItem);
    void AddBufferItemToWait(CBufferItem *pItem);
    std::size_t getBufferItemToWaitSize();

private:
    typedef std::deque<CBufferItem *> BUFFERITEMARRAY;
    BUFFERITEMARRAY m_BufferPool;
    BUFFERITEMARRAY m_WaitSendBuffer;

    std::size_t m_iMaxPoolSize;
    std::size_t m_iMaxBytes;
};
