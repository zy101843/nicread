#include "ByteStream.h"
#include <memory.h>


CByteStream::CByteStream(std::size_t iMaxSize)
{
    m_pReadBuffer = new CBufferItem(iMaxSize);
    m_iMaxBytes   = iMaxSize;
}

CByteStream::~CByteStream(void)
{
    if (m_pReadBuffer)
    {
        delete m_pReadBuffer;
    }
    BUFFERITEMARRAY::iterator it;
    for (it=m_BufferPool.begin(); it != m_BufferPool.end(); it++)
    {
        delete *it;
    }
    for (it=m_WaitSendBuffer.begin(); it != m_WaitSendBuffer.end(); it++)
    {
        delete *it;
    }
}

uint8_t* CByteStream::GetFreeBuffer(std::size_t& iBufferSize)
{
    if (m_pReadBuffer->m_iPos >= m_pReadBuffer->m_iBufferSize)
    {
        return NULL;
    }
    iBufferSize = m_pReadBuffer->m_iBufferSize - m_pReadBuffer->m_iPos;
    return m_pReadBuffer->m_pBuffer + m_pReadBuffer->m_iPos;
}
bool CByteStream::AddDataLen(std::size_t iLen)
{
    m_pReadBuffer->m_iPos += iLen;
    return GetBlockSize() > 0;
}

bool CByteStream::ParseBlock(uint8_t*& pBuffer, std::size_t& iSize)
{
    bool bRet = false;
    iSize = GetBlockSize();
    if (iSize == 0)
    {
        if (m_pReadBuffer->m_iOffset > 0 && m_pReadBuffer->m_iPos > m_pReadBuffer->m_iOffset)
        {
            iSize = m_pReadBuffer->m_iPos - m_pReadBuffer->m_iOffset;
            memmove(m_pReadBuffer->m_pBuffer, m_pReadBuffer->m_pBuffer + m_pReadBuffer->m_iOffset, iSize);
            m_pReadBuffer->m_iOffset = 0;
            m_pReadBuffer->m_iPos = iSize;
        }
        else
        {
            m_pReadBuffer->m_iOffset = 0;
            m_pReadBuffer->m_iPos = 0;
        }
    }
    else
    {
        pBuffer = m_pReadBuffer->m_pBuffer + m_pReadBuffer->m_iOffset;
        m_pReadBuffer->m_iOffset += iSize ;
        bRet = true;
    }

    return bRet;
}
std::size_t CByteStream::GetBlockSize()
{
    std::size_t iBlockSize = 0;
    std::size_t iTotal = m_pReadBuffer->m_iPos - m_pReadBuffer->m_iOffset;
    uint32_t* pBlockSize;
    if (iTotal > sizeof(uint32_t))
    {
        pBlockSize = (uint32_t*)(m_pReadBuffer->m_pBuffer + m_pReadBuffer->m_iOffset);
        if (iTotal >= (*pBlockSize) + 4)
        {
            iBlockSize = *pBlockSize + 4;
        }
    }
    return iBlockSize;
}
CByteStream::CBufferItem::CBufferItem(std::size_t iMaxSize) :m_ref(0)
{
    m_pBuffer = new uint8_t[iMaxSize];
    m_iBufferSize = iMaxSize;
    m_iPos = 0;
    m_iOffset = 0;
}
CByteStream::CBufferItem::~CBufferItem()
{
    if (m_pBuffer)
    {
        delete[]m_pBuffer;
    }
}
CByteStream::CByteStream(std::size_t iPoolSize, std::size_t iMaxSize)
{
    m_pReadBuffer = NULL;
    m_iMaxPoolSize = iPoolSize;
    m_iMaxBytes = iMaxSize;
    for (std::size_t i=0; i < iPoolSize; i++)
    {
        m_BufferPool.push_back(new CBufferItem(iMaxSize));
    }
}

CByteStream::CBufferItem* CByteStream::GetFreeBufferItem(std::size_t iMinLen)
{
    CBufferItem* pItem = NULL;
    if (!m_BufferPool.empty())
    {
        pItem = m_BufferPool.back();
        if (pItem->GetFreeSize() < iMinLen)
        {
            pItem = NULL;
        }
        else
        {
            m_BufferPool.pop_back();
        }
    }
    if (NULL == pItem)
    {
        pItem = new CBufferItem(iMinLen);
    }
    return pItem;
}
CByteStream::CBufferItem* CByteStream::GetFreeBufferItem()
{
    CBufferItem* pItem = NULL;

    if (!m_BufferPool.empty())
    {
        pItem = m_BufferPool.back();
        m_BufferPool.pop_back();
    }
    else
    {
        pItem = new CBufferItem(m_iMaxBytes);
    }
    return pItem;
}
CByteStream::CBufferItem* CByteStream::GetWaitSendItem()
{
    CBufferItem* pItem = NULL;
    if (!m_WaitSendBuffer.empty())
    {
        pItem = m_WaitSendBuffer.front();
        m_WaitSendBuffer.pop_front();
    }
    return pItem;
}
void CByteStream::FreeBufferItem(CBufferItem* pItem)
{
    pItem->Reset();
    if (m_BufferPool.size() == m_iMaxPoolSize)
    {
        delete pItem;
    }
    else
    {
        if (pItem->m_iBufferSize != m_iMaxBytes)
        {
            delete pItem;
        }
        else
        {
            m_BufferPool.push_back(pItem);
        }
    }
}
void CByteStream::AddBufferItemToWait(CBufferItem* pItem)
{
    m_WaitSendBuffer.push_back(pItem);
}
std::size_t CByteStream::getBufferItemToWaitSize()
{
    return m_WaitSendBuffer.size();
}
void CByteStream::Init()
{
    for (BUFFERITEMARRAY::iterator it=m_WaitSendBuffer.begin(); it != m_WaitSendBuffer.end(); it++)
    {
        (*it)->Reset();
        m_BufferPool.push_back(*it);
    }
    m_WaitSendBuffer.clear();
}
