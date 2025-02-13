#pragma once 
#include <mutex>
#include "ByteStream.h"

class ByteBufMgn
{
public:
    ByteBufMgn();
    ~ByteBufMgn();

public:
    static ByteBufMgn *getByteBufMgn();

public:
    CByteStream::CBufferItem *getBufItem();
    void FreeBufItem(CByteStream::CBufferItem *item);

private:
    CByteStream m_ByteStram;
    std::mutex m_Critical;
};