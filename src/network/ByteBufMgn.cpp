#include "ByteBufMgn.h"

ByteBufMgn::ByteBufMgn() : m_ByteStram(1000, 4 * 1024)
{
}
ByteBufMgn::~ByteBufMgn()
{
    
}

 ByteBufMgn *ByteBufMgn::getByteBufMgn()
 {
     static ByteBufMgn mgn;
     return &mgn;
 }

CByteStream::CBufferItem *ByteBufMgn::getBufItem()
{
    CByteStream::CBufferItem *item = NULL;
    m_Critical.lock();
    item = m_ByteStram.GetFreeBufferItem();
    m_Critical.unlock();
    return item;
}
void ByteBufMgn::FreeBufItem(CByteStream::CBufferItem *item)
{
    m_Critical.lock();
    m_ByteStram.FreeBufferItem(item);
    m_Critical.unlock();
}