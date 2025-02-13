
#include "netLink.h"
#include "netPortHub.h"
#include "../util/utility_net.h"


CNetLink::CNetLink()
{
    m_netHub =CNetPortHub::getItem();
}
CNetLink::~CNetLink()
{

}
bool CNetLink::init()
{
    return true;
}

int32_t CNetLink::processFromDown(CByteStream::CBufferItem *pItem, int leve)
{
    LinkParam *param = (LinkParam *)(pItem->m_othP);
    CPortLink *portLink = (CPortLink *)(param->leve[leve].param);
    return portLink->processData(param, leve, pItem->m_pBuffer, pItem->m_iPos);
}

int32_t CNetLink::processFromUP(CByteStream::CBufferItem *pItem, int leve)
{
    //encrypt(pItem->m_pBuffer + 2, pItem->m_iPos - 2);
    return sendToDown(pItem, leve--);
}

int32_t CNetLink::processFromDown(LinkParam *param, int leve, uint8_t *data, int len)
{
    CPortLink *portLink = (CPortLink *)(param->leve[leve].param);
    return portLink->processData(param, leve, data, len);
}
int32_t CNetLink::processFromUP(LinkParam *param, int leve, uint8_t *data, int len)
{
    //encrypt(data + 2, len - 2);
    return sendToDown(param, leve--, data, len, NULL, 0);
}
int32_t CNetLink::clean(void *param)
{
    CPortLink *portLink  = (CPortLink *)param;
    if (NULL != portLink)
    {
        delete portLink;
        return 0;
    }
    return 1;
}

void *CNetLink::getParam(int leve, void *param)
{
    
    CPortLink *portLink = new CPortLink(leve);
    portLink->m_param = param;

    return portLink;
}

void  CNetLink::notifLinkeClose(void *param, int leve)
{
    (void)leve;
    ((CNetPortHub*)m_netHub)->cleanLink(param);

}