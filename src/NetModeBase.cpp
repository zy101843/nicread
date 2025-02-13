#include "NetModeBase.h"
//#include "https/SSLSessionMg.h"
//#include "network/netMessageRoute.h"


int LinkParam::addRef()
{
    int ret = ++m_ref;
    return ret;
}
int LinkParam::delRef()
{
    int ret = --m_ref;
    if (ret == 0)
    {
        delete this;
    }
    return ret;
}


CNetModeBase::CNetModeBase()
{
 
}

CNetModeBase::~CNetModeBase()
{
}

bool CNetModeBase::init()
{
    return true;
}


int CNetModeBase::sendToDown(LinkParam  *param, int leve, uint8_t *data, uint32_t len, uint8_t *append, int applen)
{
    int localLeve = leve;
    localLeve--;
    if (localLeve < -1)
    {
        return -1;
    }
    if (-1 == localLeve)
    {
        if (param->delRef() <= 0)
        {
            //((CNetMssageRoute*)(param->route))->cleanParam(param);
        }
        else
        {
            if (IP_TCP_TYPE  == param->linkType)
            {
                param->linkMgr->sendData(param->link, data, len, append, applen);
            }
            else if(IP_UDP_TYPE == param->linkType)
            {
                param->linkMgr->sendData(param->link, data, len, append, applen);
            }
        }
    }
    else
    {
        CNetModeBase *base = (CNetModeBase *)(param->leve[localLeve].base);
        base->processFromUP(param, localLeve, data, len);
        if (applen > 0)
        {
            param->addRef();
            base->processFromUP(param, localLeve, append, applen);
        }
    }
    return 1;
}

int CNetModeBase::sendToDown(CByteStream::CBufferItem *pItem, int leve)
{
    int localLeve = leve;
    localLeve--;
    LinkParam *param = (LinkParam *)pItem->m_othP;
    if (localLeve < -1)
    {
        return -1;
    }
    if (-1 == localLeve)
    {
        if (param->delRef() <= 0)
        {
        
            //((CNetMssageRoute *)(param->route))->cleanParam(param);
            //((CNetMssageRoute *)(param->route))->cleanBufItem(pItem);
          
        }
        else
        {
            CLinkPeer *linkPeer = (CLinkPeer *)(param->link);
            int send  = -1;
            send = param->linkMgr->sendData(linkPeer, pItem, true);
            if (-1 == send)
            {
                //((CNetMssageRoute *)(param->route))->cleanBufItem(pItem);
            }
        }
    }
    else
    {
    }
    return 1;
}

int CNetModeBase::sendToUP(LinkParam *param, int leve, uint8_t *data, uint32_t len, uint8_t *append, int applen)
{
    int localLeve = leve;
    localLeve++;
    if (localLeve == param->total)
    {
        return -1;
    }
    else
    {
        CNetModeBase *base = (CNetModeBase *)(param->leve[localLeve].base);
        base->processFromDown(param, localLeve, data, len);
        if (applen > 0)
        {
            param->addRef();
            base->processFromDown(param, localLeve, data, len);
        }
    }
    return len + applen;
}

int CNetModeBase::cleanLinke(LinkParam *param)
{
    //((CNetMssageRoute*)(param->route))->cleanLink(param->link);
    return param->linkMgr->clean(param->link, 3);
}

void CNetModeBase::notifLinkeClose(void *param, int leve)
{
    (void)param;
    (void)leve;
}
