#include "netPortHub.h"  
#include "../hub/hub.h"
#include "../NetModeBase.h"
#include "portLink.h"


CNetPortHub::CNetPortHub()
{
    m_type      = 2;
}

CNetPortHub::~CNetPortHub()
{

}

CNetPortHub *CNetPortHub::getItem()
{
    static CNetPortHub hub;
    return &hub;
}


int CNetPortHub::writeData(uint8_t * data, int len, int type, void *srcParam, void *dstParam)
{
    int ret = 0;
    if (1 == type)
    {
        if(srcParam != dstParam)
        {
            sendToLink(dstParam, data, len);
        }
    }
    else if(2 == type)
    {
        sendToLink(dstParam, data, len);
    }
    else if (3 == type)
    {
        int ret = ((LinkParam *)(dstParam))->addRef();
        if(0 >= ret)
        {
            printf("error \n");
        }
    }
    return  ret;
}


int  CNetPortHub::sendToLink(void *port, uint8_t *data, int len)
{
    if (NULL == port)
    {
        return 0;
    }
    int leve;
    LinkParam *param              = (LinkParam *)port;
    //CNetMssageRoute *messageRoute = (CNetMssageRoute *)(param->route);
    //*(uint16_t*)(data - MESSAGEHEAD_LEN) = (uint16_t)len;
    //*(data - 1) = 1;
    //*(data - 2) = 1;
    //uint8_t *datasend = data - MESSAGEHEAD_LEN;
    //int sendLen       = len + MESSAGEHEAD_LEN;
    //return messageRoute->addItem(datasend, sendLen, param);
    return len;
}

int32_t CNetPortHub::processFromNet(LinkParam *param, int leve, uint8_t * data, int len)
{
    int32_t ret = 0;
    CHub *hub = (CHub*)m_hub;
    uint64_t mac; 
    if (len > 0)
    { 
        uint8_t type = data[2];
        switch (type)
        {
        case 1:
            mac  = *((uint64_t*)(data + 6 + MESSAGEHEAD_LEN)); 
            if(param->macList.find(mac) == param->macList.end())
            {
                param->macList.insert(mac);
            }
            param->interFace = this;
            ret = hub->addData(data + MESSAGEHEAD_LEN, len - MESSAGEHEAD_LEN, param);
            break;
        case 2:
            ret = hub->addData(data + MESSAGEHEAD_LEN,  -1, param);
            break;
        default:
            break;
        }
    }
    else
    {
        param->interFace = this;
        ret = hub->addData(data, len, param);
    }
    return ret;
  
}

int CNetPortHub::cleanLink(void *param)
{
    CHub *hub = (CHub*)m_hub;
    int ret = hub->cleanLink(param);
    return ret;
}
