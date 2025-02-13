#include "portLink.h"   
#include <memory.h>
#include <stdio.h>
#include "netPortHub.h"
#include "../util/utility_net.h"

CPortLink::CPortLink(int leve) :m_leve()
{
    m_curLen  = 0;
    m_noError = false;
    m_up = CNetPortHub::getItem();
}

CPortLink::~CPortLink()
{    

}

#define MAXLENTEST 2870
int CPortLink::processData(LinkParam *param, int leve, uint8_t *data, int datalen)
{
    if (m_noError)
    {
        return -1;
    }
    int leftLen =  datalen;
    uint8_t *curPost = data;

    if (leftLen <= 0)
    {
      return  sendToUP(param, leve, data, datalen);
    }
    if (IP_UDP_TYPE == param->linkType)
    {
        return  sendToUP(param, leve, data, datalen);
    }
    if (m_curLen > 0)
    {
        if (leftLen + m_curLen > 2)
        {
            if (1 == m_curLen)
            {
                m_MidData[1] = *data;
            }
            uint16_t len = *((uint16_t*)(m_MidData)) + MESSAGEHEAD_LEN;
            if (len > MAXLENTEST)
            {
                printf("error mid data  send to long %d  intput %d\n", len, datalen);
                ((CNetModeBase*)(param->leve[leve].base))->cleanLinke(param);
                m_curLen = 0;
                m_noError = true;
                return -1;
            }
            if (leftLen + m_curLen >= len)
            {
                int32_t copyLen = len - m_curLen;
                memcpy(m_MidData + m_curLen, curPost, copyLen);

                leftLen -= copyLen;
                curPost += copyLen;
                m_curLen = 0;
                if (len > MESSAGEHEAD_LEN)
                {
                    sendToUP(param, leve, m_MidData, len);
                }
                if (len > MAXLENTEST)
                {
                    printf("send to long %d \n", len);
                }
            }
            else
            {
                memcpy(m_MidData + m_curLen, curPost, leftLen);
                m_curLen  += leftLen;
                leftLen = 0;
            }
        }
        else
        {
            m_MidData[m_curLen] = *data;
            m_curLen++;
            leftLen = 0;
            printf("error %s %d\n", __FUNCTION__, __LINE__);
        }
    }
    while (leftLen > 0)
    {
        if (leftLen >= 2)
        {
            uint16_t len = *((uint16_t*)curPost) + MESSAGEHEAD_LEN;
            if (len > MAXLENTEST)
            {
                printf("error data  send to long %d  intput %d\n", len, datalen);
                ((CNetModeBase*)(param->leve[leve].base))->cleanLinke(param);
                m_curLen  = 0;
                m_noError = true;
                return -1;
            }
            if (leftLen >= len)
            {
                if (len > MAXLENTEST)
                {
                    printf("normal send to long %d  intput %d\n", len, datalen);
                }
                if (len > MESSAGEHEAD_LEN)
                {
                    sendToUP(param, leve, curPost, len);
                }
                leftLen -= len;
                curPost += len;
            }
            else
            {
                memcpy(m_MidData, curPost, leftLen);
                //printf("normal  mid data copy  %d len  %d\n", leftLen, datalen);
                m_curLen  = leftLen;
                leftLen = 0;
            }
        }
        else
        {
            if (1 == leftLen)
            {
                //m_MidData[0] = *curPost;
                m_MidData[0] = *curPost;
                m_curLen   = 1;
                leftLen--;
            }
            else
            {
                printf("this is shuld never be heare %s %d \n", __FILE__,  __LINE__);
            }
        }
    }
    return 0;
}
int CPortLink::sendToUP(LinkParam *param, int leve, uint8_t *data, int len)
{
    if (len > 4)
    {
        encrypt(data + 2, len - 2);
        if (0x1 == data[3])
        {
            return ((CNetPortHub *)m_up)->processFromNet(param, leve, data, len);
        }
        else
        {
            ((CNetModeBase*)(param->leve[leve].base))->cleanLinke(param);
        }
    }
    else
    {
        return ((CNetPortHub *)m_up)->processFromNet(param, leve, data, len);
    }
    return len;
}
