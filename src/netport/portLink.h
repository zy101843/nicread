#pragma once 

#include <stdint.h>
#include "../NetModeBase.h"

class CPortLink
{
public:
    CPortLink(int leve);
    ~CPortLink();
public:
    int processData(LinkParam *param, int leve, uint8_t *data, int len);
private:
    int sendToUP(LinkParam *param, int leve, uint8_t *data, int len);
public:
    enum {
        BUFMAXLNE_PL  = 32 * 1024
    };
    int  m_leve;
    void *m_param;
    void *m_MessageRoute;
private:
    int     m_curLen;
    uint8_t m_MidData[BUFMAXLNE_PL + 1024];
    void    *m_up;
    bool    m_noError;
    

};

