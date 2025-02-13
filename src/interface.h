#pragma once 
#include <stdint.h>
#include <stdlib.h>
class Interface
{
public:
    Interface() { 
        m_sendBuf  = new uint8_t[1514]; 
        m_type     = -1;
        m_hub      = NULL;
     };
    virtual ~Interface() {};
public:
    void *setHub(void *hub) { 
        m_hub = hub;
        return hub;
    };
public:
    virtual int writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam) =0;
public:
    void    *m_hub;
    int      m_type;  /*1 nic,  2  net, 3 gateway*/
    uint8_t *m_sendBuf;
};
