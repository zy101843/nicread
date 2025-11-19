#pragma once
#include <stdint.h>
#include <stdlib.h>

class midInterface
{
public:
    virtual int addData(uint8_t *data, int len, void *param) = 0;
};

class Interface
{
public:
    Interface()
    {
        m_type = -1;
        m_hub = NULL;
    };
    virtual ~Interface() {};

public:
    virtual void cleanPort(int type) { (void)type;};
public:
    void *setHub(midInterface *hub)
    {
        m_hub = hub;
        return hub;
    };
    void setId(uint32_t id)
    {
        m_id = id;
    };

public:
    virtual int writeData(uint8_t *data, int len, int type, void *srcparam, void *dstParam) = 0;
public:
    midInterface *m_hub;
    int           m_type; /*1 nic,  2  net, 3 gateway*/
    uint32_t      m_id;
};
