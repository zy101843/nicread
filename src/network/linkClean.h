#pragma once
#include "networkMgr.h"
class CCleanLink : public CNetworkCallBack
{
public:
    CCleanLink();
    ~CCleanLink();
public:
    virtual bool operator()(void *link);
public:
    void setParam(void *param);
private:
    void *m_param;
};