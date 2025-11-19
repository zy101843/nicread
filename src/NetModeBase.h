#pragma once
#include "common.h"

#include "network/linkpeer.h"
#include "network/networkMgr.h"
#include "interface.h"
#include "tcpiphead.h"
#include <memory.h>
#include <atomic>

struct LeveParam
{
    void *param;
    void *base;
    int  leve;
    bool topLeve;
};


struct LinkParam
{
    CLinkPeer   *link;
    CNetworkMgr *linkMgr;
    void        *route;
    int         total;
    LeveParam   leve[10];
    std::atomic<int>  m_ref;
    std::atomic<bool> m_link;
    Interface   *interFace;
    int         linkType;
    int         linkSubType;
    int         id;
    void        *m_ext;
    LinkParam()
    {
        m_ref.store(1);
        link    = NULL;
        linkMgr = NULL;
        route   = NULL;
        total   = 0;
        id      = 0;
        memset(leve, 0, sizeof(leve));
        interFace = NULL;
        m_ext  = NULL;
        setLink(false);
    }
    int  addRef();
    int  delRef();
    bool isLink();
    bool setLink(bool link);

};