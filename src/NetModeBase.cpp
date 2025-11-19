#include "NetModeBase.h"

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
        if(NULL != interFace)
        {
            interFace->cleanPort(2);
        }
        if (NULL != link)
        {
            link->delRef();
        }
        delete this;
    }
    return ret;
}

bool LinkParam::isLink()
{
    return m_link.load();
}
bool LinkParam::setLink(bool link)
{
    m_link.store(link);
    return link;
}