#include "linkClean.h"
//#include "distributionToThr.h"

CCleanLink::CCleanLink()
{
    m_param = NULL;
}
CCleanLink::~CCleanLink()
{

}
void CCleanLink::setParam(void *param)
{
    m_param = param;
}
bool CCleanLink::operator()(void *link)
{
    //DistributionToThr *megRoute = (DistributionToThr *)m_param;
    //megRoute->cleanLink(link);
    return true;
}
