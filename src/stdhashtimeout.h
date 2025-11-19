#pragma once
#include <unordered_map>
#include <list>

template<class T, class  THashFun=std::hash<T>, class TCompare=std::equal_to<T> >
class CHashTOContainerSTD
{
public:
    typedef void(*TOFun)(T&, void*, time_t);
    CHashTOContainerSTD()
    {
        m_TOFun = NULL;
        m_TOParam = NULL;
        m_LastTime = 0;
    }
    ~CHashTOContainerSTD()
    {
        Clear();
    }
    void SetTOFun(TOFun fun, void* pParam)
    {
        m_TOFun = fun;
        m_TOParam = pParam;
    }
    void Clear()
    {
        if (m_TOFun)
        {
            for (m_ListIt=m_TOList.begin(); m_ListIt != m_TOList.end(); m_ListIt++)
            {
                m_TOFun(m_ListIt->first, m_TOParam);
            }
        }
        m_TOList.clear();
        m_Map.clear();
    }

    bool Find(T& find, T& findOut, time_t nCurTime, bool bReTimeout=true)
    {
        m_MapIt = m_Map.find(find);
        if (m_MapIt == m_Map.end())
        {
            return false;
        }

        findOut = m_MapIt->first;
        if (bReTimeout)
        {
            m_TOList.erase(m_MapIt->second);
            m_MapIt->second = m_TOList.insert(m_TOList.end(), std::make_pair(findOut, nCurTime));
        }
        return true;
    }
    void printAll(TOFun fun)
    {
        for (m_ListIt=m_TOList.begin(); m_ListIt != m_TOList.end(); m_ListIt++)
        {
            fun(m_ListIt->first, m_TOParam);
        }
    }
    bool Delete(T& find, bool bTOFun)
    {
        m_MapIt = m_Map.find(find);
        if (m_MapIt == m_Map.end())
        {
            return false;
        }

        m_TOList.erase(m_MapIt->second);

        if (bTOFun && m_TOFun)
        {
            T pTemp = (T)m_MapIt->first;
            m_Map.erase(m_MapIt);
            m_TOFun(pTemp, m_TOParam);
        }
        else
        {
            m_Map.erase(m_MapIt);
        }
        return true;
    }

    bool Add(T& info, time_t nCurTime)
    {
        m_MapIt = m_Map.find(info);
        if (m_MapIt != m_Map.end())
        {
            return false;
        }
        m_Map.insert(std::make_pair(info,
            m_TOList.insert(m_TOList.end(),
                std::make_pair(info, nCurTime))));
        return true;
    }
    void Timeout(time_t nCurTime, time_t nTimeLen)
    {
        if (m_LastTime >= nCurTime)
        {
            return;
        }
        for (m_ListIt=m_TOList.begin(); m_ListIt != m_TOList.end(); m_ListIt++)
        {
            if ((nCurTime - m_ListIt->second) < nTimeLen)
            {
                break;
            }
            m_Map.erase(m_ListIt->first);
            if (m_TOFun)
            {
                T pTemp = m_ListIt->first;
                m_TOFun(pTemp, m_TOParam, nCurTime);
            }
        }
        m_TOList.erase(m_TOList.begin(), m_ListIt);
        m_LastTime = nCurTime;
    }

    bool empty()
    {
        return m_TOList.empty();
    }
    int size()
    {
        return m_Map.size();
    }
private:

    TOFun m_TOFun;
    void*  m_TOParam;
    time_t m_LastTime;
    typedef typename std::pair<T, time_t> OBJ;
    typedef typename std::list<OBJ> OBJLIST;
    typedef typename std::unordered_map<T, typename OBJLIST::iterator, THashFun, TCompare> OBJMAP;
    OBJMAP  m_Map;
    typename OBJMAP::iterator m_MapIt;
    OBJLIST m_TOList;
    typename OBJLIST::iterator m_ListIt;
public:
    typedef typename OBJLIST::iterator listiterator;
    listiterator begin()
    {
        return m_TOList.begin();
    }
    listiterator end()
    {
        return m_TOList.end();
    }
};



template<class T, class  THashFun, class TCompare>
class CHashTOContainerSTD<T* , THashFun , TCompare>
{
public:
    typedef void(*TOFun)(T *, void*, time_t);
    CHashTOContainerSTD()
    {
        m_TOFun    = NULL;
        m_TOParam  = NULL;
        m_LastTime = 0;
    }
    ~CHashTOContainerSTD()
    {
        Clear();
    }
    void SetTOFun(TOFun fun, void* pParam)
    {
        m_TOFun   = fun;
        m_TOParam = pParam;
    }
    void Clear()
    {
        if (m_TOFun)
        {
            for (m_ListIt=m_TOList.begin(); m_ListIt != m_TOList.end(); m_ListIt++)
            {
                m_TOFun(m_ListIt->first, m_TOParam, time(NULL));
            }
        }
        m_TOList.clear();
        m_Map.clear();
    }

    bool Find(T* find, T* &findOut, time_t nCurTime, bool bReTimeout=true)
    {
        m_MapIt = m_Map.find(find);
        if (m_MapIt == m_Map.end())
        {
            return false;
        }

        findOut = m_MapIt->first;
        if (bReTimeout)
        {
            m_TOList.erase(m_MapIt->second);
            m_MapIt->second = m_TOList.insert(m_TOList.end(), std::make_pair(findOut, nCurTime));
        }
        return true;
    }
    bool FindAndDel(T* find, T* &findOut)
    {
        m_MapIt = m_Map.find(find);
        if (m_MapIt == m_Map.end())
        {
            return false;
        }
        findOut = m_MapIt->first;
        m_TOList.erase(m_MapIt->second);
        m_Map.erase(m_MapIt);
        return true;
    }
    void printAll(TOFun fun)
    {
        for (m_ListIt=m_TOList.begin(); m_ListIt != m_TOList.end(); m_ListIt++)
        {
            fun(m_ListIt->first, m_TOParam);
        }
    }
    bool Delete(T* find, bool bTOFun)
    {
        m_MapIt = m_Map.find(find);
        if (m_MapIt == m_Map.end())
        {
            return false;
        }

        m_TOList.erase(m_MapIt->second);

        if (bTOFun && m_TOFun)
        {
            T* pTemp = (T*)m_MapIt->first;
            m_Map.erase(m_MapIt);
            m_TOFun(pTemp, m_TOParam, time(NULL));
        }
        else
        {
            m_Map.erase(m_MapIt);
        }
        return true;
    }

    bool Add(T* info, time_t nCurTime)
    {
        m_MapIt = m_Map.find(info);
        if (m_MapIt != m_Map.end())
        {
            return false;
        }
        m_Map.insert(std::make_pair(info, m_TOList.insert(m_TOList.end(), std::make_pair(info, nCurTime))));
        return true;
    }
    void Timeout(time_t nCurTime, time_t nTimeLen)
    {
        if (m_LastTime >= nCurTime)
        {
            return;
        }
        int count = 0;
        typename OBJLIST::iterator iter ;
        typename OBJLIST::iterator endIter = m_TOList.end();

        for (iter=m_TOList.begin(); iter != endIter; ++iter)
        {
            if ((nCurTime - iter->second) < nTimeLen)
            {
                break;
            }
            T* pTemp = (T*)iter->first;
            m_Map.erase(iter->first);
            if (m_TOFun)
            {
                m_TOFun(pTemp, m_TOParam, nCurTime);
            }
            count++;
        }
        if (count > 0)
        {
            m_TOList.erase(m_TOList.begin(), iter);
        }
        m_LastTime = nCurTime;
    }

    bool empty()
    {
        return m_TOList.empty();
    }
    int size()
    {
        return m_Map.size();
    }
private:

    TOFun  m_TOFun;
    void*  m_TOParam;
    time_t m_LastTime;
    typedef typename std::pair<T *, time_t> OBJ;
    typedef typename std::list<OBJ> OBJLIST;
    typedef typename std::unordered_map<T*, typename OBJLIST::iterator, THashFun, TCompare> OBJMAP;
    OBJMAP  m_Map;
    OBJLIST m_TOList;
    typename OBJMAP::iterator  m_MapIt;
    typename OBJLIST::iterator m_ListIt;
public:
    typedef typename OBJLIST::iterator listiterator;
    listiterator begin()
    {
        return m_TOList.begin();
    }
    listiterator end()
    {
        return m_TOList.end();
    }
};