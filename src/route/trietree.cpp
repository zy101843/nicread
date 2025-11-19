#include "trietree.h"
TrieTree::TrieTree()
{
    root = getItem(); //new TrieNode();
    root->count = 1;
    m_user = 0;
}
 
 
TrieTree::~TrieTree()
{
    destory(root);
}
 
void TrieTree::destory(TrieNode* root)
{
    if(root == nullptr)
    {
        return ;
    }
    for(int i=0;i<2;i++)
    {
        destory(root->nexts[i]);
    }
    delete root;
    root = nullptr;
}
 
 
int TrieTree::insert(uint32_t ip, int prefixlen , uint32_t gwip)
{
    if(ip == 0 || prefixlen <=0 || prefixlen >32)
    {
        return  -1;
    }
    TrieNode* node = root;
    TrieNode *tmp;
    uint32_t loalIp = ip;
    uint32_t index;
    for(int i=0; i < prefixlen; i++)
    {
        index =  loalIp & 0x80000000;
        index >>= 31;
        loalIp <<= 1;
        tmp = node->nexts[index];
        if(nullptr == tmp)
        {
            tmp = getItem();// new TrieNode();
            node->nexts[index] = tmp;
        }
        node->count++;
        node = tmp;

    }
    if(prefixlen != 32)
    {
        node->ip = ip >> (32 - prefixlen);
    }
    else 
    {
        node->ip = ip;
    }
    node->gwip  = gwip ;
    node->count = 1;
    return 0;
}
 
TrieNode *TrieTree::search(uint32_t ip, int &prefixlen)
{
    TrieNode* node = root;
    uint32_t loalIp = ip;
    uint32_t index;
    TrieNode *find = nullptr;
    int i;
    for(i=0; i < 32; i++)
    {
        index =  loalIp & 0x80000000;
        index >>= 31;
        loalIp <<= 1;
        if(node->nexts[index] == nullptr)
        {
            break;
        }
        node = node->nexts[index];
        find = node;
    }
    if (find != nullptr)
    {
        if(32 == i)
        {
            if (node->ip == ip)
            {
                prefixlen = i;
                return find;
            }
            return nullptr;
        }
        if ((node->ip != 0) &&  (node->ip == ip >> (32 - i)))
        {
            prefixlen = i;
            return find;
        }
        else
        {
            return nullptr;
        }
    }
    return nullptr;
}
 
int TrieTree::Delete(uint32_t ip, int prefixlen)
{
   if(ip == 0 || prefixlen <=0 || prefixlen >32)
    {
        return  -1;
    }
    TrieNode *node = root;
    TrieNode *tmp;
    uint32_t loalIp = ip;
    uint32_t index;
    for (int i = 0; i < prefixlen; i++)
    {
        index = loalIp & 0x80000000;
        index >>= 31;
        loalIp <<= 1;

        tmp = node->nexts[index];
        if (--(node->count) == 0)
        {
            delete node;
        }
        node = tmp;
    }
    return 0;
}

int TrieTree::initBuf()
{
    int count = 1000;
    int oneSize = sizeof(TrieNode);
    oneSize = (oneSize + 7) & ~7;
    int totalSize = oneSize * count;
    uint8_t *buf = new uint8_t[totalSize];
    uint8_t *end = buf + totalSize;
    uint8_t *post = buf;
    TrieNode *item;
    for (; post < end; post += oneSize)
    {
         item  = (TrieNode *)post;  
         m_FreeIte.push(item); 
    }
    m_memList.push_back(buf);
    return count;
}

TrieNode *TrieTree::getItem()
{
    if(m_FreeIte.empty())
    {
        initBuf();
    }
    TrieNode *item = m_FreeIte.top();
    m_FreeIte.pop();
    item = new (item) TrieNode();
    m_user++;
    return item;
}


int TrieTree::freeItem(TrieNode *item)
{
    item->~TrieNode();
    m_FreeIte.push(item);
    m_user--;
    return 1;
}
