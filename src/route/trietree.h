#pragma  once
#include <stdint.h>
#include <stack>
#include <vector>
#include <string>

class TrieNode{
public:
    
    uint32_t  ip;
    uint32_t  gwip;
    TrieNode* nexts[2];
    TrieNode()
    {
        count = 0;
        nexts[0] = nullptr;
        nexts[1] = nullptr;
        ip   = 0;
        gwip = 0;
    }
    ~TrieNode()
    {

    }
    int count; 
};

class TrieTree{

public:
    TrieTree();
    ~TrieTree();
    int insert(uint32_t  ip, int prefixlen, uint32_t gwip);
    TrieNode* search(uint32_t ip, int &prefixlen);
    int Delete(uint32_t ip, int prefixlen);
    void destory(TrieNode *root);

private:
    int initBuf();
    TrieNode *getItem();
    int freeItem(TrieNode *item);

public:
    int m_user;
    std::string m_path;
private:
    TrieNode *root;

private:
    std::vector<uint8_t *> m_memList;
    std::stack<TrieNode *> m_FreeIte;
};
 