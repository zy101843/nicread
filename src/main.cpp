#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "netport/netPortHub.h"
#include "hub/hub.h"
#include <cstring>
#include "simple_encrypt.h"
#include "niread/nicmgn.h"
#include "virnic/vnicmgn.h"
#include "network/networkMgr.h"
#include "config.h"

simple_encrypt *g_ecn;
int writeFile(const char *fileName, const char *content, int length)
{
    FILE *file = fopen(fileName, "w");
    if (file == NULL)
    {
        return -1;
    }
    int count = fwrite(content, 1, length, file);
    fclose(file);
    return count;
}

// 创建子线程
/*
struct threaParam{
    std::string nicName;
    void        *local;
    void        *outher;
    int          id ;
    void        *outherParm;
};


void *threadFunc(void *arg)
{
    return NULL;
}
void createThread(void *arg)
{
    pthread_t thread;
    int result = pthread_create(&thread, NULL, threadFunc, arg);
    if (result != 0)
    {
        printf("Failed to create thread\n");
    }
    else
    {
        pthread_detach(thread);
    }
}
 */

/*
 uint8_t key[]="liting";
 simple_encrypt *rc = new simple_encrypt(key, 6);
 uint8_t data[] = "hello world";
 uint8_t *data1 = new uint8_t[256];
 uint8_t *data2 = new uint8_t[256];
 rc->encrypt_decrypt(data, 11, data1 ,2);
 rc->decrypt_decrypt(data1, 13, data2);
 */

int main(int argc, char* argv[])
{
    int bakRun= 0;
    if (argc >= 2)
    {
        if (0 == strcmp(argv[1], "daemon") || 0 == strcmp(argv[1], "d"))
        {
            daemon(1, 0);
            bakRun = 1;
        }
    }

    config *cfg = new config();
    bool readconfig = cfg->readConfig("./config.xml");
    if (readconfig == false)
    {
        printf("read config error\n");
        delete cfg;
        return -1;
    }
    signal(SIGPIPE, SIG_IGN);
    g_ecn = new simple_encrypt((uint8_t *)"liting", 6);
    CHub *hub = new CHub();
 

    VNicMgn *virNic = NULL;
    NicMgn *nicMgn = NULL;
    if (cfg->m_vir)
    {
        VNicMgn *virNic = new VNicMgn();
        virNic->setHub(hub);
        virNic->setName(cfg->m_nicname, cfg->m_virip, cfg->m_virmask);
        virNic->start();
    }
    else
    {
        std::string nicName1 = cfg->m_nicname;
        NicMgn *nicMgn = new NicMgn();
        nicMgn->setName(nicName1);
        nicMgn->setHub(hub);
        nicMgn->start();
    }

    CNetworkMgr *netwokr = new CNetworkMgr();
    netwokr->setRouteMessage(hub);
    if (cfg->m_sevice)
    {
        netwokr->addListen(cfg->m_serviceip.c_str(), cfg->m_sport);
    }
    netwokr->start();

    if (cfg->m_clinet)
    {
        std::set<client*>::iterator iter = cfg->m_clients.begin(); 
        std::set<client*>::iterator end  = cfg->m_clients.end();
        for(;iter != end ; iter++)
        { 
            client *cli = *iter;
            //netwokr->addConnect(cfg->m_clientip.c_str(), cfg->m_cport, 2, hub);
            netwokr->addConnect(cli->m_clientip.c_str(), cli->m_cport, 2, hub);
        }
    }

    while (1)
    {
        sleep(10);
    }
    delete cfg;
    return 0;
}