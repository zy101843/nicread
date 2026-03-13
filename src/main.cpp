#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fstream>
#include "hub/hub.h"
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/file.h>
#include "simple_encrypt.h"
#include "niread/nicmgn.h"
#include "virnic/vnicmgn.h"
#include "network/networkMgr.h"
#include "config.h"
#include "nat/nat.h"
#include "route/route.h"
#include "dhHand.h"
#include "rsaProc.h"

// simple_encrypt *g_ecn;
dhHand *g_dh;
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
#define LOCK_FILE "./nic.lock"
int checkAlreadyRun()
{
    int fd;
    fd = open(LOCK_FILE, O_CREAT | O_RDWR, 0666);
    if (fd < 0)
    {
        perror("can not open lock file");
        exit(EXIT_FAILURE);
    }
    if (flock(fd, LOCK_EX | LOCK_NB) == -1)
    {
        if (errno == EWOULDBLOCK)
        {
            fprintf(stderr, "auth process in\n");
            close(fd);
            exit(EXIT_FAILURE);
        }
        else
        {
            perror("add lock file error");
            close(fd);
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int bakRun = 0;
    checkAlreadyRun();
    if (argc >= 2)
    {
        if (0 == strcmp(argv[1], "daemon") || 0 == strcmp(argv[1], "d"))
        {
            daemon(1, 0);
            bakRun = 1;
            bakRun = 1;
            while (true)
            {
                pid_t pChild = fork();
                if (pChild == 0)
                {
                    break;
                }
                else
                {
                    int iLoc;
                    pChild = waitpid(pChild, &iLoc, 0);
                    std::cout << "child process exit, restart it" << std::endl;
                }
            }
        }
    }
    OpenSSL_add_all_algorithms();
    dhHand::initAllParam();
    config *cfg = new config();
    bool readconfig = cfg->readConfig("./config.xml");
    if (readconfig == false)
    {
        printf("read config error\n");
        delete cfg;
        return -1;
    }
    signal(SIGPIPE, SIG_IGN);
    CHub *hub = new CHub();
    midInterface *mid = hub;

    if (cfg->m_darpMac.size() > 0)
    {
        printf("mac %ld", cfg->m_darpMac.size());
        hub->setDropMac(&(cfg->m_darpMac));
    }

    VNicMgn *virNic = NULL;
    NicMgn *nicMgn = NULL;

    if (!cfg->m_nicname.empty())
    {
        if (cfg->m_vir)
        {
            VNicMgn *virNic = new VNicMgn();
            virNic->setHub(mid);
            virNic->setName(cfg->m_nicname, cfg->m_virip, cfg->m_virmask, cfg->m_virMac);
            virNic->start();
        }
        else
        {
            std::string nicName1 = cfg->m_nicname;
            NicMgn *nicMgn = new NicMgn();
            nicMgn->setName(nicName1, cfg->m_virMac);
            if (cfg->m_filter)
            {
                uint32_t myip   = htonl(inet_addr(cfg->m_virip.c_str()));
                uint32_t mymask = htonl(inet_addr(cfg->m_virmask.c_str()));
                hub->setVnicNat(myip & mymask, mymask);
            }
            nicMgn->setHub(mid);
            nicMgn->start();
        }
    }

    if (cfg->m_openRoute)
    {
        Route *route = new Route();
        route->readCof();
        route->setHub(mid);
        route->start();
    }

    if (cfg->m_opennat)
    {
        Nat *nat = new Nat();
        nat->setHub(mid);
        nat->start();
    }

    CNetworkMgr *netwokr = new CNetworkMgr();
    netwokr->setRouteMessage(mid);
    if (cfg->m_sevice)
    {
        std::set<ipPort *>::iterator iter = cfg->m_serviceips.begin();
        std::set<ipPort *>::iterator end = cfg->m_serviceips.end();
        for (; iter != end; iter++)
        {
            ipPort *cli = *iter;
            if (std::string::npos == cli->ip.find(':'))
            {
                netwokr->addListen(cli->ip.c_str(), cli->port, cli->keyPath);
            }
            else
            {
                netwokr->addListenV6(cli->ip.c_str(), cli->port, cli->keyPath);
            }
        }
    }
    netwokr->start();
    if (cfg->m_clinet)
    {
        std::set<ipPort *>::iterator iter = cfg->m_clients.begin();
        std::set<ipPort *>::iterator end  = cfg->m_clients.end();
        for (; iter != end; iter++)
        {
            ipPort *cli = *iter;
            for (int i = 0; i < cli->count; i++)
            {
                netwokr->addConnect(cli->ip, cli->port, 2, cli->bindport, hub, cli->mac, cli->id, cli->keyPath);
            }
        }
    }
    hub->workThread();
    while (1)
    {
        sleep(10);
    }
    delete cfg;
    return 0;
}
