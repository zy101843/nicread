#pragma once
#include <stdint.h>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
//#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include "../hub/hub.h"

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

class nic_proc
{
public:
    enum
    {
        BUFF_SEND_SIZE = 4096,
    };

public:
    nic_proc(const std::string &nicName);
    ~nic_proc();
public:
    int open();
    void disableCheckMac();
public:
    int writeData(uint8_t *data, int len);
    uint8_t *readData(int &len);
    uint8_t *readDataMap(int &len, midInterface *hub, void *param);
    uint8_t *processData(uint8_t *data, int len,  midInterface *hubp, void *param);
private:
    void getMacAddress();
    bool setPromiscuousMode( bool enable);
private:
    std::string m_nicName;
    int m_sock;
    uint8_t            *m_buffer;
    struct ifreq       m_ifr;
    struct sockaddr_ll m_sll;
    uint8_t m_mac[6];
    uint32_t m_macBegin;
    uint16_t m_macEnd;
    int     m_maxLen;
    void    *m_map;
    unsigned int        frame_idx;
    struct pollfd       recv_pfd;
    struct tpacket_req3 m_req;
    bool                m_checkMac;   
    int                 m_havaData;
};
