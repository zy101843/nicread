#pragma once
#include <stdint.h>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>

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

public:
    int writeData(uint8_t *data, int len);
    uint8_t *readData(int &len);

private:
    void getMacAddress();
    bool setPromiscuousMode( bool enable);

private:
    std::string m_nicName;
    int m_sock;
    uint8_t *m_buffer;
    struct ifreq m_ifr;
    struct sockaddr_ll m_sll;
    uint8_t m_mac[6];
    int     m_maxLen;
};
