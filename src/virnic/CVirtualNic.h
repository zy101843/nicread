#pragma once

#include <string>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
//#include <linux/if.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <cstring>

class CVirtualNic
{
public:
    enum
    {
        BUFF_SEND_SIZE = 4096,
    };

public:
    CVirtualNic();
    ~CVirtualNic();

    public:

    bool Create(const std::string &devName, const std::string &ip, const std::string &mask);
    uint8_t *readData(int &len);
    int writeData(const uint8_t *buffer, int len);

    void Close();
    std::string getDevName() { return dev_name; }
    int open();

private:
    int tun_fd;
    std::string dev_name;
    std::string m_ip;
    std::string m_mask;
    int createTunDevice(const std::string &devName);

public:
    uint8_t *m_buffer;
    uint8_t m_mac[6];
};