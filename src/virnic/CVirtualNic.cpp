#include "CVirtualNic.h"
#include <iostream>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <linux/if_arp.h> 
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/mman.h>
#include <sys/types.h>


CVirtualNic::CVirtualNic()
{
    tun_fd = -1;
    m_buffer = new uint8_t[BUFF_SEND_SIZE];
}

CVirtualNic::~CVirtualNic()
{
    Close();
}

int CVirtualNic::open()
{
    return tun_fd;
}

bool CVirtualNic::Create(const std::string &devName, const std::string &ip, const std::string &mask, const uint8_t *mac)
{
    dev_name = devName;
    m_ip     = ip;
    m_mask   = mask;
    memcpy(m_mac, mac, 6);
    tun_fd = createTunDevice(devName);
   
    if (tun_fd < 0)
    {
        std::cout << "Failed to create tun device" << std::endl;
        return false;
    }
    return true;
}
void CVirtualNic::Close()
{
    if (tun_fd >= 0)
    {
        close(tun_fd);
        tun_fd = -1;
    }
    std::string strCommand = "ip link delete " + dev_name;
    std::system(strCommand.c_str());
    delete m_buffer;
    m_buffer = NULL;
}

static int set_ethtool_value(int sock, const char *ifname, int set_cmd, int val) {
    struct ifreq ifr;
    struct ethtool_value eval;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    eval.cmd = set_cmd;
    eval.data = val;

    ifr.ifr_data = (caddr_t)&eval;

    if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
        return -1;
    }
    return 0;
}

int setethtool(const char *argv) 
{
   
    const char *ifname =argv;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    struct { int set_cmd; int get_cmd; const char *name; } ops[] = 
    {
        { ETHTOOL_SGSO, ETHTOOL_GGSO, "GSO" },
        { ETHTOOL_SGRO, ETHTOOL_GGRO, "GRO" },
        { ETHTOOL_STSO, ETHTOOL_GTSO, "TSO" },
    };

    for (size_t i = 0; i < sizeof(ops)/sizeof(ops[0]); ++i) 
    {
        if (set_ethtool_value(sock, ifname, ops[i].set_cmd, 0) < 0) 
        {
            fprintf(stderr, "Warning: failed to set %s off on %s: %s\n", ops[i].name, ifname, strerror(errno));
        }
         else 
        {
            printf("%s: set off (request sent)\n", ops[i].name);
        }
    }
    close(sock);
    return 0;
}

int set_mac_addr(const char *dev, unsigned char *mac) 
{
    struct ifreq ifr;
    int sock, err;
    //int err;

    // 创建 socket 用于设置 MAC
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
       perror("socket");
        return sock;
    }

    struct
    {
        int set_cmd;
        int get_cmd;
        const char *name;
    } ops[] =
        {
            {ETHTOOL_SGSO, ETHTOOL_GGSO, "GSO"},
            {ETHTOOL_SGRO, ETHTOOL_GGRO, "GRO"},
            {ETHTOOL_STSO, ETHTOOL_GTSO, "TSO"},
        };

    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); ++i)
    {
        if (set_ethtool_value(sock, dev, ops[i].set_cmd, 0) < 0)
        {
            fprintf(stderr, "Warning: failed to set %s off on %s: %s\n", ops[i].name, dev, strerror(errno));
        }
        else
        {
            printf("%s: set off (request sent)\n", ops[i].name);
        }
    }

    // 设置 MAC 地址
    printf("will setting MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);

    if ((err = ioctl(sock, SIOCSIFHWADDR, &ifr)) < 0) 
    {
        perror("ioctl SIOCSIFHWADDR");
        close(sock);
        return err;
    }

    // 激活接口
    ifr.ifr_flags |= IFF_UP;
    if ((err = ioctl(sock, SIOCSIFFLAGS, &ifr)) < 0) 
    {
        perror("ioctl SIOCSIFFLAGS");
        close(sock);
        return err;
    }
    close(sock);
    return 0;
}
int set_juest_mac_addr(int sock, const char *dev, unsigned char *mac) 
{
    struct ifreq ifr;
    int err;
    printf("will setting MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
    if ((err = ioctl(sock, SIOCSIFHWADDR, &ifr)) < 0) 
    {
        perror("ioctl SIOCSIFHWADDR");
        return err;
    }
    return 0;
}


int CVirtualNic::createTunDevice(const std::string &devName)
{
    struct ifreq ifr;
    int fd, err;

    std::string strCommand;
    //std::system(strCommand.c_str());
    
    if ((fd = ::open("/dev/net/tun", O_RDWR)) < 0)
    {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, devName.c_str(), IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    int fd1 = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd1 < 0) 
    {
        perror("socket");
    }
    set_mac_addr(devName.c_str(), m_mac);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, devName.c_str(), IFNAMSIZ);

    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(m_ip.c_str());

    if (ioctl(fd1, SIOCSIFADDR, &ifr) < 0) 
    {
        perror("ioctl SIOCSIFADDR");
    } 
    else 
    {
        printf("IP address set to %s\n", m_ip.c_str());
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, devName.c_str(), IFNAMSIZ);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(m_mask.c_str());

    if (ioctl(fd1, SIOCSIFNETMASK, &ifr) < 0) 
    {
        perror("ioctl SIOCSIFNETMASK");
    } 
    else 
    {
        printf("Set Netmask: %s\n", "255.255.255.0");
    }
    bool condition = false;
    do
    {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, devName.c_str(), IFNAMSIZ - 1);
        if (ioctl(fd1, SIOCGIFHWADDR, &ifr) >= 0)
        {
            uint32_t type = ifr.ifr_hwaddr.sa_family;
            unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
            printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

            if (memcmp(mac, m_mac, 6) != 0)
            {
                set_juest_mac_addr(fd1, devName.c_str(), m_mac);
                condition = true;
                usleep(100000);
            }
            else
            {
                memcpy(m_mac, mac, 6);
                condition =false;
            }
        }
        
    } while (condition);
    close(fd1);
    
    strCommand = "sysctl -w net.ipv6.conf." + devName + ".disable_ipv6=1";
    std::system(strCommand.c_str());
    return fd;
}

uint8_t *CVirtualNic::readData(int &len)
{
    int ret = ::read(tun_fd, m_buffer, BUFF_SEND_SIZE);
	if (ret < 0)
	{
		std::cout << "::read return <0: " << strerror(errno) << std::endl;
	}
    len = ret;
    return m_buffer;
}

int CVirtualNic::writeData(const uint8_t *buffer, int len)
{   
    static uint8_t la[] ={ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    if( 0 == memcmp(buffer, la, 6))
    {
        return ::write(tun_fd, buffer, len);
    }
    if(0 == memcmp(m_mac, buffer, 6))
    {
        return ::write(tun_fd, buffer, len);
    }
    return len;
}
