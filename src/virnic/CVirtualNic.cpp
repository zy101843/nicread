#include "CVirtualNic.h"
#include <iostream>
#include <netinet/in.h> 
#include <arpa/inet.h>


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
bool CVirtualNic::Create(const std::string &devName, const std::string &ip, const std::string &mask)
{
    dev_name = devName;
    m_ip = ip;
    m_mask = mask;

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
}
int CVirtualNic::createTunDevice(const std::string &devName)
{
    struct ifreq ifr;
    int fd, err;

    std::string strCommand = "ip link delete " + devName;
    std::system(strCommand.c_str());
    
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

    strCommand = "ip link set " + devName + " up";
    std::system(strCommand.c_str());


    int fd1 = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd1 < 0) {
        perror("socket");
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, devName.c_str(), IFNAMSIZ);

    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(m_ip.c_str());

    if (ioctl(fd1, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFADDR");
    } else {
        printf("IP address set to %s\n", m_ip.c_str());
    }



    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, devName.c_str(), IFNAMSIZ);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(m_mask.c_str());

    if (ioctl(fd1, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCSIFNETMASK");
    } else {
        printf("Set Netmask: %s\n", "255.255.255.0");
    }


    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, devName.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd1, SIOCGIFHWADDR, &ifr) >= 0)
    {
        uint32_t type = ifr.ifr_hwaddr.sa_family;
        unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        memcpy(m_mac, mac, 6);
    }
    close(fd1);
    return fd;
}

uint8_t* CVirtualNic::readData(int &len)
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