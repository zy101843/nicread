
#include "readnic.h"
#include <errno.h>
#include <cstring>
#include <linux/ethtool.h>
#include <linux/sockios.h>


#define	MY_PACKET_AUXDATA 8
const uint8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
nic_proc::nic_proc(const std::string &nicName)
{
    m_nicName = nicName;
    m_sock = INVALID_SOCKET;
    m_buffer = new uint8_t[BUFF_SEND_SIZE];
    m_maxLen = 0;
    memset(&m_ifr, 0, sizeof(m_ifr));
}

nic_proc::~nic_proc()
{
    if (m_sock != INVALID_SOCKET)
    {
        setPromiscuousMode(false);
        close(m_sock);
    }
    if (m_buffer != NULL)
    {
        delete[] m_buffer;
    }
}

void nic_proc::getMacAddress()
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, m_nicName.c_str(), IFNAMSIZ - 1);
    if (ioctl(m_sock, SIOCGIFHWADDR, &ifr) >= 0)
    {
        uint32_t type = ifr.ifr_hwaddr.sa_family;
        unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        memcpy(m_mac, mac, 6);
    }
}

//混在模式

bool nic_proc::setPromiscuousMode( bool enable)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, m_nicName.c_str(), IFNAMSIZ - 1);
    bool hava = false;
    if (ioctl(m_sock, SIOCGIFFLAGS, &ifr) == -1)
    {
        perror("ioctl(SIOCGIFFLAGS)");
        return false;
    }
    
    if (enable)
    {
        if(ifr.ifr_flags & IFF_PROMISC)
        {
            hava = true;
        }
        ifr.ifr_flags |= IFF_PROMISC;
    }
    else
    {
        ifr.ifr_flags &= ~IFF_PROMISC;
    }

    if (false == hava)
    {
        if (ioctl(m_sock, SIOCSIFFLAGS, &ifr) < 0)
        {
            perror("Error setting promiscuous mode");
        }
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, m_nicName.c_str(), IFNAMSIZ - 1);
    struct ethtool_value eval;

    eval.cmd  = ETHTOOL_SGRO; 
    eval.data = 0; 
    ifr.ifr_data = (caddr_t)&eval;

 
    if (ioctl(m_sock, SIOCETHTOOL, &ifr) < 0) {
        perror("ioctl ETHTOOL_SGRO error");
    }


    eval.cmd  = ETHTOOL_STSO;   // 关闭 TSO
    eval.data = 0;
    ifr.ifr_data = (char *)&eval;

    if (ioctl(m_sock, SIOCETHTOOL, &ifr) < 0) {
        perror("ioctl ETHTOOL_STSO error");
    }
    return true;
}
// 使用 Raw 打开网卡
int nic_proc::open()
{
    int sockfd;

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return -2;
    }

    // 2️ 获取网卡索引
 
    strncpy(m_ifr.ifr_name, m_nicName.c_str(), IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &m_ifr) == -1)
    {
        perror("ioctl() failed to get interface index");
        close(sockfd);
         return -3;
    }
    printf("Interface %s index: %d\n", m_nicName.c_str(), m_ifr.ifr_ifindex);

    // 3️ 绑定套接字到指定网卡
    memset(&m_sll, 0, sizeof(struct sockaddr_ll));
    m_sll.sll_family = AF_PACKET;
    m_sll.sll_protocol = htons(ETH_P_ALL);
    m_sll.sll_ifindex = m_ifr.ifr_ifindex; // 设置网卡索引


    if (bind(sockfd, (struct sockaddr *)&m_sll, sizeof(m_sll)) == -1)
    {
        perror("Bind failed");
        close(sockfd);
         return -4;
    }
    printf("Listening for packets on interface: %s\n", m_nicName.c_str());
    m_sock = sockfd;
    getMacAddress();
    setPromiscuousMode(true);
/*
    int val = 1;
    int ss_ret = setsockopt(sockfd, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val));

    if (ss_ret < 0)
    {
        printf("eth(%s): setsockopt: PACKET_AUXDATA failed.\n", m_nicName.c_str());
    }
    else
    {
        printf("eth(%s): setsockopt: PACKET_AUXDATA ok.\n", m_nicName.c_str());
    }
*/
    int version = TPACKET_V3;
    if (setsockopt(sockfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        perror("Failed to set PACKET_VERSION");
        //exit(EXIT_FAILURE);
    }
    return sockfd;
}

int nic_proc::writeData(uint8_t *data, int len)
{
    // 发送原始数据包
    int ret = sendto(m_sock, data, len, 0, (struct sockaddr*) & m_sll, sizeof(struct sockaddr_ll));
    if (ret == -1)
    {
        perror("sendto failed");
        //close(m_sock);
        //m_sock = -1;
    }
/*
    struct iovec   msg_iov;
    struct msghdr msg_header;

    msg_iov.iov_base = data;
    msg_iov.iov_len = len;

    msg_header.msg_name = NULL;
    msg_header.msg_namelen = 0;
    msg_header.msg_iov = &msg_iov;
    msg_header.msg_iovlen = 1;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;
    msg_header.msg_flags = 0;

    ssize_t ret = sendmsg(m_sock, &msg_header, 0);
    if (ret < 0)
    {
        printf("EthPutPacket: ret:%ld errno:%d  size:%d\n", ret, errno, len);
    }
    */
    return ret;
}

struct my_tpacket_auxdata
{
	uint32_t tp_status;
	uint32_t tp_len;
	uint32_t tp_snaplen;
	uint16_t tp_mac;
	uint16_t tp_net;
	uint16_t tp_vlan_tci;
	uint16_t tp_vlan_tpid;
};

uint8_t *nic_proc::readData(int &len)
{

/*
    struct iovec msg_iov;
	struct msghdr msg_header;
	struct cmsghdr *cmsg;
	union
	{
		struct cmsghdr cmsg;
		char buf[CMSG_SPACE(sizeof(struct my_tpacket_auxdata))];
	} cmsg_buf;



	msg_iov.iov_base = m_buffer;
	msg_iov.iov_len = BUFF_SEND_SIZE;

	msg_header.msg_name = NULL;
	msg_header.msg_namelen = 0;
	msg_header.msg_iov = &msg_iov;
	msg_header.msg_iovlen = 1;

    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    msg_header.msg_control = &cmsg_buf;
    msg_header.msg_controllen = sizeof(cmsg_buf);

    msg_header.msg_flags = 0;

    ssize_t num_bytes = recvmsg(m_sock, &msg_header, 0);
*/
    ssize_t num_bytes = recvfrom(m_sock, m_buffer, BUFF_SEND_SIZE, 0, NULL, NULL);
    if (num_bytes == -1)
    {
        perror("recvfrom() failed");
        // close(m_sock);
        return NULL;
    }
    bool dst = memcmp(m_buffer, m_mac, 6) == 0;
    bool src = memcmp(m_buffer + 6, m_mac, 6) == 0;
    if (dst || src)
    {
        return NULL;
    }
/*
    for (cmsg = CMSG_FIRSTHDR(&msg_header); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg_header, cmsg))
    {
        if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA)
        {
            struct tpacket_auxdata *aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
            printf("VLAN TCI: %u, VLAN TPID: 0x%X len %d\n", aux->tp_vlan_tci, aux->tp_vlan_tpid, aux->tp_len);
        }
    }
*/
    len = num_bytes;
    if(len > m_maxLen)
    {
        m_maxLen = len;
        printf("max len is %d \n", m_maxLen);
       
    }
    return m_buffer;
}