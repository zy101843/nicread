
#include "readnic.h"
#include <errno.h>
#include <cstring>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define MY_PACKET_AUXDATA 8
const uint8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


#define TPACKET_ALIGNMENT 16
#define BLOCK_SIZE (1024 * 4)
#define BLOCK_NR   64   //user 2^n  mask easy
#define FRAME_SIZE TPACKET_ALIGN(2048)
#define BLOCK_TIMEOUT_MS 1
#define BLOCK_NR_MASK (BLOCK_NR-1)
#define BUSY_POLL   50         // 忙碌轮询 50 微秒

nic_proc::nic_proc(const std::string &nicName)
{
    m_nicName = nicName;
    m_sock = INVALID_SOCKET;
    m_buffer = new uint8_t[BUFF_SEND_SIZE];
    m_maxLen = 0;
    memset(&m_ifr, 0, sizeof(m_ifr));
    frame_idx = 0;

    memset(&m_req, 0, sizeof(m_req));

    m_req.tp_block_size = BLOCK_SIZE;
    m_req.tp_block_nr = BLOCK_NR;
    m_req.tp_frame_size = FRAME_SIZE;
    m_req.tp_frame_nr = (m_req.tp_block_size / m_req.tp_frame_size) * m_req.tp_block_nr;
    m_req.tp_retire_blk_tov = BLOCK_TIMEOUT_MS;
    m_checkMac = true;
    m_map      = NULL;
    m_havaData = 0;
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
    if (m_map)
    {
        munmap(m_map, m_req.tp_block_size * m_req.tp_block_nr);
    }
}

 void nic_proc::disableCheckMac()
 {
    m_checkMac = false;
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

        m_macBegin = *(uint32_t *)mac;
        m_macEnd = *(uint16_t *)(mac + 4);
    }
}

// 混在模式

bool nic_proc::setPromiscuousMode(bool enable)
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
        if (ifr.ifr_flags & IFF_PROMISC)
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

    eval.cmd = ETHTOOL_SGRO;
    eval.data = 0;
    ifr.ifr_data = (caddr_t)&eval;

    if (ioctl(m_sock, SIOCETHTOOL, &ifr) < 0)
    {
        perror("ioctl ETHTOOL_SGRO error");
    }

    eval.cmd = ETHTOOL_STSO; // 关闭 TSO
    eval.data = 0;
    ifr.ifr_data = (char *)&eval;

    if (ioctl(m_sock, SIOCETHTOOL, &ifr) < 0)
    {
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
    int version = TPACKET_V3;
    if (setsockopt(sockfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0)
    {
        perror("Failed to set PACKET_VERSION");
    }
    
    int busy_poll = BUSY_POLL;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll)) < 0) {
        perror("setsockopt SO_BUSY_POLL");
    }

    if (setsockopt(sockfd, SOL_PACKET, PACKET_RX_RING, &m_req, sizeof(m_req)) < 0)
    {
        perror("PACKET_RX_RING failed");
    }
    else
    {
        m_map = mmap(NULL, m_req.tp_block_size * m_req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED |MAP_LOCKED, sockfd, 0);
        if (m_map == MAP_FAILED)
        {
            perror("mmap failed");
            m_map = 0;
        }
        else 
        {
             printf("user  nmap \n");
        }
    }

    recv_pfd.fd = m_sock;
    recv_pfd.events = POLLIN;

    return sockfd;
}

int nic_proc::writeData(uint8_t *data, int len)
{
    if(len <=0 || len > 1514)
    {
        return 0;
    }
    
    int ret = sendto(m_sock, data, len, 0, (struct sockaddr *)&m_sll, sizeof(struct sockaddr_ll));
    if (ret == -1)
    {
        perror("sendto failed");
    }
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

/*
uint8_t *nic_proc::readDataMap(int &len, midInterface *hubp, void *param)
{
 
    if (NULL == m_map)
    {
        unsigned char *data = readData(len);
        if (len > 0)
        {
            processData(data, len, hubp, param);
        }
    }
    if (poll(&recv_pfd, 1, -1) < 0)
    {
        perror("poll failed");
        return NULL;
    }
    do
    {
        struct tpacket_block_desc *block = (struct tpacket_block_desc *)((char *)m_map + (frame_idx * BLOCK_SIZE));
        if (!(block->hdr.bh1.block_status & TP_STATUS_USER))
        {
            perror("not user poll failed");
            return NULL;
        }

        struct tpacket3_hdr *frame = (struct tpacket3_hdr *)((char *)block + block->hdr.bh1.offset_to_first_pkt);
        int num_pkts = block->hdr.bh1.num_pkts;
        unsigned char *data;
        for (int i = 0; i < num_pkts; i++)
        {
            if (frame->tp_status & TP_STATUS_USER)
            {
                data = (unsigned char *)frame + frame->tp_mac;
                len = frame->tp_len;
                processData(data, len, hubp, param);
            }
            else
            {
                printf("nic read body is not data TP_STATUS_USER \n");
            }
            frame = (struct tpacket3_hdr *)((char *)frame + frame->tp_next_offset);
        }
        block->hdr.bh1.block_status = TP_STATUS_KERNEL;
        frame_idx += 1;
        frame_idx &= (BLOCK_NR_MASK);
        len = 0;
    } while (condition);
    return NULL;
}
*/

uint8_t *nic_proc::readDataMap(int &len, midInterface *hubp, void *param)
{
 
    if (NULL == m_map)
    {
        unsigned char *data = readData(len);
        if (len > 0)
        {
            processData(data, len, hubp, param);
        }
    }

    struct tpacket_block_desc *block = (struct tpacket_block_desc *)((char *)m_map + (frame_idx * m_req.tp_block_size));
    uint32_t status = block->hdr.bh1.block_status;
    if ((status & TP_STATUS_USER) == 0)
    {
        if (poll(&recv_pfd, 1, -1) < 0)
        {
            perror("poll failed");
            return NULL;
        }
        m_havaData = 0;
    }
    else 
    {
        m_havaData++;
        //printf("hava data %d\n", m_havaData);
    }
   
    if (!(block->hdr.bh1.block_status & TP_STATUS_USER))
    {
        perror("not user poll failed");
        return NULL;
    }

    struct tpacket3_hdr *frame = (struct tpacket3_hdr *)(((char *)block) + block->hdr.bh1.offset_to_first_pkt);
    int num_pkts = block->hdr.bh1.num_pkts;
    unsigned char *data;
    for (int i = 0; i < num_pkts; i++)
    {
        if (frame->tp_status & TP_STATUS_USER)
        {
            data = ((unsigned char *)frame) + frame->tp_mac;
            len = frame->tp_len;
            uint32_t caplen = frame->tp_snaplen;
            if(caplen == len)
            {
                processData(data, caplen, hubp, param);
            }
            else 
            {
                  printf("nic read error len %d    %u \n", len, caplen);
            }
        }
        else
        {
            printf("nic read body is not data TP_STATUS_USER \n");
        }
        frame = (struct tpacket3_hdr *)(((char *)frame) + frame->tp_next_offset);
    }
    block->hdr.bh1.block_status = TP_STATUS_KERNEL;
    __sync_synchronize();
    frame_idx += 1;
    frame_idx &= (BLOCK_NR_MASK);
    len = 0;
    return NULL;
}

uint8_t *nic_proc::readData(int &len)
{
    ssize_t num_bytes = recvfrom(m_sock, m_buffer, BUFF_SEND_SIZE, 0, NULL, NULL);
    if (num_bytes == -1)
    {
        perror("recvfrom() failed");
        return NULL;
    }

    bool dst = ((*((uint32_t *)m_buffer)) == m_macBegin) && ((*((uint16_t *)(m_buffer + 4))) == m_macEnd);
    bool src = ((*((uint32_t *)(m_buffer + 6))) == m_macBegin) && ((*((uint16_t *)(m_buffer + 10))) == m_macEnd);
    if (dst || src)
    {
        return NULL;
    }

    len = num_bytes;
    if (len > m_maxLen)
    {
        m_maxLen = len;
        printf("max len is %d \n", m_maxLen);
    }
    return m_buffer;
}

uint8_t *nic_proc::processData(uint8_t *data, int len, midInterface *hubp, void *param)
{
    if (len <= 0 || len > 1514)
    {
        return NULL;
    }

    if (m_checkMac)
    {
        bool dst = ((*((uint32_t *)data)) == m_macBegin) && ((*((uint16_t *)(data + 4))) == m_macEnd);
        bool src = ((*((uint32_t *)(data + 6))) == m_macBegin) && ((*((uint16_t *)(data + 10))) == m_macEnd);
        if (!(dst || src))
        {
            hubp->addData(data, len, param);
        }
    }
    else
    {
        hubp->addData(data, len, param);
    }
    return NULL;

}
