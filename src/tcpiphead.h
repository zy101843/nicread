#pragma once
#pragma pack(1)
#include <stdint.h>
#define IP_TCP_TYPE  0x06
#define IP_UDP_TYPE  0x11
#define ICMPV6       0x3a
#define ETH_ALEN_T   0x06
#define IP6_NEXTH_ICMP6     58


#pragma pack(1)
struct compact_eth_hdr
{
    unsigned char   h_dest[ETH_ALEN_T];
    unsigned char   h_source[ETH_ALEN_T];
    uint16_t        h_proto;
};

struct compact_ip_hdr {
    uint8_t	ihl : 4,
            version : 4;
    uint8_t	    tos;
    uint16_t	tot_len;
    uint16_t	id;
    uint16_t	frag_off;
    uint8_t	    ttl;
    uint8_t	    protocol;
    uint16_t	check;
    uint32_t	saddr;
    uint32_t	daddr;
};
struct compact_ipv6_hdr {
    uint8_t		priority : 4,
                version : 4;
    uint8_t		flow_lbl[3];
    uint16_t	payload_len;
    uint8_t		nexthdr;
    uint8_t		hop_limit;
    in6_addr    saddr;
    in6_addr    daddr;
};
struct icmp_echo_hdr {
  uint8_t    type;
  uint8_t    code;
  uint16_t   chksum;
  uint16_t   id;
  uint16_t   seqno;
} ;

struct icmp_mtu_hdr {
    uint8_t    type;
    uint8_t    code;
    uint16_t   chksum;
    uint32_t   mtu;
};


typedef struct tagUDPHDR
{
    uint16_t SrcPort;			//source udp port
    uint16_t DesPort;			//detination udp port
    uint16_t Ulen;			    //udp datagram length contain the header and data
    uint16_t CheckSum;			//udp checksum is the  pseudo checksum
}UDPHDR, *PUDPHDR;

enum TCP_FLAG
{
    TCP_FLAG_URG = 0x30,
    TCP_FLAG_ACK = 0x10,
    TCP_FLAG_PSH = 0x08,
    TCP_FLAG_RST = 0x04,
    TCP_FLAG_SYN = 0x02,
    TCP_FLAG_FIN = 0x01
};
typedef struct tagTCPHDR
{
    uint16_t SrcPort;			//source udp port
    uint16_t DesPort;			//detination udp port
    uint32_t ulSeq;			    //
    uint32_t ulAck;			    //
    uint8_t Ver : 4;			//
    uint8_t hdLen : 4;			//
    uint8_t FLAG;				//
    uint16_t WinSize;			//
    uint16_t CheckSum;		//
}TCPHDR, *PTCPHDR;



typedef union {
    uint64_t v6l[2];
    uint32_t v6[4];
    uint16_t v6s[8];
    uint8_t  v6c[16];
    uint32_t v4;
} ip_tr_addr;

struct arp_hdr
{
    uint16_t htype;     //hdtyep
    uint16_t ptype;     //protocol type
    uint8_t  haddrlen;  //hardware addr length
    uint8_t  paddrlen;  //protocol addr len
    uint16_t  optype;   //1 is request , 2 is reply
    uint8_t  srcmac[6];
    uint32_t srcip;
    uint8_t  dstmac[6];
    uint32_t dstip;
};

struct icmp6_hdr
{
    uint8_t  type;
    uint8_t  code;
    uint16_t chksum;
    uint32_t data;
};

struct ns_header 
{
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint32_t reserved;
    uint32_t target_address[4];
};

struct na_header
{
    uint8_t  type;
    uint8_t  code;
    uint16_t chksum;
    uint8_t  flags;
    uint8_t  reserved[3];
    uint32_t target_address[4];
};
struct lladdr_option
{
    uint8_t type;
    uint8_t length;
    uint8_t addr[6];
};

struct ra_header
{
    uint8_t  type;
    uint8_t  code;
    uint16_t chksum;
    uint8_t  current_hop_limit;
    uint8_t  flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;
    
} ;
struct mtu_option 
{
    uint8_t  type;
    uint8_t  length;
    uint16_t reserved;
    uint32_t mtu;
} ;

typedef struct ICMPhead
{
    uint8_t type;//类型
    uint8_t code;//代码
    uint16_t checkSum;//校验和
    uint16_t ident;//进程标识符
    uint16_t seqNum;//序号
} ICMPhead;

struct icmp6_echo_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint16_t id;
    uint16_t seqno;
};
#pragma pack()

struct IPANDPORT4ITEM
{
    ip_tr_addr srcIP;
    ip_tr_addr dstIP;
    uint16_t   srcPort;
    uint16_t   dstPort;
    uint16_t   protcol;
    bool       isIPV6;
    IPANDPORT4ITEM()
    {
        isIPV6 = false;
    }
    void restIp()
    {
        isIPV6 = false;
        srcIP.v6[0] = 0;
        srcIP.v6[1] = 0;
        srcIP.v6[2] = 0;
        srcIP.v6[3] = 0;

        dstIP.v6[0] = 0;
        dstIP.v6[1] = 0;
        dstIP.v6[2] = 0;
        dstIP.v6[3] = 0;
    }
};
struct IPTYPE
{
    ip_tr_addr ip;
    bool       isV6;
  
    IPTYPE()
    {
        isV6 = false;
        ip.v6[0] = 0;
        ip.v6[1] = 0;
        ip.v6[2] = 0;
        ip.v6[3] = 0;
    }
};
#pragma pack()