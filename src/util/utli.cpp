#include "util.h"
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
char *refind(char find, char *buf, int len, int rebegin)
{
    char *end;
    if (-1 == rebegin)
    {
        end = buf + rebegin;
    }
    else
    {
        end = buf + len;
        end--;
    }
    char *post = 0;
    for (; end >= buf; end--)
    {
        if (*end == find)
        {
            post = end;
            break;
        }
    }
    return post;
}

uint16_t ls_atoi(uint8_t *buf, int len)
{
    uint8_t  *end   = buf + len;
    uint16_t result = 0;
    uint8_t  ch;
    while (buf < end)
    {
        ch = *buf;
        if (ch < '0' && ch > '9')
        {
            return 0;
        }
        result *= 10;
        result += ch - '0';
        buf++;
    }
    return result;
}
uint32_t l_atoi(uint8_t *buf, int len)
{
    uint8_t  *end   = buf + len;
    uint32_t result = 0;
    uint8_t  ch;
    while (buf < end)
    {
        ch = *buf;
        if (ch < '0' && ch > '9')
        {
            return 0;
        }
        result *= 10;
        result += ch - '0';
        buf++;
    }
    return result;
}
uint64_t ll_atoi(uint8_t *buf, int len)
{
    uint8_t  *end   = buf + len;
    uint64_t result = 0;
    uint8_t  ch;
    while (buf < end)
    {
        ch = *buf;
        if (ch < '0' && ch > '9')
        {
            return 0;
        }
        result *= 10;
        result += ch - '0';
        buf++;
    }
    return result;
}
int buf_ipv6(uint8_t *buf, int len, ip_tr_addr &add)
{
    uint8_t  *end   = buf + len;
    uint8_t  ch;
    uint8_t  data;
    int curPost = 0;
    add.v6c[curPost] = 0;
    int ret =0;
    while (buf < end)
    {
        ch = *buf;
        if (ch >= '0' && ch <= '9')
        {
            data = ch - '0';
            add.v6c[curPost] <= 4;
            add.v6c[curPost] |= data;

        }
        else if (ch >= 'a' && ch <= 'f')
        {
            data = ch - 'a';
            add.v6c[curPost] <= 4;
            add.v6c[curPost] |= data;
        }
        else if (ch >= 'A' && ch <= 'F')
        {
            data = ch - 'A';
            add.v6c[curPost] <= 4;
            add.v6c[curPost] |= data;
        }
        else if (':' == ch)
        {
            curPost++;
            add.v6c[curPost] = 0;
        } 
        else
        {
            ret = -1;
        }
        buf++;
    }
    return ret;
}
int str_ip(uint8_t *buf, int len, ip_tr_addr &add)
{
    bool isv6 = false;
    int ret = 0;
    if (len > 5)
    {
        if (':' == buf[4])
        {
            isv6 = true;
        }
    }
    if (isv6)
    {
        ret = buf_ipv6(buf, len, add);
        if (-1 == ret)
        {
            printf("error _ v6 %s %d", __FILE__, __LINE__);
        }
        isv6 = true;
    }
    else
    {
        add.v6l[0] = 0;
        add.v6l[1] = 0;
        add.v4 = l_atoi(buf,len);
    }
    return isv6;
}

uint32_t hashFun(ip_tr_addr *ip)
{
    uint32_t seed = 0;
    seed ^= ip->v6[0] + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= ip->v6[1] + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= ip->v6[2] + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= ip->v6[3] + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    return seed;
}
uint32_t hashFun(IPANDPORT &tuple, int &type)
{
    uint32_t seed1 = 0;
    uint32_t seed2 = 0;
    uint32_t hash;

    if (tuple.port.port.sport > tuple.port.port.dport)
    {
        seed1 ^= tuple.srcIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.srcIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.srcIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.srcIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

        seed1 ^= tuple.dstIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.dstIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.dstIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.dstIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

        seed2 ^= tuple.port.port.sport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
        seed2 ^= tuple.port.port.dport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
        type = 1;
    }
    else if (tuple.port.port.sport == tuple.port.port.dport)
    {
        if (tuple.srcIP.v6l[0] == tuple.dstIP.v6l[0])
        {
            if (tuple.srcIP.v6l[1] > tuple.dstIP.v6l[1])
            {
                seed1 ^= tuple.srcIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.srcIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.srcIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.srcIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

                seed1 ^= tuple.dstIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.dstIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.dstIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.dstIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

                seed2 ^= tuple.port.port.sport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
                seed2 ^= tuple.port.port.dport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
                type  = 1;
            }
            else
            {
                seed1 ^= tuple.dstIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.dstIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.dstIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.dstIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

                seed1 ^= tuple.srcIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.srcIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.srcIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
                seed1 ^= tuple.srcIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);


                seed2 ^= tuple.port.port.dport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
                seed2 ^= tuple.port.port.sport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
                type  = 2;
            }
        }
        else if (tuple.srcIP.v6l[0] > tuple.dstIP.v6l[0])
        {
            seed1 ^= tuple.srcIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.srcIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.srcIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.srcIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

            seed1 ^= tuple.dstIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.dstIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.dstIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.dstIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

            seed2 ^= tuple.port.port.sport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
            seed2 ^= tuple.port.port.dport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);

            type  =1;
        }
        else
        {
            seed1 ^= tuple.dstIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.dstIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.dstIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.dstIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

            seed1 ^= tuple.srcIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.srcIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.srcIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
            seed1 ^= tuple.srcIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

            seed2 ^= tuple.port.port.dport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
            seed2 ^= tuple.port.port.sport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
            type   = 2;
        }
    }
    else
    {
        seed1 ^= tuple.dstIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.dstIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.dstIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.dstIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);

        seed1 ^= tuple.srcIP.v6[0] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.srcIP.v6[1] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.srcIP.v6[2] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);
        seed1 ^= tuple.srcIP.v6[3] + 0x9e3779b9 + (seed1 << 6) + (seed1 >> 2);


        seed2 ^= tuple.port.port.dport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
        seed2 ^= tuple.port.port.sport + 0x9e3779b9 + (seed2 << 6) + (seed2 >> 2);
        type   = 2;

    }
    hash = seed1 ^ seed2;
    return hash;
}

int static_cdir(const char *pPath)
{
    char *p1, *p2;
    int ret = 0;
    if ((p1 = strrchr((char*)pPath, SLASH)))
    {
        p2 = strchr((char*)pPath, SLASH);
        if (p1 == p2)
        {
            goto tail_0;
        }
        *p1 = '\0';
        DIR *pDir = opendir(pPath);
        if (!pDir)
        {
            if ((ret = static_cdir(pPath)) == 0)
            {
                if ((ret = mkdir(pPath, 0777)) == 0)
                {
                    ret = chmod(pPath, 00777);
                }
            }
        }
        else
        {
            closedir(pDir);
        }
        *p1 = SLASH;
    }
tail_0:
    return ret;
}

void createDir(const char *pPath)
{
#define INTERNAL_INTERVAL   (1000*100)
#define INTERNAL_COUNT      (5)
    unsigned int i = 0;
    for (i = 0; i < INTERNAL_COUNT; i++)
    {
        if (static_cdir(pPath) != 0)
        {
            usleep(INTERNAL_INTERVAL);
            continue;
        }
        break;
    }
    return;
}
bool fileExits(char *fileName)
{
    struct stat buffer;
    int ret = stat(fileName, &buffer);
    if (ret == -1)
    {
        return false;
    }
    return true;
}

uint32_t alignment64bitSize(uint32_t size)
{
    uint32_t ret = size;
    uint32_t midT = size & 0x07;
    if (0 != midT)
    {
        ret = size + 8 - midT;
    }
    return ret;
}
uint32_t getBit(uint32_t input, uint32_t &size)
{
    int ret = 0;
    uint32_t mid;
    for (int i =1; i < 20; i++)
    {
        mid = 1 << i;
        if (mid >= input)
        {
            size = mid;
            ret = i;
            break;
        }
    }
    return ret;
}

int WriteFileAddStr(char *pFilePath, char *pData, int nDataLen)
{
    if (pFilePath == NULL || pData == NULL || nDataLen <= 0)
    {
        return -1;
    }

    FILE *file = NULL;

    file = fopen(pFilePath, "rb+");

    if (file == NULL)
    {
        file = fopen(pFilePath, "wb");

        if (file == NULL)
        {
            return 0;
        }
    }

    fseek(file, 0x00, SEEK_END);

    fwrite(pData, 1, nDataLen, file);
    fclose(file);
    return 0;
}

