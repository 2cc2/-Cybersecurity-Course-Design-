#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>

#define BUFFSIZE 1024

void save_packet_info(int count, struct ip *ip, int n, unsigned char *buff, FILE *analysis_fp)
{
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
    strcpy(src_addr, inet_ntoa(ip->ip_src));
    strcpy(dst_addr, inet_ntoa(ip->ip_dst));

    fprintf(analysis_fp, "%4d    %15s    %15s    %5d    %5d\n", count, src_addr, dst_addr, ip->ip_p, ntohs(ip->ip_len));

    int i = 0, j = 0;
    for (i = 0; i < n; i++)
    {
        if (i != 0 && i % 16 == 0)
        {
            fprintf(analysis_fp, "    ");
            for (j = i - 16; j < i; j++)
            {
                if (buff[j] >= 32 && buff[j] <= 128)
                    fprintf(analysis_fp, "%c", buff[j]);
                else
                    fprintf(analysis_fp, ".");
            }
            fprintf(analysis_fp, "\n");
        }
        if (i % 16 == 0)
        {
            fprintf(analysis_fp, "%04x    ", i);
        }
        fprintf(analysis_fp, "%02x", buff[i]);

        if (i == n - 1)
        {
            for (j = 0; j < 15 - i % 16; j++)
            {
                fprintf(analysis_fp, "  ");
            }
            fprintf(analysis_fp, "    ");
            for (j = i - i % 16; j <= i; j++)
            {
                if (buff[j] >= 32 && buff[j] < 127)
                {
                    fprintf(analysis_fp, "%c", buff[j]);
                }
                else
                {
                    fprintf(analysis_fp, ".");
                }
            }
        }
    }
    fprintf(analysis_fp, "\n\n");
    fflush(analysis_fp);
}

void print_packet_info(int count, struct ip *ip)
{
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
    strcpy(src_addr, inet_ntoa(ip->ip_src));
    strcpy(dst_addr, inet_ntoa(ip->ip_dst));

    printf("%4d    %15s    %15s    %5d    %5d\n", count, src_addr, dst_addr, ip->ip_p, ntohs(ip->ip_len));
}

int set_promiscuous_mode(const char *interface)
{
    int sockfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        perror("socket");
        return EXIT_FAILURE;
    }

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1)
    {
        perror("ioctl(SIOCGIFFLAGS)");
        close(sockfd);
        return EXIT_FAILURE;
    }

    if (ifr.ifr_flags & IFF_PROMISC)
    {
        printf("Interface %s is already in promiscuous mode\n", interface);
        close(sockfd);
        return 0;
    }

    ifr.ifr_flags |= IFF_PROMISC;

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1)
    {
        perror("ioctl(SIOCSIFFLAGS)");
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("Interface %s set to promiscuous mode\n", interface);
    close(sockfd);
    return 0;
}

int main(int argc, char *argv[])
{
    int rawsock;
    unsigned char buff[BUFFSIZE];
    int n;
    int count = 0;
    char ch;
    char proto[6] = "", saddr[20] = "", daddr[20] = "";
    int slen = 0;
    // 打开文件
    FILE *analysis_fp = fopen("packet_analysis.txt", "a");
    if (analysis_fp == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    char *interface = "ens33";

    printf("Using interface: %s\n", interface);
    // 创建原始套接字
    rawsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rawsock < 0)
    {
        printf("raw socket error!\n");
        fclose(analysis_fp);
        exit(1);
    }

    if (set_promiscuous_mode(interface) != 0)
    {
        fclose(analysis_fp);
        exit(1);
    }
    // 处理命令行参数
    while ((ch = getopt(argc, argv, "p:s:d:h")) != -1)
    {
        switch (ch)
        {
        case 'p':
            slen = strlen(optarg);
            if (slen > 5)
            {
                fprintf(stdout, "The protocol is error!\n");
                return -1;
            }
            strncpy(proto, optarg, slen);
            proto[slen] = '\0';
            break;
        case 's':
            slen = strlen(optarg);
            if (slen > 15 || slen < 7)
            {
                fprintf(stdout, "The IP address is error!\n");
                return -1;
            }
            strncpy(saddr, optarg, slen);
            saddr[slen] = '\0';
            break;
        case 'd':
            slen = strlen(optarg);
            if (slen > 15 || slen < 7)
            {
                fprintf(stdout, "The IP address is error!\n");
                return -1;
            }
            strncpy(daddr, optarg, slen);
            daddr[slen] = '\0';
            break;
        case 'h':
            fprintf(stdout, "usage: sniffer [-p protocol] [-s source_ip_address] [-d dest_ip_address]\n"
                            "    -p    protocol[TCP/UDP/ICMP]\n"
                            "    -s    source ip address\n"
                            "    -d    dest ip address\n");
            exit(0);
        case '?':
            fprintf(stdout, "unrecognized option: %c\n", ch);
            exit(-1);
        }
    }

    while (1)
    {
        // 接收数据包
        n = recvfrom(rawsock, buff, BUFFSIZE, 0, NULL, NULL);
        if (n < 0)
        {
            printf("receive error!\n");
            fclose(analysis_fp);
            exit(1);
        }

        count++;
        struct ip *ip = (struct ip *)(buff + sizeof(struct ethhdr));
        // 根据过滤条件过滤数据包
        if (strlen(proto))
        {
            if (!strcmp(proto, "TCP") && ip->ip_p != IPPROTO_TCP)
            {
                // printf("Filtered out protocol: %d\n", ip->ip_p);
                continue;
            }
            if (!strcmp(proto, "UDP") && ip->ip_p != IPPROTO_UDP)
            {
                // printf("Filtered out protocol: %d\n", ip->ip_p);
                continue;
            }
            if (!strcmp(proto, "ICMP") && ip->ip_p != IPPROTO_ICMP)
            {
                // printf("Filtered out protocol: %d\n", ip->ip_p);
                continue;
            }
        }
        // 根据源 IP 地址过滤数据包
        if (strlen(saddr))
        {
            char address[INET_ADDRSTRLEN];
            strcpy(address, inet_ntoa(ip->ip_src));
            if (strcmp(address, saddr) != 0)
                continue;
        }
        // 根据目标 IP 地址过滤数据包
        if (strlen(daddr))
        {
            char address[INET_ADDRSTRLEN];
            strcpy(address, inet_ntoa(ip->ip_dst));
            if (strcmp(address, daddr) != 0)
                continue;
        }
        // 打印和保存数据包信息
        print_packet_info(count, ip);
        save_packet_info(count, ip, n, buff, analysis_fp);
    }

    fclose(analysis_fp);
    close(rawsock);
    return 0;
}
