#include "scan.h"

#define MAX_RESULTS 1000

// 构造 ICMP 数据包
void make_icmp8_packet(struct icmp *icmp, int len, int n)
{
    memset(icmp, 0, len);
    // 记录发送时间
    gettimeofday((struct timeval *)(icmp->icmp_data), (struct timezone *)0);
    // 填充ICMP头部
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = 0;
    icmp->icmp_seq = n;
    // 计算校验和
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = checksum((u_int16_t *)icmp, len);
}

// 计算时间差
void tvsub(struct timeval *out, struct timeval *in)
{
    if ((out->tv_usec -= in->tv_usec) < 0)
    {
        out->tv_sec--;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

// 计算校验和
u_int16_t checksum(u_int16_t *data, int len)
{
    u_int32_t sum = 0;
    for (; len > 1; len -= 2)
    {
        sum += *data++;
        if (sum & 0x80000000)
            sum = (sum & 0xffff) + (sum >> 16);
    }
    if (len == 1)
    {
        u_int16_t i = 0;
        *(u_char *)(&i) = *(u_char *)data;
        sum += i;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (sum == 0xffff) ? sum : ~sum;
}

void write_results_to_file(char results[][32], int result_count)
{
    FILE *csv_file = fopen("log.csv", "w");
    if (csv_file == NULL)
    {
        perror("Failed to open CSV file");
        exit(EXIT_FAILURE);
    }
    fprintf(csv_file, "IP Address,RTT (ms)\n");
    for (int i = 0; i < result_count; i++)
    {
        fprintf(csv_file, "%s\n", results[i]);
    }
    fclose(csv_file);
}

void scanhost(const char *start_ip, const char *end_ip)
{
    struct sockaddr_in send_sa;
    int s;                      /* 原始套接字文件描述符         */
    char send_buff[PACKET_LEN]; /* 发送缓冲区                   */
    char recv_buff[BUFSIZE];    /* 接收缓冲区                   */
    int start_ip_int;           /* 起始扫描IP地址             */
    int end_ip_int;             /* 终止扫描IP地址             */
    int dst_ip;                 /* 当前扫描IP地址             */
    int on = 1;                 /* ON                             */
    /*暂存结果*/
    char results[MAX_RESULTS][32];
    int result_count = 0;
    /* 解析起始和结束IP地址 */
    start_ip_int = ntohl(inet_addr(start_ip));
    end_ip_int = ntohl(inet_addr(end_ip));
    /* 创建原始套接字以发送 ICMP/IP 数据包 */
    memset(&send_sa, 0, sizeof(send_sa));
    send_sa.sin_family = AF_INET;
    /* 设置允许广播 */
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("socket(SOCK_RAW, IPPROTO_ICMP)");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0)
    {
        perror("setsockopt(SOL_SOCKET, SO_BROADCAST)");
        exit(EXIT_FAILURE);
    }
    /*
     * 开始扫描指定范围内的主机
     */
    for (dst_ip = start_ip_int; dst_ip <= end_ip_int; dst_ip++)
    {
        int i; /* 循环计数器 */
        send_sa.sin_addr.s_addr = htonl(dst_ip);

        for (i = 0; i < 3; i++)
        {
            struct timeval tv; /* 时间变量 */

            printf("scan %s (%d)\r", inet_ntoa(send_sa.sin_addr), i + 1);
            fflush(stdout);
            /* 构造 ICMP 数据包（类型为 8 表示 ICMP 请求） */
            make_icmp8_packet((struct icmp *)send_buff, PACKET_LEN, i);
            if (sendto(s, (char *)&send_buff, PACKET_LEN, 0, (struct sockaddr *)&send_sa, sizeof(send_sa)) < 0)
            {
                perror("sendto");
                exit(EXIT_FAILURE);
            }
            /* 设置 select 超时时间 */
            tv.tv_sec = 0;
            tv.tv_usec = 200 * 1000;

            while (1)
            {
                fd_set readfd; /* select 可读文件描述符集合 */
                struct ip *ip; /* IP 头指针                   */
                int ihlen;     /* IP 头长度                   */
                               /* 设置 select 可读文件描述符集合 */
                FD_ZERO(&readfd);
                FD_SET(s, &readfd);
                /* 接收数据包 */
                if (select(s + 1, &readfd, NULL, NULL, &tv) <= 0)
                    break;

                if (recvfrom(s, recv_buff, BUFSIZE, 0, NULL, NULL) < 0)
                {
                    perror("recvfrom");
                    exit(EXIT_FAILURE);
                }

                ip = (struct ip *)recv_buff;
                ihlen = ip->ip_hl << 2;
                if (ip->ip_src.s_addr == send_sa.sin_addr.s_addr)
                {
                    struct icmp *icmp;

                    icmp = (struct icmp *)(recv_buff + ihlen);
                    if (icmp->icmp_type == ICMP_ECHOREPLY)
                    {
                        /* 打印响应主机的IP地址 */
                        printf("%-15s", inet_ntoa(*(struct in_addr *)&(ip->ip_src.s_addr)));
                        /* 计算往返时间（RTT）并打印 */
                        gettimeofday(&tv, (struct timezone *)0);
                        tvsub(&tv, (struct timeval *)(icmp->icmp_data));
                        double rtt = tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
                        snprintf(results[result_count], 32, "%s,%8.4f", inet_ntoa(*(struct in_addr *)&(ip->ip_src.s_addr)), rtt);
                        result_count++;
                        if (result_count >= MAX_RESULTS)
                        {
                            fprintf(stderr, "Result buffer overflow\n");
                            write_results_to_file(results, result_count);
                            close(s);
                            return;
                        }
                        printf(": RTT = %8.4f ms\n", tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0);
                        goto exit_loop;
                    }
                }
            }
        }
    exit_loop:;
    }

    write_results_to_file(results, result_count);
    close(s);
}
