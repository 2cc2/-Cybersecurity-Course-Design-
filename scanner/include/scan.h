
#ifndef SCAN_H
#define SCAN_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define CHKADDRESS(_saddr_) \
        {\
          unsigned char *p = (unsigned char *) &(_saddr_);\
          if ((p[0] == 127)\
           || (p[0] == 10)\
           || (p[0] == 172 && 16 <= p[1] && p[1] <= 31)\
           || (p[0] == 192 && p[1] == 168))\
            ;\
          else {\
            fprintf(stderr, "IP address error.\n");\
            exit(EXIT_FAILURE);\
          }\
        }

#define BUFSIZE    4096
#define PACKET_LEN 72

// enum {CMD_NAME, START_IP, LAST_IP};

//构造 ICMP 数据包
void make_icmp8_packet(struct icmp *icmp, int len, int n);
// 计算时间差
void tvsub(struct timeval *out, struct timeval *in);

// 计算校验和
 
u_int16_t checksum(u_int16_t *data, int len);
void scanhost(const char *start_ip, const char *end_ip);
#endif