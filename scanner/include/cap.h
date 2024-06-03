#ifndef CAP_H
#define CAP_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <semaphore.h>
#include <arpa/inet.h>
#include <sys/types.h>

#define SIZE_ETHERNET 14
#define ETH_ADDR_LEN 6
#define IP_ADDR_LEN 4
typedef unsigned char u_char;

// 主机列表结构体
struct host_list
{
  uint32_t ip; /* 用于对列表进行排序 */
  char ip_str[16];
  char mac_str[18];
  struct host_list *next;
};

// 捕获结构体
struct cap_struct
{
  sem_t *sem;             /* 用于同步捕获线程和主线程 */
  pcap_t *ctx;            /* 给主线程的 pcap 上下文以终止循环 */
  bool *ok;               /* 捕获线程是否正常？ */
  const char *dev;        /* 两个线程使用的设备 */
  struct host_list *list; /* 网络中的主机列表 */
};

// ARP 头结构体
struct arp_hdr
{
  u_int16_t arp_htype;
  u_int16_t arp_ptype;
  u_char arp_hlen;
  u_char arp_plen;
  u_int16_t arp_oper;
  u_char arp_sha[ETH_ADDR_LEN];
  u_char arp_sip[IP_ADDR_LEN];
  u_char arp_dha[ETH_ADDR_LEN];
  u_char arp_dip[IP_ADDR_LEN];
};

void *cap(void *args);

#endif
