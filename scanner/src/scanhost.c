#include "scanhost.h"

// 打印可用的网络接口
void printInterfaces()
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces;
  pcap_if_t *temp;

  // 查找所有设备
  if (pcap_findalldevs(&interfaces, errbuf) == -1)
  {
    printf("%s\n", errbuf);
    return;
  }

  printf("Available devices are: \n");
  // 遍历设备列表并打印有地址的设备
  for (temp = interfaces; temp != NULL; temp = temp->next)
  {
    if (temp->addresses != NULL)
    {
      printf("       * " BOLD "%s" RESET "\n", temp->name);
    }
  }

  // 释放设备列表
  pcap_freealldevs(interfaces);
}

// 检查接口是否适合扫描
bool validForScan(pcap_if_t *iface)
{
  // 检查接口是否不是回环接口并且是活动的
  if (!(iface->flags & PCAP_IF_LOOPBACK) &&
#ifndef PCAP_IF_CONNECTION_STATUS
      iface->flags & PCAP_IF_UP)
  {
#else
      (iface->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_CONNECTED)
  {
#endif
    // 检查接口是否有地址
    if (iface->addresses != NULL)
    {
      pcap_addr_t *list = iface->addresses;
      // 遍历地址列表，检查是否有 IPv4 地址
      for (; list->next != NULL; list = list->next)
      {
        struct sockaddr *saddr = list->addr;
        if (saddr->sa_family == AF_INET)
        {
          // printf("Found candidate (%s) with address %s\n", iface->name, inet_ntoa(((struct sockaddr_in*)list->addr)->sin_addr));
          return true;
        }
      }
    }
  }

  return false;
}

// 获取默认设备
char *getDefaultDevice()
{
  char *devname = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces;
  pcap_if_t *temp;

  // 查找所有设备
  if (pcap_findalldevs(&interfaces, errbuf) == -1)
  {
    printf("%s\n", errbuf);
    return NULL;
  }

  bool found = false;
  // 遍历设备列表，找到第一个有效的设备
  for (temp = interfaces; temp != NULL; temp = temp->next)
  {
    if (validForScan(temp))
    {
      if (found)
      {
        return NULL;
      }
      else
      {
        found = true;
        devname = temp->name;
      }
    }
  }

  return devname;
}

// 扫描函数
int scan()
{
  /* pcap */
  bpf_u_int32 mask;
  bpf_u_int32 net;
  char pcap_errbuf[PCAP_ERRBUF_SIZE];

  /* libnet */
  libnet_t *l;
  libnet_ptag_t arp_tag = 0;
  int bytes_written;
  char errbuf[LIBNET_ERRBUF_SIZE];
  u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  u_int8_t mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

  /* 当前主机 */
  const char *devname;
  u_int32_t src_ip_addr;
  struct libnet_ether_addr *src_mac_addr;

  /* 捕获线程 */
  sem_t thread_sem;
  pthread_t cap_thread;
  struct cap_struct caps;
  // struct host_list *list;

  /* 用户未指定任何设备 */

  /* 尝试找到正在使用的接口 */
  devname = getDefaultDevice();

  if (devname == NULL)
  {
    printf("ERROR: DEVICE option was not specified and no device could be selected automatically\n");
    printInterfaces();
    return EXIT_SUCCESS;
  }

  // 初始化 libnet
  if ((l = libnet_init(LIBNET_LINK, devname, errbuf)) == NULL)
  {
    fprintf(stderr, "libnet_init: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  printf("Using interface: '%s'\n", devname);

  // 初始化信号量
  if (sem_init(&thread_sem, 0, 0) == -1)
  {
    perror("client");
    return EXIT_FAILURE;
  }

  caps.sem = &thread_sem;
  caps.ok = malloc(sizeof(bool));
  caps.dev = devname;

  // 创建捕获线程
  if (pthread_create(&cap_thread, NULL, &cap, &caps) == -1)
  {
    perror("pthread_create");
    return EXIT_FAILURE;
  }

  // 等待捕获线程初始化完成
  if (sem_wait(&thread_sem) == -1)
  {
    perror("client");
    return EXIT_FAILURE;
  }

  if (!*caps.ok)
  {
    return EXIT_FAILURE;
  }

  // 查找网络地址和掩码
  if (pcap_lookupnet(devname, &net, &mask, pcap_errbuf) == -1)
  {
    fprintf(stderr, "%s\n", errbuf);
    return EXIT_FAILURE;
  }

  // 获取源 IP 地址
  if ((src_ip_addr = libnet_get_ipaddr4(l)) == (u_int32_t)-1)
  {
    fprintf(stderr, "%s\n", libnet_geterror(l));
    libnet_destroy(l);
    return EXIT_FAILURE;
  }

  // 获取源 MAC 地址
  if ((src_mac_addr = libnet_get_hwaddr(l)) == NULL)
  {
    fprintf(stderr, "%s\n", libnet_geterror(l));
    libnet_destroy(l);
    return EXIT_FAILURE;
  }

  // 计算网络地址和广播地址
  mask = htonl(mask);
  uint32_t network_address = htonl(src_ip_addr) & mask;
  uint32_t broadcast_address = htonl(src_ip_addr) | ~mask;
  printf("Scanning from %d.%d.%d.%d to %d.%d.%d.%d\n", ((network_address + 1) & 0xFF000000) >> 24,
         ((network_address + 1) & 0x00FF0000) >> 16,
         ((network_address + 1) & 0x0000FF00) >> 8,
         (network_address + 1) & 0x000000FF,
         ((broadcast_address - 1) & 0xFF000000) >> 24,
         ((broadcast_address - 1) & 0x00FF0000) >> 16,
         ((broadcast_address - 1) & 0x0000FF00) >> 8,
         (broadcast_address - 1) & 0x000000FF);

  // 发送 ARP 请求
  for (uint32_t ip = network_address + 1; ip < broadcast_address; ip++)
  {
    uint32_t target_ip_addr = ntohl(ip);
    if ((arp_tag = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REQUEST, src_mac_addr->ether_addr_octet, (u_int8_t *)(&src_ip_addr), mac_zero_addr, (u_int8_t *)(&target_ip_addr), NULL, 0, l, arp_tag)) == -1)
    {
      fprintf(stderr, "%s\n", libnet_geterror(l));
      libnet_destroy(l);
      return EXIT_FAILURE;
    }

    if (ip == network_address + 1)
    {
      /* 仅在第一次迭代中构建（在其他迭代中重用） */
      if (libnet_autobuild_ethernet(mac_broadcast_addr, ETHERTYPE_ARP, l) == -1)
      {
        fprintf(stderr, "%s\n", libnet_geterror(l));
        libnet_destroy(l);
        return EXIT_FAILURE;
      }
    }

    bytes_written = libnet_write(l);
    if (bytes_written == -1)
    {
      fprintf(stderr, "%s\n", libnet_geterror(l));
    }
  }

  libnet_destroy(l);

  printf("Waiting for requests...\n");
  sleep(1);

  /* 结束捕获线程 */
  pcap_breakloop(caps.ctx);

  if (pthread_join(cap_thread, NULL) == -1)
  {
    perror("pthread_join");
    return EXIT_FAILURE;
  }
  free(caps.ok);

  return print_hosts(caps.list->next, src_ip_addr);
}
