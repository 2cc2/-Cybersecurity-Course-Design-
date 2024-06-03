#include "cap.h"

/* 我们假设这里可以接收 ARP 数据包 */
void got_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
  struct host_list *tmp = (struct host_list *)args;
  struct host_list *p;
  bool repeated = false;
  char sourceip[16];
  char sourcemac[18];
  uint32_t ip;
  const struct arp_hdr *arp = (struct arp_hdr *)(packet + SIZE_ETHERNET);

  snprintf(sourceip, 16, "%d.%d.%d.%d", arp->arp_sip[0], arp->arp_sip[1], arp->arp_sip[2], arp->arp_sip[3]);
  snprintf(sourcemac, 18, "%02X:%02X:%02X:%02X:%02X:%02X", arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
  ip = inet_addr(sourceip);

  // 检查 IP 是否已经在列表中
  while (!repeated && tmp->next != NULL && tmp->next->ip <= ip)
  {
    tmp = tmp->next;
    if (tmp->ip == ip)
      repeated = true;
  }

  // 如果没有重复，添加到列表
  if (!repeated)
  {
    if (tmp->next == NULL)
    {
      tmp->next = malloc(sizeof(struct host_list));
      tmp->next->next = NULL;
    }
    else
    {
      p = tmp->next;
      tmp->next = malloc(sizeof(struct host_list));
      tmp->next->next = p;
    }

    tmp->next->ip = ip;
    strncpy(tmp->next->ip_str, sourceip, 16);
    strncpy(tmp->next->mac_str, sourcemac, 18);
  }
}

void *cap(void *args)
{
  struct cap_struct *s = (struct cap_struct *)args;

  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask;
  bpf_u_int32 net;

  /* 过滤器 */
  struct bpf_program fp;
  char filter_exp[] = "arp";

  /* 捕获 */
  // const u_char *packet;
  // struct pcap_pkthdr header;

  *s->ok = true;
  s->list = malloc(sizeof(struct host_list));
  s->list->next = NULL;

  // 获取网络号和掩码
  if (pcap_lookupnet(s->dev, &net, &mask, errbuf) == -1)
  {
    fprintf(stderr, "%s\n", errbuf);
    *s->ok = false;

    if (sem_post(s->sem) == -1)
    {
      perror("client");
    }

    return NULL;
  }

  // 打开捕获设备
  if ((handle = pcap_open_live(s->dev, BUFSIZ, 1, 100, errbuf)) == NULL)
  {
    fprintf(stderr, "%s\n", errbuf);
    *s->ok = false;

    if (sem_post(s->sem) == -1)
    {
      perror("client");
    }

    return NULL;
  }

  s->ctx = handle;

  // 编译过滤器
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
  {
    fprintf(stderr, "%s\n", pcap_geterr(handle));
    *s->ok = false;
    if (sem_post(s->sem) == -1)
    {
      perror("client");
    }

    return NULL;
  }

  // 设置过滤器
  if (pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "%s\n", pcap_geterr(handle));
    *s->ok = false;

    if (sem_post(s->sem) == -1)
    {
      perror("client");
    }

    return NULL;
  }

  // 设置非阻塞模式
  if (pcap_setnonblock(handle, 1, errbuf) == -1)
  {
    fprintf(stderr, "%s\n", errbuf);
    *s->ok = false;

    if (sem_post(s->sem) == -1)
    {
      perror("client");
      return NULL;
    }
  }

  // 信号量解锁，通知主线程准备完成
  if (sem_post(s->sem) == -1)
  {
    perror("client");
    *s->ok = false;
    return NULL;
  }

  // 开始捕获 ARP 包
  if (pcap_loop(handle, -1, got_packet, (u_char *)s->list) == -1)
  {
    fprintf(stderr, "%s\n", pcap_geterr(handle));
    *s->ok = false;
    return NULL;
  }

  return NULL;
}
