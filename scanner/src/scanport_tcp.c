#include "scanport_tcp.h"

void scanport_tcp(const char *dst_ip_str, int start_port, int end_port)
{
  u_int32_t dst_ip; /* 目标IP地址         */
  int dst_port;     /* 目标端口号         */

  /* 解析命令行参数并检查合法性 */
  dst_ip = inet_addr(dst_ip_str);
  CHKADDRESS(dst_ip);

  /* 开始端口扫描 */
  for (dst_port = start_port; dst_port <= end_port; dst_port++)
  {
    printf("Scan Port %d\r", dst_port);
    fflush(stdout);

    if (tcpportscan(dst_ip, dst_port) == CONNECT)
    {
      struct servent *sp; /* 端口服务结构体 */

      sp = getservbyport(htons(dst_port), "tcp");
      printf("%5d %-20s\n", dst_port, (sp == NULL) ? "unknown" : sp->s_name);
    }
  }
}

/*
 * TCP端口扫描函数
 */
int tcpportscan(u_int32_t dst_ip, int dst_port)
{
  struct sockaddr_in dest; /* 目标地址结构体       */
  int s;                   /* 套接字文件描述符 */
  int ret;                 /* 返回值               */

  /* 初始化目标地址结构体 */
  memset(&dest, 0, sizeof dest);
  dest.sin_family = AF_INET;
  dest.sin_port = htons(dst_port);
  dest.sin_addr.s_addr = dst_ip;

  /* 创建TCP套接字 */
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  /* 尝试连接目标TCP端口 */
  if (connect(s, (struct sockaddr *)&dest, sizeof dest) < 0)
    ret = NOCONNECT;
  else
    ret = CONNECT;
  close(s);

  return ret;
}
