#include "printer.h"

// 获取 MAC 地址对应的供应商字符串
char *get_mac_vendor_str(char *file, char *mac)
{
  if (file == NULL)
    return NULL;

  char *vendor;
  char *str = strchr(file, '\n'); // 查找文件中的换行符
  char mac_str[6] = {mac[0], mac[1], mac[3], mac[4], mac[6], mac[7]}; // 提取 MAC 地址的前 6 个字符用于匹配

  /* 搜索 MAC 地址 */
  while (str != NULL && strncmp(str + 1, mac_str, 6) != 0)
    str = strchr(str + 1, '\n'); // 查找下一个换行符

  if (str != NULL)
  {
    /* 找到 MAC 地址 */
    str++;
    char *tmp1 = str + 7;
    char *tmp2;

    /* 如果以 '"' 开头，则以 '"' 结尾 */
    if (*tmp1 == '\"')
    {
      tmp1++;
      tmp2 = strchr(tmp1, '\"'); // 查找下一个双引号
    }
    else
    {
      tmp2 = strchr(tmp1, ','); // 查找下一个逗号
    }

    vendor = malloc(sizeof(char) * (tmp2 - tmp1 + 1));
    memset(vendor, 0, (tmp2 - tmp1 + 1));
    strncpy(vendor, tmp1, tmp2 - tmp1); // 复制供应商字符串
  }
  else
  {
    vendor = malloc(sizeof(char) * 4);
    memset(vendor, 0, 4);
    strncpy(vendor, "???", 4); // 如果未找到，返回 "???"
  }

  return vendor;
}

// 打印主机信息
void print_host(char *file, char *ip_str, char *mac_str, char *vendor, u_int32_t ip, u_int32_t this_host)
{
  if (ip == this_host)
  {
    if (vendor == NULL)
      printf(BOLD "%-18s %-18s" RESET "\n", ip_str, mac_str);
    else
      printf(BOLD "%-18s %-18s(%s)" RESET "\n", ip_str, mac_str, get_mac_vendor_str(file, mac_str));
  }
  else
  {
    if (vendor == NULL)
      printf("%-18s %-18s\n", ip_str, mac_str);
    else
      printf("%-18s %-18s(%s)\n", ip_str, mac_str, get_mac_vendor_str(file, mac_str));
  }
}

// 打印所有主机信息
bool print_hosts(struct host_list *list, u_int32_t this_host)
{
  int dbfd;
  char *file = NULL;
  struct stat st;

  if (list == NULL)
  {
    fprintf(stderr, "WARNING: No hosts found!\n");
    return true;
  }

  // 尝试打开 MAC 地址数据库文件
  if ((dbfd = open(MACDB_PATH1 MACDB_FILE, O_RDONLY)) == -1 && (dbfd = open(MACDB_PATH2 MACDB_FILE, O_RDONLY)) == -1)
  {
    fprintf(stderr, "WARNING: MAC vendors will not be shown\n%s: ", MACDB_FILE);
    perror("open");
  }
  else
  {
    if (fstat(dbfd, &st) != 0)
    {
      perror("stat");
      return false;
    }

    file = malloc(sizeof(char) * st.st_size);
    read(dbfd, file, st.st_size); // 读取文件内容
  }

  printf("\n%-18s %-18s\n", "IP Addess", "MAC Address");
  while (list->next != NULL)
  {
    print_host(file, list->ip_str, list->mac_str, get_mac_vendor_str(file, list->mac_str), list->ip, this_host);
    list = list->next;
  }
  if (list != NULL)
    print_host(file, list->ip_str, list->mac_str, get_mac_vendor_str(file, list->mac_str), list->ip, this_host);
  free(file);

  return true;
}
