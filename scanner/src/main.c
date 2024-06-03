#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scanport_tcp.h"
#include "scan.h"
#include "scanhost.h"

int main(int argc, char *argv[])
{
  if (argc < 3)
  {
    fprintf(stderr, "usage: %s <option> [arguments...]\n", argv[0]);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  1. TCP port scanning: %s -tcp <dst_ip> <start_port> <end_port>\n", argv[0]);
    fprintf(stderr, "  2. Host scanning: %s -s <start_ip> <end_ip>\n", argv[0]);
    fprintf(stderr, "  3. Host scanning: %s -arp hostname\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  if (strcmp(argv[1], "-tcp") == 0)
  {
    scanport_tcp(argv[2], atoi(argv[3]), atoi(argv[4]));
  }
  else if (strcmp(argv[1], "-s") == 0)
  {
    scanhost(argv[2], argv[3]);
  }
  else if (strcmp(argv[1], "-arp") == 0)
  {
    scan();
  }
  else
  {
    fprintf(stderr, "Invalid option!\n");
    exit(EXIT_FAILURE);
  }

  return 0;
}
