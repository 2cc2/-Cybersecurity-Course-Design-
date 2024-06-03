#ifndef __PRINTER__
#define __PRINTER__

#include "cap.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#define MACDB_FILE "macdb.csv"
#define MACDB_PATH1 "./"
#define MACDB_PATH2 "/usr/share/snetscan/"
#define RESET "\033[0m"
#define BOLD "\033[1m"
bool print_hosts(struct host_list *list, u_int32_t this_host);
#endif
