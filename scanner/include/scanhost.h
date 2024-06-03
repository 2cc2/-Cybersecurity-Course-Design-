#ifndef SCANHOST_H
#define SCANHOST_H
#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <pthread.h>
#include <pcap.h>
#include <stdbool.h>

#include "cap.h"
#include "printer.h"

#define RESET "\033[0m"
#define BOLD "\033[1m"

void printVersion();
void printInterfaces();
bool validForScan(pcap_if_t *iface);
char *getDefaultDevice();
int scan();
#endif