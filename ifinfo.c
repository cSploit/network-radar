/* cSploit - a simple penetration testing suite
 * Copyright (C) 2014  Massimo Dragano aka tux_mind <tux_mind@csploit.org>
 * 
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with cSploit.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <pcap.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "logger.h"
#include "ifinfo.h"
#include "netdefs.h"

struct if_info ifinfo;

#define L3_NOT_FOUND 1
#define L2_NOT_FOUND 2

int sysfs_get_L2_ifinfo(char *ifname) {
  char *path;
  FILE *fp;
  int ret;
  
  path = NULL;
  fp = NULL;
  ret = -1;
  
  if(asprintf(&path, "/sys/class/net/%s/address", ifname) == -1) {
    print( ERROR, "asprintf: %s", strerror(errno));
    goto exit;
  }
  
  fp = fopen(path, "r");
  
  if(!fp) {
    print(ERROR, "fopen: %s", strerror(errno));
    goto exit;
  }
  
  ret = fscanf(fp, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
         &(ifinfo.eth_addr[0]), &(ifinfo.eth_addr[1]), &(ifinfo.eth_addr[2]), 
         &(ifinfo.eth_addr[3]), &(ifinfo.eth_addr[4]), &(ifinfo.eth_addr[5]));
  
  if(ret != 6) {
    print( ERROR, "fscanf: %s", strerror(errno));
    ret = -1;
    goto exit;
  }
  
  ret = 0;
  
  exit:
  
  if(fp)
    fclose(fp);
  
  if(path)
    free(path);
  
  return ret;
}

int ioctl_get_L2_ifinfo(char *ifname) {
  struct ifreq ir;
  int fd;
  
  fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  
  if(fd == -1) {
    print( ERROR, "socket: %s", strerror(errno));
    return -1;
  }

  memset(&ir, 0, sizeof(struct ifreq));
  
  strncpy(ir.ifr_name, ifname, IFNAMSIZ);
  
  if (ioctl(fd, SIOCGIFHWADDR, &ir) == -1) {
    print( ERROR, "ioctl: %s", strerror(errno));
    close(fd);
    return -1;
  }
  
  close(fd);
  
  memcpy(ifinfo.eth_addr, ir.ifr_addr.sa_data, ETH_ALEN);
  
  return 0;
}

/**
 * @brief get info about an interface and store them into ::ifinfo .
 * 
 * @param ifname name of the interface
 * @returns 0 on success, -1 on error.
 */
int get_ifinfo(char *ifname) {
  pcap_if_t *devlist, *dev;
  pcap_addr_t *a;
  struct sockaddr_in *i;
  struct sockaddr_ll *l;
  char err_buff[PCAP_ERRBUF_SIZE];
  char status;
  
  err_buff[0] = '\0';
  status = (L2_NOT_FOUND | L3_NOT_FOUND);
  
  if(pcap_findalldevs(&devlist, err_buff)) {
    print( ERROR, "pcap_findalldevs: %s", err_buff);
    return -1;
  }
  
  for(dev=devlist; dev && strncmp(dev->name, ifname, IFNAMSIZ); dev=dev->next);
  
  if(!dev) {
    print( ERROR, "device '%s' not found", ifname);
    pcap_freealldevs(devlist);
    return -1;
  }
  
  for(a=dev->addresses;a && status;a=a->next) {
    
    if(a->addr->sa_family == AF_INET) {
      i = (struct sockaddr_in *) a->addr;
      
      memcpy(ifinfo.ip_addr, &(i->sin_addr.s_addr), 4);
      
      i = (struct sockaddr_in *) a->netmask;
      
      if(i) {
        memcpy(&(ifinfo.ip_mask), &(i->sin_addr.s_addr), 4);
        status &= ~(L3_NOT_FOUND);
      }
    } else if(a->addr->sa_family == AF_PACKET) {
      l = (struct sockaddr_ll *) a->addr;
      
      if(l->sll_halen != ETH_ALEN) continue;
      
      memcpy(ifinfo.eth_addr, l->sll_addr, ETH_ALEN);
      status &= ~(L2_NOT_FOUND);
    }
  }
  
  pcap_freealldevs(devlist);
  
  if((status & L2_NOT_FOUND) && (!ioctl_get_L2_ifinfo(ifname) || !sysfs_get_L2_ifinfo(ifname))) {
    status &= ~(L2_NOT_FOUND);
  }
  
  if(status) {
    if(status & L2_NOT_FOUND) {
      print( ERROR, "cannot find link layer address");
    }
    if(status & L3_NOT_FOUND) {
      print( ERROR, "cannot find IPv4 address");
    }
    return -1;
  }
  
  strncpy(ifinfo.name, ifname, IFNAMSIZ);
  
  return 0;
}
