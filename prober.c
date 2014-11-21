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

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#include "logger.h"

#include "sniffer.h"
#include "host.h"
#include "prober.h"
#include "event.h"

#define NBREQ_LEN 50

uint8_t netbios_request[NBREQ_LEN] = {
    0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01
};


struct arp_packet {
  struct ether_header eh;
  struct arphdr ah;
  uint8_t ar_sha[ETHER_ADDR_LEN];
  uint8_t ar_spa[4];
  uint8_t ar_tha[ETHER_ADDR_LEN];
  uint8_t ar_tpa[4];
} arp_request;

void *prober(void *arg) {
  uint32_t max_index, i;
  struct sockaddr_in addr;
  int sockfd;
  useconds_t delay;
  struct host *h;
  time_t timeout;
  struct event *e;
  
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  
  if(sockfd == -1) {
    print( ERROR, "socket: %s\n", strerror(errno));
    return NULL;
  }
  
  // build the ethernet header
  
  memset(arp_request.eh.ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(arp_request.eh.ether_shost, if_info.eth_addr, ETHER_ADDR_LEN);
  arp_request.eh.ether_type = htons(ETH_P_ARP);
  
  // build arp header
  
  arp_request.ah.ar_hrd = htons(ARPHRD_ETHER);
  arp_request.ah.ar_pro = htons(ETH_P_IP);
  arp_request.ah.ar_hln = ETHER_ADDR_LEN;
  arp_request.ah.ar_pln = 4;
  arp_request.ah.ar_op  = htons(ARPOP_REQUEST);
  
  // build arp message constants
  
  memcpy(arp_request.ar_sha, if_info.eth_addr, ETHER_ADDR_LEN);
  memcpy(arp_request.ar_spa, if_info.ip_addr, 4);
  memset(arp_request.ar_tha, 0x00, ETHER_ADDR_LEN);
  
  max_index = get_host_max_index();
  
  delay = (FULL_SCAN_MS / max_index) * 1000;
  
  memset(&addr, 0, sizeof(addr));
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(137);
  
  // quick probe on startup
  
  for(i=1;i<max_index;i++) {
    
    addr.sin_addr.s_addr = get_host_addr(i);
    
    sendto(sockfd, netbios_request, NBREQ_LEN, 0, (struct sockaddr *) &addr, sizeof(addr));
  }
  
  pthread_mutex_lock(&(hosts.control.mutex));
  
  do {
    
    for(i=1;i<max_index && hosts.control.active;i++) {
      
      h = hosts.array[i];
      timeout = ( h ? h->timeout : 0);
      
      pthread_mutex_unlock(&(hosts.control.mutex));
      
      addr.sin_addr.s_addr = get_host_addr(i);
      
      if(h && time(NULL) < timeout) {
        
        memcpy(&(arp_request.ar_tpa), &(addr.sin_addr.s_addr), 4);
        
        //NOTE: should we worried about race conditions here ?
        
        if(pcap_inject(handle, &arp_request, sizeof(struct arp_packet)) == -1) {
          print( ERROR, "pcap_inject: %s\n", pcap_geterr(handle));
        }
      } else {
        
        if(h) {
          pthread_mutex_lock(&(hosts.control.mutex));
          hosts.array[i] = NULL;
          pthread_mutex_unlock(&(hosts.control.mutex));
          
          free_host(h);
          
          e = malloc(sizeof(struct event));
          
          if(e) {
            e->type = MAC_LOST;
            e->ip = addr.sin_addr.s_addr;
            
            add_event(e);
          } else {
            print( ERROR, "malloc: %s\n", strerror(errno));
          }
        }
        
        if(sendto(sockfd, netbios_request, NBREQ_LEN, 0, (struct sockaddr *) &addr, sizeof(addr)) == -1)
          print( ERROR, "sendto(%u): %s\n", i, strerror(errno));
      }
      
      usleep(delay);
      
      pthread_mutex_lock(&(hosts.control.mutex));
    }
    
  } while(hosts.control.active);
  
  pthread_mutex_unlock(&(hosts.control.mutex));
  
  close(sockfd);
  
  return NULL;
}

void stop_prober() {
  control_deactivate(&(hosts.control));
}