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
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#include "logger.h"

#include "netdefs.h"
#include "sniffer.h"
#include "ifinfo.h"
#include "host.h"
#include "nbns.h"
#include "prober.h"
#include "event.h"

int nbns_sockfd = -1;
struct arp_packet arp_request;

int init_prober() {
  nbns_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  
  if(nbns_sockfd == -1) {
    print( ERROR, "socket: %s\n", strerror(errno));
    return -1;
  }
  
  // build the ethernet header
  
  memcpy(arp_request.eh.ether_shost, ifinfo.eth_addr, ETH_ALEN);
  arp_request.eh.ether_type = htons(ETH_P_ARP);
  
  // build arp header
  
  arp_request.ah.ar_hrd = htons(ARPHRD_ETHER);
  arp_request.ah.ar_pro = htons(ETH_P_IP);
  arp_request.ah.ar_hln = ETH_ALEN;
  arp_request.ah.ar_pln = 4;
  arp_request.ah.ar_op  = htons(ARPOP_REQUEST);
  
  // build arp message constants
  
  memcpy(arp_request.arp_sha, ifinfo.eth_addr, ETH_ALEN);
  memcpy(arp_request.arp_spa, &(ifinfo.ip_addr), 4);
  memset(arp_request.arp_tha, 0x00, ETH_ALEN);
  
  return 0;
}

void begin_nbns_lookup(uint32_t ip) {
  struct sockaddr_in addr;
  
  memset(&addr, 0, sizeof(addr));
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(137);
  
  addr.sin_addr.s_addr = ip;
    
  if(sendto(nbns_sockfd, nbns_nbstat_request, NBNS_NBSTATREQ_LEN, 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    print( ERROR, "sendto(%u.%u.%u.%u): %s",
           ((uint8_t *) &ip)[0], ((uint8_t *) &ip)[1], ((uint8_t *) &ip)[2], ((uint8_t *) &ip)[3],
           strerror(errno));
  }
}

/**
 * @brief perform a full and quick scan sending a NBSTAT request to all hosts
 */
void full_scan() {
  uint32_t i, max;
  struct sockaddr_in addr;
  
  max = get_host_max_index();
  
  memset(&addr, 0, sizeof(addr));
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(137);
  
  for(i=1;i<max;i++) {
    
    addr.sin_addr.s_addr = get_host_addr(i);
    
    sendto(nbns_sockfd, nbns_nbstat_request, NBNS_NBSTATREQ_LEN, 0, (struct sockaddr *) &addr, sizeof(addr));
  }
}

void *prober(void *arg) {
  uint32_t max_index, i, ip;
  useconds_t delay;
  struct host *h;
  time_t timeout;
  struct event *e;
  
  max_index = get_host_max_index();
  
  delay = (FULL_SCAN_MS * 1000 / max_index);
  
  // quick and full scan on startup
  full_scan();
  
  pthread_mutex_lock(&(hosts.control.mutex));
  
  do {
    
    for(i=1;i<max_index && hosts.control.active;i++) {
      
      h = hosts.array[i];
      
      if(h) {
        timeout = h->timeout;
        
        memcpy(arp_request.eh.ether_dhost, h->mac, ETH_ALEN);
      } else {
        timeout = 0;
      }
      
      pthread_mutex_unlock(&(hosts.control.mutex));
      
      if(h) {
        ip = get_host_addr(i);
        
        if(time(NULL) < timeout) {
        
          memcpy(&(arp_request.arp_tpa), &ip, 4);
          
          //NOTE: should we worried about race conditions here ?
          
          if(pcap_inject(handle, &arp_request, sizeof(struct arp_packet)) == -1) {
            print( WARNING, "pcap_inject: %s", pcap_geterr(handle));
          }
        } else {
          pthread_mutex_lock(&(hosts.control.mutex));
          hosts.array[i] = NULL;
          pthread_mutex_unlock(&(hosts.control.mutex));
          
          free_host(h);
          
          e = malloc(sizeof(struct event));
          
          if(e) {
            e->type = MAC_LOST;
            e->ip = ip;
            
            add_event(e);
          } else {
            print( ERROR, "malloc: %s\n", strerror(errno));
          }
        }
      }
      
      usleep(delay);
      
      pthread_mutex_lock(&(hosts.control.mutex));
    }
    
  } while(hosts.control.active);
  
  pthread_mutex_unlock(&(hosts.control.mutex));
  
  close(nbns_sockfd);
  
  return NULL;
}

void stop_prober() {
  control_deactivate(&(hosts.control));
  shutdown( nbns_sockfd, SHUT_WR);
}