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

struct prober_data prober_info;

int init_prober() {
#ifdef HAVE_LIBPCAP
  char err_buff[PCAP_ERRBUF_SIZE];
#endif
  
  
  prober_info.nbns_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  
  if(prober_info.nbns_sockfd == -1) {
    print( ERROR, "socket: %s", strerror(errno));
    return -1;
  }
  
#ifdef HAVE_LIBPCAP

  *err_buff = '\0';

  prober_info.handle = pcap_open_live(ifinfo.name, ifinfo.mtu + ETH_HLEN, 0, 1000, err_buff);
  
  if(!(prober_info.handle)) {
    print( ERROR, "pcap_open_live: %s", err_buff);
    return -1;
  }
  
  if(*err_buff) {
    print( WARNING, "pcap_open_live: %s", err_buff);
  }
  
#else
  
  prober_info.arp_sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  
  if(prober_info.arp_sockfd == -1) {
    print( ERROR, "socket: %s", strerror(errno));
    close(prober_info.nbns_sockfd);
    close(prober_info.arp_sockfd);
    return -1;
  }
  
#endif
  
  // build the ethernet header
  
  memcpy(prober_info.arp_request.eh.ether_shost, ifinfo.eth_addr, ETH_ALEN);
  prober_info.arp_request.eh.ether_type = htons(ETH_P_ARP);
  
  // build arp header
  
  prober_info.arp_request.ah.ar_hrd = htons(ARPHRD_ETHER);
  prober_info.arp_request.ah.ar_pro = htons(ETH_P_IP);
  prober_info.arp_request.ah.ar_hln = ETH_ALEN;
  prober_info.arp_request.ah.ar_pln = 4;
  prober_info.arp_request.ah.ar_op  = htons(ARPOP_REQUEST);
  
  // build arp message constants
  
  memcpy(prober_info.arp_request.arp_sha, ifinfo.eth_addr, ETH_ALEN);
  memcpy(prober_info.arp_request.arp_spa, &(ifinfo.ip_addr), 4);
  memset(prober_info.arp_request.arp_tha, 0x00, ETH_ALEN);
  
  return 0;
}

void begin_nbns_lookup(uint32_t ip) {
  struct sockaddr_in addr;
  
  memset(&addr, 0, sizeof(addr));
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(137);
  
  addr.sin_addr.s_addr = ip;
    
  if(sendto(prober_info.nbns_sockfd, nbns_nbstat_request, NBNS_NBSTATREQ_LEN, 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
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
    
    sendto(prober_info.nbns_sockfd, nbns_nbstat_request, NBNS_NBSTATREQ_LEN, 0, (struct sockaddr *) &addr, sizeof(addr));
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
        
        memcpy(prober_info.arp_request.eh.ether_dhost, h->mac, ETH_ALEN);
      } else {
        timeout = 0;
      }
      
      pthread_mutex_unlock(&(hosts.control.mutex));
      
      if(h) {
        ip = get_host_addr(i);
        
        if(time(NULL) < timeout) {
        
          memcpy(&(prober_info.arp_request.arp_tpa), &ip, 4);
          
          #ifdef HAVE_LIBPCAP
          if(pcap_inject(prober_info.handle, &(prober_info.arp_request), sizeof(struct arp_packet)) == -1) {
            print( WARNING, "pcap_inject: %s", pcap_geterr(prober_info.handle));
          }
          #else
          // TODO: send arp packets ( arpd.c )
          #endif
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
  
  close(prober_info.nbns_sockfd);
  
  return NULL;
}

void stop_prober() {
  control_deactivate(&(hosts.control));
  shutdown( prober_info.nbns_sockfd, SHUT_WR);
}
