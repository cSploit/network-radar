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

#include <pcap.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <stddef.h>

#include "logger.h"

#include "netdefs.h"
#include "host.h"
#include "event.h"
#include "nbns.h"
#include "sniffer.h"
#include "resolver.h"
#include "prober.h"
#include "ifinfo.h"

pcap_t *handle;

pthread_t sniffer_tid = 0;

void on_host_found(uint8_t *mac, uint32_t ip, char *name, char assumed_lstatus) {
  struct host *h;
  struct event *e;
  int old_errno;
  uint8_t e_type;
  char lstatus;
  
  e_type = NONE;
  
  pthread_mutex_lock(&(hosts.control.mutex));
  
  h = get_host(ip);
  
  if(h) {
    if(memcmp(mac, h->mac, ETH_ALEN)) {
      memcpy(h->mac, mac, ETH_ALEN);
      
      e_type = MAC_CHANGED;
    }
    
    if(name || e_type == MAC_CHANGED) {
      if(h->name)
        free(h->name);
      h->name = name;
    }
    
  } else {
    h = malloc(sizeof(struct host));
    
    if(!h) {
      old_errno = errno;
      pthread_mutex_unlock(&(hosts.control.mutex));
      print(ERROR, "malloc: %s", strerror(old_errno));
      return;
    }
    
    memset(h, 0, sizeof(struct host));
    memcpy(h->mac, mac, ETH_ALEN);
    h->name = name;
    
    set_host(ip, h);
    
    e_type = NEW_MAC;
  }
  
  h->timeout = time(NULL) + HOST_TIMEOUT;
  
  lstatus = h->lookup_status;
  h->lookup_status |= (HOST_LOOKUP_DNS|HOST_LOOKUP_NBNS);
  
  pthread_mutex_unlock(&(hosts.control.mutex));
  
  if(!((lstatus | assumed_lstatus) & HOST_LOOKUP_DNS)) {
    begin_dns_lookup(ip);
  }
  
  if(!((lstatus | assumed_lstatus) & HOST_LOOKUP_NBNS)) {
    begin_nbns_lookup(ip);
  }
  
  if(name)
    e_type = NEW_NAME;
  else if(e_type == NONE)
    return;
  
  e = malloc(sizeof(struct event));
  
  if(!e) {
    print( ERROR, "malloc: %s", strerror(errno));
    return;
  }
  
  e->ip = ip;
  e->type = e_type;
  
  add_event(e);
}

void on_arp(struct ether_arp *arp) {
  uint8_t *mac;
  uint32_t ip;
  
  static const uint8_t arp_hwaddr_any[ETH_ALEN] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  
  // sanity check
  if(arp->arp_hln != ETH_ALEN || arp->arp_pln != 4) {
    return;
  }
  
  // skip sent arp packets
  if(!memcmp(arp->arp_sha, ifinfo.eth_addr, ETH_ALEN))
    return;
  
  mac = (uint8_t *) arp->arp_tha;
  ip = *((uint32_t *) arp->arp_tpa);
  
  process:
  
  if(ip != INADDR_ANY && ip != ifinfo.ip_addr) {
    if(!memcmp(mac, ifinfo.eth_addr, ETH_ALEN)) {
      // skip
    } else if(memcmp(mac, arp_hwaddr_any, ETH_ALEN)) {
      on_host_found(mac, ip, NULL, 0);
    } else if (!get_host(ip)) {
      // we dont have this host and someone want to talk to him
      begin_nbns_lookup(ip);
    }
  }
  
  if(mac == (uint8_t *) arp->arp_tha) {
    mac = (uint8_t *) arp->arp_sha;
    ip = *((uint32_t *) arp->arp_spa);
    goto process;
  }
}

void on_udp(struct ether_header *eth) {
  struct iphdr *ip;
  struct udphdr *udp;
  struct nbnshdr *nb;
  char *nbname;
  uint32_t host_ip;
  uint8_t *host_mac;
  
  ip = (struct iphdr *) (eth+1);
  udp = NULL;
  nb = NULL;
  nbname = NULL;
  
  if(!memcmp(eth->ether_dhost, ifinfo.eth_addr, ETH_ALEN)) {
    // received UDP packet
    
    udp = (struct udphdr *) (((uint32_t *)ip) + ip->ihl);
    nb = (struct nbnshdr *) (((uint8_t *)udp) + sizeof(struct udphdr));
    
    host_mac = eth->ether_shost;
    
    host_ip = ip->saddr;
  } else {
    // sent UDP packet
    
    host_mac = eth->ether_dhost;
    host_ip = ip->daddr;
  }
  
  if(nb) {
    nbname = nbns_get_status_name(nb);
  }
  
  on_host_found(host_mac, host_ip, nbname, HOST_LOOKUP_NBNS);
}

void *sniffer(void *arg) {
  struct ether_header *eth;
  struct iphdr *ip;
  struct pcap_pkthdr pkthdr;
  unsigned short int eth_type_arp;
  uint16_t eth_type_ip;
  
  eth_type_arp = htons(ETH_P_ARP);
  eth_type_ip  = htons(ETH_P_IP);
  
  while((eth = (struct ether_header *) pcap_next(handle, &pkthdr))) {
    if(eth->ether_type == eth_type_arp) {
      on_arp((struct ether_arp *) (eth + 1));
    } else if(eth->ether_type == eth_type_ip) {
      ip = (struct iphdr *) (eth+1);
      
      if(ip->protocol == IPPROTO_UDP) {
        on_udp(eth);
      }
    }
  }
  
  return NULL;
}

/**
 * @brief start sniffing on @p interface
 * @param interface the interface to sniff on
 * @returns 0 on success, -1 on error.
 */
int start_sniff() {
  char err_buff[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  
  *err_buff = '\0';
  
  handle = pcap_open_live(ifinfo.name, 1514, 0, 0, err_buff);
  
  if(!handle) {
    print( ERROR, "pcap_open_live: %s", err_buff);
    return -1;
  }
  
  if(*err_buff) {
    print( ERROR, "pcap_open_live: %s", err_buff);
  }
  
  if(pcap_datalink(handle) != DLT_EN10MB) {
    print( ERROR, "Device %s doesn't provide Ethernet headers - not supported\n", ifinfo.name);
    pcap_close(handle);
    return -1;
  }
  
  if(pcap_compile(handle, &filter, "( ( arp or rarp ) or ( udp and port 137 ))", 1, (bpf_u_int32) ifinfo.ip_mask)) {
    print( ERROR, "pcap_compile: %s", pcap_geterr(handle));
    pcap_close(handle);
    return -1;
  }
  
  if(pcap_setfilter(handle, &filter)) {
    print( ERROR, "pcap_setfilter: %s", pcap_geterr(handle));
    pcap_close(handle);
    return -1;
  }
  
  if(init_hosts()) {
    pcap_close(handle);
    print( ERROR, "init_hosts: %s", strerror(errno));
    return -1;
  }
  
  if(pthread_create(&sniffer_tid, NULL, sniffer, NULL)) {
    sniffer_tid = 0;
    pcap_close(handle);
    free(hosts.array);
    print( ERROR, "pthread_create: %s", strerror(errno));
    return -1;
  }
  
  return 0;
}

/**
 * @brief stop the sniffer thread
 */
void stop_sniff() {
  pthread_t tid;
  
  if(sniffer_tid) {
    tid = sniffer_tid;
    sniffer_tid = 0;
    
    pcap_close(handle);
    pthread_join(tid, NULL);
  }
}
