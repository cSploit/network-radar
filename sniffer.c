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

pcap_t *handle;

struct if_info if_info;

pthread_t sniffer_tid = 0;

void on_arp(struct ether_arp *arp) {
  uint8_t *mac;
  uint32_t *ip;
  struct host *h;
  struct event *e;
  
  // sanity check
  if(arp->arp_hln != ETH_ALEN || arp->arp_pln != 4) {
    return;
  }
  
  e = malloc(sizeof(struct event));
  
  if(!e) {
    print( ERROR, "malloc: %s", strerror(errno));
    return;
  }
  
  memset(e, 0, sizeof(struct event));
  
  // due to our pcap filter this is an ARP reply
  
  if(memcmp(arp->arp_spa, if_info.ip_addr, 4)) {
    mac = (uint8_t *) arp->arp_sha;
    ip = (uint32_t *) arp->arp_spa;
  } else {
    mac = (uint8_t *) arp->arp_tha;
    ip = (uint32_t *) arp->arp_tpa;
  }
  
  memcpy(&(e->ip), ip, 4);
  
  pthread_mutex_lock(&(hosts.control.mutex));
  
  h = get_host(*ip);
  
  if(h) {
    if(memcmp(h->mac, mac, 6)) {
      
      e->type = MAC_CHANGED;
      
      memcpy(&(h->mac), mac, 6);
      
      if(h->name)
        free(h->name);
      
      h->name = NULL;
      
      begin_dns_lookup(*ip);
      
    }
    
    h->timeout = time(NULL) + HOST_TIMEOUT;
  } else {
    h = malloc(sizeof(struct host));
    if(!h) {
      pthread_mutex_unlock(&(hosts.control.mutex));
      print( ERROR, "malloc: %s\n", strerror(errno));
      free(e);
      return;
    }
    e->type = NEW_MAC;
    
    memset(h, 0, sizeof(struct host));
    memcpy(&(h->mac), mac, 6);
    h->timeout = time(NULL) + HOST_TIMEOUT;
    set_host(*ip, h);
    begin_dns_lookup(*ip);
  }
  pthread_mutex_unlock(&(hosts.control.mutex));
  
  if(e->type != NONE) {
    add_event(e);
  } else {
    free(e);
  }
}

void on_udp(const unsigned char *packet) {
  struct ether_header *eth;
  struct iphdr *ip;
  struct udphdr *udp;
  struct nbnshdr *nb;
  struct host *h;
  struct event *e;
  uint32_t host_ip;
  uint8_t *host_mac;
  
  eth = (struct ether_header *) packet;
  ip = (struct iphdr *) (packet + sizeof(struct ether_header));
  udp = NULL;
  nb = NULL;
  
  if(!memcmp(eth->ether_dhost, if_info.eth_addr, ETH_ALEN)) {
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
  
  e = malloc(sizeof(struct event));
  
  if(!e) {
    print( ERROR, "malloc: %s\n", strerror(errno));
    return;
  }
  
  memset(e, 0, sizeof(struct event));
  e->ip = host_ip;
  
  pthread_mutex_lock(&(hosts.control.mutex));

  h = get_host(host_ip);
  
  if(!h) {
    h = malloc(sizeof(struct host));
    
    if(!h) {
      print( ERROR, "malloc: %s\n", strerror(errno));
      pthread_mutex_unlock(&(hosts.control.mutex));
      return;
    }
    
    memset(h, 0, sizeof(struct host));
    memcpy(&(h->mac), host_mac, ETH_ALEN);
    h->timeout = time(NULL) + HOST_TIMEOUT;
    
    set_host(host_ip, h);
    
    e->type = NEW_MAC;
  } else if(memcmp(h->mac, host_mac, ETH_ALEN)) {
    
    memcpy(h->mac, host_mac, ETH_ALEN);
    
    e->type = MAC_CHANGED;
  }
  
  if(nb) {
    h->name = nbns_get_status_name(nb);
    if(h->name)
      e->type = NEW_NAME;
  }
  
  pthread_mutex_unlock(&(hosts.control.mutex));
  
  if(!nb) {
    begin_dns_lookup(host_ip);
  }
  
  if(e->type != NONE) {
    add_event(e);
  } else {
    free(e);
  }
}

void *sniffer(void *arg) {
  const unsigned char *packet;
  struct pcap_pkthdr pkthdr;
  
  while((packet = pcap_next(handle, &pkthdr))) {
    if(packet[12] == 0x08) {
      if( packet[13] == 0x06 || packet[13] == 0x35)
        on_arp((struct ether_arp *) (packet + ETH_HLEN));
      else if( packet[13] == 0x00 )
        on_udp(packet);
    }
  }
  
  return NULL;
}

#define L3_NOT_FOUND 1
#define L2_NOT_FOUND 2

/**
 * @brief start sniffing on @p interface
 * @param interface the interface to sniff on
 * @returns 0 on success, -1 on error.
 */
int start_sniff(char *interface) {
  char err_buff[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  pcap_if_t *devlist, *dev;
  pcap_addr_t *a;
  struct sockaddr_in *i;
  struct sockaddr_ll *l;
  char status;
  
  err_buff[0] = '\0';
  status = (L2_NOT_FOUND | L3_NOT_FOUND);
  
  if(pcap_findalldevs(&devlist, err_buff)) {
    print( ERROR, "pcap_findalldevs: %s", err_buff);
    return -1;
  }
  
  for(dev=devlist; dev && strncmp(dev->name, interface, IFNAMSIZ); dev=dev->next);
  
  if(!dev) {
    print( ERROR, "device '%s' not found", interface);
    pcap_freealldevs(devlist);
    return -1;
  }
  
  for(a=dev->addresses;a && status;a=a->next) {
    
    print( DEBUG, "sa_family=%02hX", a->addr->sa_family );
    
    if(a->addr->sa_family == AF_INET) {
      i = (struct sockaddr_in *) a->addr;
      
      memcpy(if_info.ip_addr, &(i->sin_addr.s_addr), 4);
      
      i = (struct sockaddr_in *) a->netmask;
      
      if(i) {
        memcpy(&(if_info.ip_mask), &(i->sin_addr.s_addr), 4);
        status &= ~(L3_NOT_FOUND);
      }
    } else if(a->addr->sa_family == AF_PACKET) {
      l = (struct sockaddr_ll *) a->addr;
      
      if(l->sll_halen != ETH_ALEN) continue;
      
      memcpy(if_info.eth_addr, l->sll_addr, ETH_ALEN);
      status &= ~(L2_NOT_FOUND);
    }
  }
  
  pcap_freealldevs(devlist);
  
  if(status) {
    if(status & L2_NOT_FOUND) {
      print( ERROR, "cannot find link layer address");
    }
    if(status & L3_NOT_FOUND) {
      print( ERROR, "cannot find IPv4 address");
    }
    return -1;
  }
  
  handle = pcap_open_live(interface, 1514, 0, 0, err_buff);
  
  if(!handle) {
    print( ERROR, "pcap_open_live: %s", err_buff);
    return -1;
  }
  
  if(*err_buff) {
    print( ERROR, "pcap_open_live: %s", err_buff);
  }
  
  if(pcap_datalink(handle) != DLT_EN10MB) {
    print( ERROR, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
    pcap_close(handle);
    return -1;
  }
  
  if(pcap_compile(handle, &filter, "( ( ( arp or rarp ) and (arp[6:2] & 1 == 0 ) ) or ( udp and port 137 ))", 1, (bpf_u_int32) if_info.ip_mask)) {
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
