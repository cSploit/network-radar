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

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <errno.h>

#include "logger.h"

#include "ifinfo.h"
#include "host.h"
#include "event.h"
#include "prober.h"
#include "resolver.h"

struct hosts_data hosts;

/**
 * @brief initalize host table
 * @param ip interface ip address
 * @param mask interface network mask
 * @returns 0 on success, -1 on error.
 */
int init_hosts() {
  int zerobits,b;
  
  for(zerobits=b=0;b<32;b++) {
    if(!((ifinfo.ip_mask >> b) & 1))
      zerobits++;
  }
  
  // UINT32_MAX = 2^32 -1
  hosts.maxindex = (pow(2, zerobits) - 1);
  
  hosts.array = calloc(sizeof(struct host *), ((uint64_t)hosts.maxindex) + 1);
  
  if(!hosts.array) {
    print( ERROR, "calloc: %s\n", strerror(errno));
    return -1;
  }
  
  hosts.mask = ~ifinfo.ip_mask;
  hosts.base_ip = ifinfo.ip_addr & ifinfo.ip_mask;
  
  return 0;
}

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
