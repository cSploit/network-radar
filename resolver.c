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

#include <pthread.h>
#include <stdint.h>
#include <ares.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>

#include "logger.h"

#include "control.h"
#include "event.h"
#include "host.h"

ares_channel channel;
pthread_t resolver_tid = 0;

data_control resolver_control;

void on_query_end(void *arg, int status, int timeouts, struct hostent *ent) {
  uint32_t ip;
  struct host *h;
  struct event *e;
  
  if(status != ARES_SUCCESS)
    return;
  
  // avoid unuseful names
  if(strstr(ent->h_name, ".in-addr.arpa"))
    return;
  
  e = NULL;
  ip = *((uint32_t *) &arg);
  
  pthread_mutex_lock(&(hosts.control.mutex));
  
  h = get_host(ip);
  
  if(h && !(h->name)) {
    
    e = malloc(sizeof(struct event));
    if(!e) {
      print( ERROR, "malloc: %s\n", strerror(errno));
    }
    e->type = NEW_NAME;
    e->ip = ip;
    
    h->name = strdup(ent->h_name);
  }
  
  pthread_mutex_unlock(&(hosts.control.mutex));
  
  if(e) add_event(e);
}

void begin_dns_lookup(uint32_t ip) {
  
  ares_gethostbyaddr(channel, &ip, 4, AF_INET, on_query_end, ((void *)0) + ip);
  
  pthread_cond_broadcast(&(resolver_control.cond));
}

void *resolver(void *arg) {
  int nfds;
  fd_set readers, writers;
  struct timeval tv, *tvp;
  
  pthread_mutex_lock(&(resolver_control.mutex));
  while (resolver_control.active) {
    pthread_mutex_unlock(&(resolver_control.mutex));
    
    FD_ZERO(&readers);
    FD_ZERO(&writers);
    
    nfds = ares_fds(channel, &readers, &writers);
    
    if(!nfds) {
      // c-ares docs say that we should break and exit here,
      // but have 0 queries is an accaptable state, we have
      // just to wait for new ones.
      pthread_cond_wait(&(resolver_control.cond), &(resolver_control.mutex));
      continue;
    }
    
    tvp = ares_timeout(channel, NULL, &tv);
    
    select(nfds, &readers, &writers, NULL, tvp);
    ares_process(channel, &readers, &writers);
    
    pthread_mutex_lock(&(resolver_control.mutex));
  }
  pthread_mutex_unlock(&(resolver_control.mutex));
  
  ares_library_cleanup();
  
  return NULL;
}

int start_resolver() {
  int ret;
  
  ret = ares_library_init(ARES_LIB_INIT_ALL);
  
  if(ret) {
    print( ERROR, "ares_library_init: %s\n", ares_strerror(ret));
    return -1;
  }
  
  ret = ares_init(&channel);
  
  if(ret) {
    print( ERROR, "ares_init: %s\n", ares_strerror(ret));
    ares_library_cleanup();
    return -1;
  }
  
  if(control_init(&resolver_control)) {
    ares_destroy(channel);
    ares_library_cleanup();
    return -1;
  }
  
  if(pthread_create(&resolver_tid, NULL, resolver, NULL)) {
    print( ERROR, "pthread_create: %s\n", strerror(errno));
    resolver_tid = 0;
    control_destroy(&resolver_control);
    ares_destroy(channel);
    ares_library_cleanup();
    return -1;
  }
  
  return 0;
}

void stop_resolver() {
  pthread_t tid;
  
  if(resolver_tid) {
    tid = resolver_tid;
    resolver_tid = 0;
    
    control_deactivate(&resolver_control);
    ares_destroy(channel);
    pthread_join(tid, NULL);
    control_destroy(&resolver_control);
  }
}