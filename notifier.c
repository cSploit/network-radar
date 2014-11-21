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
#include <arpa/inet.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "logger.h"

#include "event.h"
#include "host.h"

pthread_t notifier_tid = 0;

void *notifier(void *arg) {
  struct event *e;
  const char *name;
  struct host *h;
  char ip_str[INET_ADDRSTRLEN + 1];
  
  pthread_mutex_lock(&(events.control.mutex));
  
  while(events.control.active) {
  
    while(!events.list.head && events.control.active)
      pthread_cond_wait(&(events.control.cond), &(events.control.mutex));
    
    e = (struct event *) queue_get(&(events.list));
    
    if(!e) continue;
    
    if(!inet_ntop(AF_INET, &(e->ip), ip_str, INET_ADDRSTRLEN)) {
      print( ERROR, "inet_ntop(%u): %s\n", e->ip, strerror(errno));
      ip_str[0] = '\0';
    }
    
    name = NULL;
    
    pthread_mutex_lock(&(hosts.control.mutex));
    
    h = get_host(e->ip);
    
    if(h && h->name)
      name = strdup(h->name);
    
    pthread_mutex_unlock(&(hosts.control.mutex));
    
    switch(e->type) {
      case MAC_LOST:
        printf("DEL_HOST %*s\n", INET_ADDRSTRLEN, ip_str);
        break;
      case MAC_CHANGED:
        printf("DEL_HOST %*s\n", INET_ADDRSTRLEN, ip_str);
      case NEW_MAC:
        printf("NEW_HOST %*s %s\n", INET_ADDRSTRLEN, ip_str, (name ? name : ""));
        break;
      case NAME_CHANGED:
        printf("DEL_NAME %*s\n", INET_ADDRSTRLEN, ip_str);
      case NEW_NAME:
        printf("NEW_NAME %*s %s\n", INET_ADDRSTRLEN, ip_str, (name ? name : ""));
        break;
    }
    
    free(e);
    
    if(name)
      free((void *) name);
    
    fflush(stdout);
  }
  
  pthread_mutex_unlock(&(events.control.mutex));
  
  return NULL;
}


int start_notifier() {
  if(pthread_create(&notifier_tid, NULL, notifier, NULL)) {
    print( ERROR, "pthread_create: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}

void stop_notifier() {
  pthread_t tid;
  
  if(notifier_tid) {
    tid = notifier_tid;
    notifier_tid = 0;
    
    control_deactivate(&(events.control));
    pthread_join(tid, NULL);
  }
}