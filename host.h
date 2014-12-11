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
#ifndef HOST_H
#define HOST_H

#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>

#include "control.h"

#define HOST_LOOKUP_DNS 1
#define HOST_LOOKUP_NBNS 2

struct host {
  uint8_t mac[6];
  char *name;
  char lookup_status;
  time_t timeout;
};

extern struct hosts_data {
  struct host **array;
  uint32_t mask;
  uint32_t base_ip;
  uint32_t maxindex;
  data_control control;
} hosts;

/** seconds of inactivity to mark an host as disconnected  */
#define HOST_TIMEOUT 60

#define get_host_addr(i) (htonl(i) | hosts.base_ip);
#define get_host_index(ip) ntohl(ip & hosts.mask)
#define get_host(ip) hosts.array[get_host_index(ip)]
#define set_host(ip, h) (hosts.array[get_host_index(ip)] = h)
#define del_host(ip) set_host(ip, NULL)
#define free_host(h) do { if(h->name) free(h->name); free(h); } while(0)
#define get_host_max_index() (hosts.maxindex)

int init_hosts();
void on_host_found(uint8_t *, uint32_t , char *, char);

#endif