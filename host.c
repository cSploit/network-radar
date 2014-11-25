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