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
#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <stdint.h>
#include <net/ethernet.h>

extern pcap_t *handle;

extern struct if_info {
  uint8_t  eth_addr[ETHER_ADDR_LEN];
  uint8_t  ip_addr[4];
  uint32_t ip_mask;
} if_info;

int start_sniff(char *);
void stop_sniff(void);

#endif