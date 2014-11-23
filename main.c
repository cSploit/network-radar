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
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#include "logger.h"

#include "event.h"
#include "sniffer.h"
#include "notifier.h"
#include "resolver.h"
#include "prober.h"
#include "host.h"
#include "ifinfo.h"
#include "main.h"

void signal_handler(int signal) {
  stop_sniff();
  stop_notifier();
  stop_prober();
  stop_resolver();
}

/**
 * @brief register main thread signal handlers
 * @returns 0 on success, -1 on error.
 */
int register_signal_handlers() {
  struct sigaction action;
  
  action.sa_handler = signal_handler;
  sigemptyset(&(action.sa_mask));
  action.sa_flags = 0;
  
  if(sigaction(SIGINT, &action, NULL)) {
    print( ERROR, "sigaction(SIGINT): %s", strerror(errno) );
    return -1;
  } else if(sigaction(SIGTERM, &action, NULL)) {
    print( ERROR, "sigaction(SIGTERM): %s", strerror(errno) );
    return -1;
  }
  
  return 0;
}

int main(int argc, char **argv) {
  char *prog_name;
  
  if(argc < 2 || !strncmp(argv[1], "-h", 3) || !strncmp(argv[1], "--help", 7) ) {
    prog_name = strrchr(argv[0], '/');
    
    if(!prog_name)
      prog_name = argv[0];
    else
      prog_name++;
    
    print( ERROR, "Usage: %s <interface>\n", prog_name);
    return EXIT_FAILURE;
  }
  
  if(get_ifinfo(argv[1]))
    return EXIT_FAILURE;
  
  if(register_signal_handlers())
    return EXIT_FAILURE;
  
  if(control_init(&(events.control)))
    return EXIT_FAILURE;
  
  if(control_init(&(hosts.control)))
    return EXIT_FAILURE;
  
  if(start_notifier())
    return EXIT_FAILURE;
  
  if(start_resolver())
    return EXIT_FAILURE;
  
  if(start_sniff()) {
    stop_resolver();
    return EXIT_FAILURE;
  }
  
  prober(NULL);
  
  return EXIT_SUCCESS;
}
