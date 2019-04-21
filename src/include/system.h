/* Copyright 2019, Timothy Demulder <timothy@syphzero.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SYSTEM_H
#define SYSTEM_H

#include <fcntl.h>

#define UNUSED_ARG(x) (void)(x)

#define LCKFD ".wurmd.lck"
#define CONFIG_READ_BUFFER 96 // ipv4 + mac + netbios name
#define IFNAMSIZ 16 // From Linux' include/uapi/linux/if.h
#define TCP4ADDRSIZ 15
#define TCP4ADDRSIZHEX 11
#define NBADDRSIZE 17
#define NBNS_NAME_MAX 16
#define ARPADDRSIZ 18
#define LOGFILE "/var/log/wurmd.log"

void daemonize(void);
char * get_lockfile(void);
int set_lock(char * lockfile);
void signal_handler(int sig);
pid_t get_pid_of_process(char * process);

#endif
