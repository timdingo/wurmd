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

#include <sys/types.h>

#ifndef FILTER_H
#define FILTER_H

// arp [6:2] = 1 -> arp.opcode 1 (request)
#define PCAP_ARP_AND "(arp and (arp [6:2] = 1) and ("
#define PCAP_UDP_DST_PORT_137 " or (udp dst port 137 and ("
#define PCAP_TCP_FLAGS_SYN " or (tcp[tcpflags] == tcp-syn and ("
#define PCAP_OR " or "
#define PCAP_SRC "src "
#define PCAP_ETHER_28_4 "ether[28:4]="
#define PCAP_EHTER_38_4 "ether[38:4]="
#define PCAP_DOUBLE_CLOSE "))"
#define PCAP_DST "dst "
#define PCAP_CLOSE_AND_OPEN ") and ("

char * create_pcap_filter(const char * dev, const char * cfg_file);
void pcap_loop_callback(u_char * args, const struct pcap_pkthdr * packet_header, const u_char * packet);

typedef struct pcap_loop_callback_args
{
    char * cfg_file;
} pcap_loop_callback_args_t;

#endif
