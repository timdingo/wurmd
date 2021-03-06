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

#ifndef NET_H
#define NET_H

#include<stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <regex.h>

#define NTOHL(x)	(x) = ntohl(x)
#define AR_TPA(ap)	(((const u_char *)((ap)+1))+2*(ap)->ar_hln+(ap)->ar_pln)
#define PCAP_VALIDATE_MAC_ADDRESS "^\\([0-9a-fA-F]\\{2\\}:\\)\\{5\\}[0-9a-fA-F]\\{2\\}$"

int send_packet(const unsigned char * packet);
char * tcp4_dec_to_hex(const char * tcp4_address);
char * get_target_from_packet(const u_char * packet);
char * get_ethernet_address_associated_with_target(const char * input, const char * cfg_file);
unsigned char * make_wol_payload(const char * aeaddr);
void send_wol_packet(const char * ethernet_address);
void validate_ethernet_address(const char * ethernet_address);
void validate_inet_addr(const char * taddr);
char * intoa(u_int32_t addr);
int str_empty(const char * string);

typedef struct nbnshdr
{
    uint16_t nametrnid;
    uint16_t opcode;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} nbnshdr_t;

#endif
