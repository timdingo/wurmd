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

#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#include "include/inetutils.h"
#include "include/errors.h"
#include "include/safermem.h"
#include "include/system.h"

void validate_ethernet_address(const char * ethernet_address)
{
    regex_t re;

    if(regcomp(&re, PCAP_VALIDATE_MAC_ADDRESS, 0) != 0)
    {
        regfree(&re);
        eprintf(MSG_FAILED_REGEX_COMPILE);
    }

    if(regexec(&re, ethernet_address, 0, NULL, 0) != 0)
    {
        regfree(&re);
        eprintf(MSG_INVALID_ETHERNET, ethernet_address);
    }

    regfree(&re);
}

void validate_inet_addr(const char * inet_address)
{
    struct in_addr tcstr;
    if (!inet_aton(inet_address, &tcstr))
        eprintf(MSG_INVALID_IP, inet_address);
}

char * intoa(u_int32_t addr) /* Stolen from tcpdump */
{
    register char *cp;
    register u_int byte;
    register int n;
    static char buf[sizeof(".xxx.xxx.xxx.xxx")];
    NTOHL(addr);
    cp = buf + sizeof(buf);
    *--cp = '\0';
    n = 4;
    do
    {
        byte = addr & 0xff;
        *--cp = byte % 10 + '0';
        byte /= 10;
        if (byte > 0)
        {
            *--cp = byte % 10 + '0';
            byte /= 10;
            if (byte > 0)
                *--cp = byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    }
    while (--n > 0);
    return cp + 1;
}

char * get_target_from_packet(const u_char * packet)
{
    char *nmptr;
    const struct ether_header *etherhdr;
    etherhdr = (struct ether_header *)(packet);
    const struct ip * ip;
    ip = (struct ip *)(packet + sizeof(struct ether_header));
    const struct udphdr * udphdr;
    udphdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    const nbnshdr_t * nbnshdr;
    nbnshdr = (struct nbnshdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

    /* Based on the PCAP filter we define 3 scenarios here:
     *  - ARP packet with ARP OP code of 256
     *  - UDP packet with a destination of 137 and an NetBIOS OP code of 4097 (NM name request)
     *  - IPV4 SYN packet
     */

    if (ntohs(etherhdr->ether_type) == ETHERTYPE_ARP)
    {
        struct arphdr* arp_header = (struct arphdr*)(packet + sizeof(struct ether_header));
        if (arp_header->ar_op == 256)
        {
            u_int32_t addr;
            memcpy(&addr, AR_TPA(arp_header), sizeof(addr));
            nmptr=intoa(addr);
            vprintf(MSG_ARP_REQUEST, nmptr);
        }
        else
        {
            /* satisfying static analysis on above conditional and nmptr */
            exit(-1);
        }
    }
    else if (ip->ip_p == IPPROTO_UDP && ntohs(udphdr->dest) == 137 && nbnshdr->opcode == 4097)
    {
        /* nbnshdr->opcode should be 0x0001000000000001 for a NB name request */
        unsigned char databuf,datanbuf;
        char nbnsaddrbuf[16] = "";
        int idx = 0;
        const unsigned char *nbnsdata = (packet + sizeof(struct ether_header) + sizeof(struct ip) +
            sizeof(struct udphdr) + sizeof(struct nbnshdr) - 1);
        for(;;)
        {
            databuf = *nbnsdata;
            if (databuf == '\0' || databuf < 'A' || databuf > 'Z' )
                break;
            databuf -= 'A';
            datanbuf = databuf << 4;
            nbnsdata++;
            databuf = *nbnsdata;
            if (databuf=='\0' || databuf < 'A' || databuf > 'Z' )
                eprintf(MSG_MALFORMED_NBNS);
            databuf -= 'A';
            datanbuf= databuf | datanbuf;
            nbnsdata++;
            if (datanbuf == 32)
                continue;
            if (idx <= NBNS_NAME_MAX)
                nbnsaddrbuf[idx++] = datanbuf;
        }
        nbnsaddrbuf[idx] = '\0';
        nmptr = nbnsaddrbuf;
        vprintf(MSG_NBNS_REQUEST, nmptr);
    }
    else
    {
        char taddrbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_dst), taddrbuf, INET_ADDRSTRLEN);
        nmptr = taddrbuf;
        vprintf(MSG_TCP_INIT, nmptr);
    }
    return nmptr;
}

char * tcp4_dec_to_hex(const char * tcp4_dec)
{
    char *tcp4_hex = s_malloc(TCP4ADDRSIZHEX);
    uint tcp4_oct_0, tcp4_oct_1, tcp4_oct_2, tcp4_oct_3;
    if (sscanf(tcp4_dec, "%u.%u.%u.%u", &tcp4_oct_0, &tcp4_oct_1, &tcp4_oct_2, &tcp4_oct_3) != 4)
        eprintf(MSG_COULD_NOT_CONVERT_ADDRESS, tcp4_dec);
    snprintf(tcp4_hex, 11, "0x%.2x%.2x%.2x%.2x", tcp4_oct_0, tcp4_oct_1, tcp4_oct_2, tcp4_oct_3);
    return tcp4_hex;
}

char * get_ethernet_address_associated_with_target(const char * input, const char * cfg_file)
{
    if (str_empty(input))
        eprintf("Comparing something to nothing is no better than dividing by 0!\n");

    char * bfr = s_malloc(CONFIG_READ_BUFFER);
    char * tcp4_address = s_malloc(TCP4ADDRSIZ);
    char * ethernet_address = s_malloc(ARPADDRSIZ);
    char * nbaddr = s_malloc(NBADDRSIZE);
    FILE * fp;

    fp = fopen(cfg_file, "r");
    if(fp == NULL)
        eprintf(MSG_FAILED_CONFIG_OPEN, cfg_file);

    while(fgets(bfr, CONFIG_READ_BUFFER, fp) != NULL)
    {
        if (!strncmp(bfr, "#", 1) || !strncmp(bfr, "\n", 1))
            continue;
        sscanf(bfr, "%s %s %s", tcp4_address, ethernet_address, nbaddr);

        if (!strcmp(tcp4_address, input))
            break;
        if (!strcmp(nbaddr, input))
            break;
    }
    fclose(fp);
    free(bfr);
    free(tcp4_address);
    free(nbaddr);
    return ethernet_address;
}

unsigned char * make_wol_payload(char * aeaddr)
{
    unsigned char *payload = s_malloc(102); //6+(16*6) bytes
    struct ether_addr *ethernet_address;
    ethernet_address = ether_aton(aeaddr);

    memset(payload, 0xff, 6);
    for (short int i = 0; i < 16; ++i)
    {
        memcpy(payload + (6 * (i + 1)), ethernet_address, 6);
    }
    return payload;
}

int send_packet(unsigned char *packet)
{
    const char *bcastinet="255.255.255.255";
    const int portnr = 9;
    const int pktsize = (102);
    int socket_ptr = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ptr < 0)
        eprintf(MSG_FAILED_SOCK_INIT);
    int enbcast = 1;
    if (setsockopt(socket_ptr,SOL_SOCKET,SO_BROADCAST, &enbcast, sizeof(enbcast)))
    {
        close(socket_ptr);
        eprintf(MSG_FAILED_BCAST_FLAG);
    }
    struct sockaddr_in bcast_sockaddr;
    memset(&bcast_sockaddr, 0, sizeof(bcast_sockaddr));
    bcast_sockaddr.sin_family = AF_INET;
    inet_pton(AF_INET, bcastinet , &bcast_sockaddr.sin_addr);
    bcast_sockaddr.sin_port = htons(portnr);
    int ret = sendto(socket_ptr,packet,pktsize,0,(struct sockaddr*)&bcast_sockaddr, sizeof bcast_sockaddr);
    if (ret < 0 )
    {
        close(socket_ptr);
        return 1;
    }
    close(socket_ptr);
    return 0;
}

int str_empty(const char * string)
{
    return (string == NULL || (string != NULL && string[0] == '\0'));
}
