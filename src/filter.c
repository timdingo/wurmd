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

#include <string.h>

#include <netinet/ip.h>

#include <pcap/pcap.h>

#include "include/errors.h"
#include "include/filter.h"
#include "include/inetutils.h"
#include "include/safermem.h"

extern char *cfg_file;

char *create_pcap_filter(char *dev)
{
    pcap_if_t *pcap_devices, *devices_it;
    pcap_addr_t *addr;
    char errbuf[PCAP_ERRBUF_SIZE];

    char *pcap_filter = s_malloc(s_strlen(PCAP_ARP_AND));
    strcpy(pcap_filter, PCAP_ARP_AND);

    char *pcap_filter_udp = s_malloc(s_strlen(PCAP_UDP_DST_PORT_137));
    strcpy(pcap_filter_udp, PCAP_UDP_DST_PORT_137);

    char *pcap_filter_syn = s_malloc(s_strlen(PCAP_TCP_FLAGS_SYN));
    strcpy(pcap_filter_syn, PCAP_TCP_FLAGS_SYN);

    if (pcap_findalldevs(&pcap_devices, errbuf))
        eprintf(MSG_FAILED_PCAP_FINDDEVS, errbuf);

    devices_it = pcap_devices;
    short int counter=0;

    while(devices_it != NULL)
    {
        if (*devices_it->name == *dev)
        {
            addr = devices_it->addresses;
            while (addr != NULL)
            {
                if(addr->addr->sa_family == AF_INET)
                {
                    if (counter)
                    {
                        pcap_filter = s_strcat(&pcap_filter, PCAP_OR);
                        pcap_filter_udp = s_strcat(&pcap_filter_udp,PCAP_OR);
                        pcap_filter_syn = s_strcat(&pcap_filter_syn, PCAP_OR);
                    }

                    char tcp4_address_buffer[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET,&(((struct sockaddr_in*)addr->addr)->sin_addr),
                        tcp4_address_buffer, INET_ADDRSTRLEN);

                    char *tcp4_address = tcp4_address_buffer;
                    validate_inet_addr(tcp4_address);

                    pcap_filter_syn = s_strcat(&pcap_filter_syn, PCAP_SRC);
                    pcap_filter_syn = s_strcat(&pcap_filter_syn, tcp4_address);
                    pcap_filter_udp = s_strcat(&pcap_filter_udp, PCAP_AND_SRC);
                    pcap_filter_udp = s_strcat(&pcap_filter_udp, tcp4_address);

                    char *tcp4_address_hex = tcp4_dec_to_hex(tcp4_address);
                    pcap_filter = s_strcat(&pcap_filter, PCAP_ETHER_28_4);
                    pcap_filter = s_strcat(&pcap_filter, tcp4_address_hex);

                    free(tcp4_address_hex);
                    counter++;
                }
                addr = addr->next;
            }
        }
        devices_it = devices_it->next;
    }
    pcap_freealldevs(pcap_devices);

    // READING THE CONFIG FILE
    static short int read_buffer = 96;
    char *cfg_line, *tcp4_address, *ethernet_address;
    cfg_line = s_malloc(read_buffer);
    tcp4_address = s_malloc(15);
    ethernet_address = s_malloc(18);

    FILE *fp;
    fp = fopen(cfg_file, "r");

    if(fp==NULL)
        eprintf(MSG_FAILED_CONFIG_OPEN, cfg_file);

    s_strcat(&pcap_filter, PCAP_CLOSE_AND_OPEN);
    s_strcat(&pcap_filter_syn, PCAP_CLOSE_AND_OPEN);

    short int config_entry = 0;

    /* read from config file */
    while(fgets(cfg_line, read_buffer, fp) != NULL)
    {
        if (!strncmp(cfg_line, "#", 1) || !strncmp(cfg_line, "\n", 1))
            // skip commented and new lines
            continue;

        if (config_entry)
        {
            s_strcat(&pcap_filter, PCAP_OR);
            s_strcat(&pcap_filter_syn, PCAP_OR);
        }

        sscanf(cfg_line, "%s %s", tcp4_address, ethernet_address);
        validate_inet_addr(tcp4_address);
        validate_ethernet_address(ethernet_address);

        s_strcat(&pcap_filter_syn, PCAP_DST);
        s_strcat(&pcap_filter_syn, tcp4_address);

        char *taddrh = tcp4_dec_to_hex(tcp4_address);

        s_strcat(&pcap_filter, PCAP_EHTER_38_4);
        s_strcat(&pcap_filter, taddrh);

        free(taddrh);

        if (!config_entry)
            config_entry=1;
    }

    if (!config_entry)
    {
        eprintf(MSG_HOST_CFG);
    }

    fclose(fp);

    /* closing and concatenating everything */
    s_strcat(&pcap_filter, PCAP_DOUBLE_CLOSE);
    s_strcat(&pcap_filter_udp, PCAP_CLOSE);
    s_strcat(&pcap_filter_syn, PCAP_DOUBLE_CLOSE);

    s_strcat(&pcap_filter, pcap_filter_udp);
    s_strcat(&pcap_filter, pcap_filter_syn);

    free(cfg_line);
    free(tcp4_address);
    free(ethernet_address);

    return pcap_filter;
}

void pcap_loop_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    char *target = get_target_from_packet(args, pkthdr, packet);
    char *ethernet_address = get_ethernet_address_associated_with_target(target);
    validate_ethernet_address(ethernet_address);
    unsigned char *wol_packet = make_wol_payload(ethernet_address);

    if (send_packet(wol_packet))
        vprintf(MSG_NO_BROADCAST, ethernet_address);

    free(wol_packet);
    vprintf(MSG_WOL_BROADCAST, ethernet_address);
    free(ethernet_address);
}
