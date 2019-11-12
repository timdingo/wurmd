static char version[]=
"Version 20190603 - Timothy Demulder <timothy@syphzero.net> - https://github.com/timdingo/wurmd/";
static char usage[] =
"usage: wurmd [-o <mac>] [-i <ifname>] [-fvd] [-l <log file>] -c <config file>";
static char lusage[] =
"This daemon generates and transmits Wake-On-Lan (WoL) packets\n"
"to configured hosts based on networking events in an attempt to\n"
"wake up sleeping machines when they're actually needed.\n"
"\nOptions:\n"
"	-o mac		Send one WoL packet to MAC address, once.\n"
"	-i ifname       Use interface IFNAME instead of the system's default.\n"
"	-c conffile     Use the configuration file CONFFILE.\n"
"	-v              Be verbose.\n"
"	-d		Be even more verbose (DEBUG)\n"
"	-f		Don't run in the background\n"
"	-l logfile	Use the log file LOGFILE\n"
"			(default: /var/log/wurmd.log)";
/*
 * To the nice people who wrote libpcap: thanks.
 * 
 * Copyright 2019, Timothy Demulder <timothy@syphzero.net>
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

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/limits.h>
#include <pcap/pcap.h>
#include <sys/types.h>

#include "include/errors.h"
#include "include/filter.h"
#include "include/inetutils.h"
#include "include/safermem.h"
#include "include/system.h"

short int verbose = 0, debug = 0, background = 1;
char *log_file = NULL;

int main(int argc, char *argv[])
{    
    char *inet_device = NULL;
    char *ethernet_address = NULL;
    int c = 0;

    char *cfg_file = NULL;

	while ((c = getopt (argc, argv, "fdvhl:i:c:o:")) != -1)

        switch (c)
        {
            case 'v':
                verbose=1;
                break;
            case 'd':
                debug=1;
                verbose=1;
                break;
            case 'h':
                printf("%s\n", usage);
                printf("\n%s\n", lusage);
                printf("%s\n", version);
                exit(0);
            case 'i':
                inet_device = s_malloc(IFNAMSIZ);
                strcpy(inet_device, optarg);
                if (str_empty(inet_device))
                {
                    free(inet_device);
                    fprintf(stderr, MSG_ARGUMENT_CANNOT_BE_EMPTY, "i");
                    exit(1);
                }
                break;
            case 'c':
                cfg_file = s_malloc(PATH_MAX);
                strcpy(cfg_file, optarg);
                if (str_empty(cfg_file))
                {
                    fprintf(stderr, MSG_NEEDS_CFG_FILE, argv[0], usage);
                    free(cfg_file);
                    exit(1);
                }
                break;
            case 'f':
                background = 0;
                break;
            case 'l':
                log_file = s_malloc(PATH_MAX);
                strcpy(log_file, optarg);
                if (str_empty(log_file))
                {
                    fprintf(stderr, MSG_ARGUMENT_CANNOT_BE_EMPTY, "l");
                    free(log_file);
                    exit(1);
                }
                break;
            case 'o':
                background = 0;
                ethernet_address = s_malloc(ARPADDRSIZ);
                strcpy(ethernet_address, optarg);
                break;
            case '?':
                if (optopt == 'c' || optopt == 'l' || optopt == 'o' || optopt == 'i')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                printf("%s\n", usage);
                exit(1);
            default:
                // safety: should never be reached
                abort();
        }

    /* pre flight checks */
    if (getuid())
    {
        fprintf(stderr, "%s: This program must be run as uid 0.\n", argv[0]);
        exit(1);
    }

    if (log_file == NULL)
        log_file = LOGFILE;

    /* log file check before daemonizing */
    FILE *log_fp = fopen(log_file, "a+");
    if(log_fp == NULL)
    {
        fprintf(stderr, MSG_OPEN_FILE_APPEND, log_file, strerror(errno));
        return(1);
    }
    fclose(log_fp);

    if (ethernet_address)
    {
        validate_ethernet_address(ethernet_address);

        unsigned char * packet = make_wol_payload(ethernet_address);

        if(send_packet(packet))
            EPRINTF(MSG_NO_BROADCAST, ethernet_address);
        VPRINTF(MSG_WOL_BROADCAST, ethernet_address);

        free(ethernet_address);
        free(packet);
        return(0);
	}

    if (cfg_file == NULL && ethernet_address == NULL)
    {
        fprintf(stderr, MSG_NEEDS_CFG_FILE, argv[0], usage);
        free(cfg_file);
        return(1);
    }

    FILE *cfg_fp = fopen(cfg_file, "r"); // TODO: this still validates "./"
    if(cfg_fp == NULL)
    {
        fprintf(stderr, MSG_OPEN_CONF_FAILED, cfg_file, strerror(errno));
        return(1);
    }
    fclose(cfg_fp);

    if (background)
    {
        daemonize();
    }

    char * lockfile = get_lockfile();
    int fd = set_lock(lockfile);

    // register SIGINT
    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    pcap_if_t *dev_list = {0};

    if (str_empty(inet_device))
    {
        inet_device = s_malloc(IFNAMSIZ);
        if(pcap_findalldevs(&dev_list, errbuf) != 0)
            EPRINTF(MSG_COULD_NOT_ITERATE_DEVICES, errbuf);
        // TODO: handle no devices at all
        strcpy(inet_device, dev_list->next->name);

        if (str_empty(inet_device))
            EPRINTF(MSG_NO_DEFAULT_DEVICE, errbuf);
        VPRINTF(MSG_NO_INTERFACE_PROVIDED, inet_device);
    }

    bpf_u_int32 mask, net;
    if (pcap_lookupnet(inet_device, &net, &mask, errbuf) == -1)
        EPRINTF(MSG_GET_IP_ADDR_FAILED, errbuf);

    char * pcap_filter = create_pcap_filter(inet_device, cfg_file);

    pcap_t *pcap_session_handle = pcap_open_live(
        inet_device,
        BUFSIZ,
        1 /* pcappromisc */,
        1000 /* pcaptimeout */,
        errbuf);

    if (pcap_session_handle == NULL)
        EPRINTF(MSG_OPEN_DEVICE_FAILED, inet_device, errbuf);

    struct bpf_program pcap_filter_bin;
    memset(&pcap_filter_bin, 0, sizeof(struct bpf_program));

    if (pcap_compile(pcap_session_handle, &pcap_filter_bin, pcap_filter, 0, net) == -1)
        EPRINTF(MSG_FAILED_PCAP_FILTER_PARSE,
            pcap_filter, pcap_geterr(pcap_session_handle));

    DPRINTF(MSG_PCAP_FILTER, pcap_filter);
    free(pcap_filter);

    if (pcap_setfilter(pcap_session_handle, &pcap_filter_bin) == -1)
        EPRINTF(MSG_FAILED_FILTER_INSTALL,
            pcap_filter, pcap_geterr(pcap_session_handle));

    VPRINTF(MSG_WORKING_ON, inet_device);

    const int packet_capture_amount = -1; // unlimited
    pcap_loop_callback_args_t callback_args = { cfg_file };
    u_char * args = (u_char *) & callback_args;
    int pcap_loop_ret = 0;

    do
    {
        pcap_loop_ret = pcap_loop(pcap_session_handle, packet_capture_amount, pcap_loop_callback, args);
        DPRINTF(MSG_PCAP_LOOP_RET, pcap_loop_ret, pcap_geterr(pcap_session_handle));
    }
    while(pcap_loop_ret); // can never get 0 as packet_capture_amount can never get exhausted nor are we
                          // reading from a pcap recorded file as per PCAP_LOOP(3PCAP) man page.

    VPRINTF(MSG_SHUTTING_DOWN);

    free(pcap_session_handle);
    free(inet_device);
    close(fd);
    free(lockfile);

    return(0);
}
