static char version[]=
"\nwurmd.c: v20181106 Timothy Demulder <timothy@syphzero.net>, https://github.com/timdingo/wurmd/\n";
static char usage[] =
"usage: wurmd [-o <mac>] [-i <ifname>] [-fvd] [-l <config file>] -c <config file>\n";
static char lusage[] =
"\n  This daemon generates and transmits Wake-On-Lan (WoL) packets \n"
"  to configured hosts based on networking events in an attempt to\n"
"  wake up sleeping machines when they're actually needed.\n"
"\nOptions:\n"
"	-o mac		Send one WoL packet to MAC address, once.\n"
"	-i ifname       Use interface IFNAME instead of the system's default.\n"
"	-c conffile     Use the configuration file CONFFILE.\n"
"	-v              Be verbose.\n"
"	-d		Be even more verbose (DEBUG)\n"
"	-f		Don't run in the background\n"
"	-l logfile	Use the log file LOGFILE\n"
"			(default: /var/log/wurmd.log)\n";
/*
 * To the nice people who wrote libpcap: thanks.
 * 
 * Copyright 2018, Timothy Demulder <timothy@syphzero.net>
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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "include/errors.h"
#include "include/filter.h"
#include "include/inetutils.h"
#include "include/system.h"

char *cfg_file, *logfile="/var/log/wurmd.log";
short int verbose = 0, debug = 0, background = 1;

int main(int argc, char *argv[])
{
    char *inet_device = NULL;
    char *single_shot_wol = NULL;
	int c;

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
            printf("%s", usage);
            printf("%s", lusage);
            printf("%s", version);
			return 0;
		case 'i':
            inet_device=optarg;
			break;
		case 'c':
            cfg_file=optarg;
			break;
		case 'f':
            background = 0;
			break;
		case 'l':
			logfile=optarg;
			break;
		case 'o':
            background = 0;
            single_shot_wol=optarg;
			break;

        case '?':
			if (optopt == 'c')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint (optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
                fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
            printf("%s", usage);
			return 1;

		default:
            abort();
	}

    if (getuid())
    {
        fprintf(stderr, "%s: This program must be run as uid 0.\n", argv[0]);
        exit(1);
    }

    if (single_shot_wol)
    {
        validate_ethernet_address(single_shot_wol);

        unsigned char *packet = make_wol_payload(single_shot_wol);

        if(send_packet(packet))
            eprintf(MSG_NO_BROADCAST, single_shot_wol);
        vprintf(MSG_WOL_BROADCAST, single_shot_wol);
		exit(0);
	}

    single_instance_check();

    /* config file check */
    if (cfg_file == NULL)
        eprintf("%s needs a config file to run.\n%s", argv[0], usage);

    /* log file check before daemonizing */
	FILE *fp;
	fp = fopen(logfile, "a+");
    if(fp==NULL)
        eprintf("Can't open log file %s for appending.\n", logfile);
	fclose(fp);

    if (background)
        daemonize();

    // register SIGINT
	signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];

    if (inet_device == NULL)
    {
        inet_device = pcap_lookupdev(errbuf);
        if (inet_device == NULL)
			eprintf("Couldn't find default device: %s\n", errbuf);
        vprintf("No interface option provided, using %s\n", inet_device);
	}

    bpf_u_int32 mask, net;
    if (pcap_lookupnet(inet_device, &net, &mask, errbuf) == -1)
		eprintf("Couldn't get ip address for device %s\n", errbuf);

    char *pcap_filter = create_pcap_filter(inet_device);

    pcap_t *pcap_session_handle = pcap_open_live(
        inet_device,
        BUFSIZ,
        1 /* pcappromisc */,
        1000 /* pcaptimeout */,
        errbuf);

    if (pcap_session_handle == NULL)
        eprintf("Couldn't open device %s: %s\n", inet_device, errbuf);

    struct bpf_program pcap_filter_bin;
    memset(&pcap_filter_bin, 0, sizeof(struct bpf_program));

    if (pcap_compile(pcap_session_handle, &pcap_filter_bin, pcap_filter, 0, net) == -1)
        eprintf("Couldn't parse filter %s: %s\n",
            pcap_filter, pcap_geterr(pcap_session_handle));

    if (pcap_setfilter(pcap_session_handle, &pcap_filter_bin) == -1)
        eprintf("Couldn't install filter %s: %s\n",
            pcap_filter, pcap_geterr(pcap_session_handle));

    vprintf("Working the magic on %s\n", inet_device);
    dprintf("Pcap filter: %s\n", pcap_filter);
    free(pcap_filter); // not needed any more: we've got the compiled version

    const int packet_capture_amount = -1; // unlimited
    pcap_loop(pcap_session_handle, packet_capture_amount, pcap_loop_callback, NULL);
	return(0);
}
