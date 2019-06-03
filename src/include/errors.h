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

#ifndef ERRORS_H
#define ERRORS_H

#include <stdio.h>
#include <syslog.h>
#include <time.h>

#define MSG_HOST_CFG "No hosts configured in the configuration file."
#define MSG_CHANGE_CURDIR "Could not change working directory to %s."
#define MSG_CURDIR "Current working dir: %s."
#define MSG_NO_HOMEDIR "No home directory (or a bad one) defined."
#define MSG_LOCKFILE "Lockfile: %s."
#define MSG_NO_LOCKFILE "Can't create a lockfile."
#define MSG_NOT_SINGLE_INSTANCE "Another instance is already running."
#define MSG_COULD_NOT_CONVERT_ADDRESS "Couldn't convert address %s."
#define MSG_ARP_REQUEST "ARP request for %s detected."
#define MSG_MALFORMED_NBNS "Malformed NBNS packet, something is very wrong here."
#define MSG_NBNS_REQUEST "NBNS request for %s detected."
#define MSG_TCP_INIT "Initial TCP connection detected to %s."
#define MSG_NO_BROADCAST "couldn't broadcast WoL for %s."
#define MSG_WOL_BROADCAST "WoL broadcast for %s."
#define MSG_FAILED_REGEX_COMPILE "Could not compile regex."
#define MSG_INVALID_ETHERNET "Not a valid mac address: %s."
#define MSG_INVALID_IP "Not a valid IP address: %s."
#define MSG_MALLOC_FAILED "Couldn't assign needed memory."
#define MSG_SIGNAL_SIGINT "SIGINT detected, shutting down."
#define MSG_FAILED_PCAP_FINDDEVS "Couldn't iterate over all network devices: %s."
#define MSG_FAILED_CONFIG_OPEN "Can't open configuration file %s."
#define MSG_FAILED_SOCK_INIT "Couldn't create socket."
#define MSG_FAILED_BCAST_FLAG "Couldn't set broadcast flag on socket."
#define MSG_ARGUMENT_CANNOT_BE_EMPTY "Value for argument -%s cannot be an empty string.\n"
#define MSG_COULD_NOT_ITERATE_DEVICES "Couldn't list all devices: %s."
#define MSG_NEEDS_CFG_FILE "%s needs a config file to run.\n%s"
#define MSG_WORKING_ON "Working the magic on %s."
#define MSG_FAILED_FILTER_INSTALL "Couldn't install filter %s: %s."
#define MSG_PCAP_FILTER "Pcap filter: %s."
#define MSG_FAILED_PCAP_FILTER_PARSE "Couldn't parse filter %s: %s."
#define MSG_OPEN_DEVICE_FAILED "Couldn't open device %s: %s."
#define MSG_GET_IP_ADDR_FAILED "Couldn't get ip address for device %s."
#define MSG_NO_INTERFACE_PROVIDED "No interface option provided, using %s."
#define MSG_NO_DEFAULT_DEVICE "Couldn't find default device: %s."
#define MSG_OPEN_CONF_FAILED "Can't open config file %s: %s.\n"
#define MSG_OPEN_FILE_APPEND "Can't open file %s for appending: %s.\n"
#define MSG_SHUTTING_DOWN "Shutting down."
#define MSG_PCAP_LOOP_RET "pcap_loop_ret: %d, pcap_geterr: %s"
#define MSG_COMPARE_TO_NOTHING "Comparing something to nothing is no better than dividing by 0!"

extern char * log_file;
extern short int verbose, debug, background;

#define EPRINTF(format, ...)\
{\
    fprintf(stderr, format, ##__VA_ARGS__);\
    fprintf(stderr, "\n");\
    FILE *ptr = fopen(log_file, "a+");\
    if ( ptr == NULL )\
    {\
        openlog("wurmd", LOG_PID|LOG_CONS|LOG_NDELAY, LOG_USER);\
        syslog(LOG_ERR, format, ##__VA_ARGS__);\
        closelog();\
    }\
    else\
    {\
        time_t tt = time(NULL);\
        char *t = ctime(&tt);\
        t[strlen(t) - 1] = 0;\
        fprintf(ptr, "%s - Error: ", t);\
        fprintf(ptr, format, ##__VA_ARGS__);\
        fprintf(ptr, "\n");\
        fclose(ptr);\
        exit(1);\
    }\
};

#define VPRINTF(format, ...)\
{\
    if(verbose || debug)\
    {\
        if (!background)\
        {\
            fprintf(stdout, format, ##__VA_ARGS__);\
            fprintf(stdout, "\n");\
        }\
        else\
        {\
            FILE *ptr=fopen(log_file,"a+");\
            if ( ptr == NULL )\
            {\
                openlog("wurmd", LOG_PID|LOG_CONS|LOG_NDELAY, LOG_USER);\
                syslog(LOG_INFO, format, ##__VA_ARGS__);\
                closelog();\
            }\
            else\
            {\
                time_t tt=time(NULL);\
                char *t=ctime(&tt);\
                t[strlen(t) - 1] = 0;\
                fprintf(ptr, "%s - Info: ", t);\
                fprintf(ptr, format, ##__VA_ARGS__);\
                fprintf(ptr, "\n");\
                fclose(ptr);\
            }\
        }\
    }\
};

#define DPRINTF(format, ...)\
{\
    if(debug)\
    {\
        if (!background)\
        {\
            fprintf(stdout, format, ##__VA_ARGS__);\
            fprintf(stdout, "\n");\
        }\
        else\
        {\
            FILE *ptr = fopen(log_file, "a+");\
            if ( ptr == NULL )\
            {\
                openlog("wurmd", LOG_PID|LOG_CONS|LOG_NDELAY, LOG_USER);\
                syslog(LOG_DEBUG, format, ##__VA_ARGS__);\
                closelog();\
            }\
            else\
            {\
                time_t tt = time(NULL);\
                char *t = ctime(&tt);\
                t[strlen(t) - 1] = 0;\
                fprintf(ptr, "%s - Debug: ", t);\
                fprintf(ptr, format, ##__VA_ARGS__);\
                fprintf(ptr, "\n");\
                fclose(ptr);\
            }\
        }\
    }\
}

#endif
