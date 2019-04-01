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
#include <time.h>

#define MSG_HOST_CFG "No hosts configured in the configuration file."
#define MSG_CHANGE_CURDIR "Could not change working directory to %s."
#define MSG_CURDIR "Current working dir: %s."
#define MSG_NO_HOMEDIR "No home directory (or a bad one) defined."
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
#define MSG_INVALID_ETHERNET "%s is not a valid mac address."
#define MSG_INVALID_IP "%s is not a valid IP address."
#define MSG_MALLOC_FAILED "Couldn't assign needed memory."
#define MSG_SIGNAL_SIGINT "SIGINT detected, shutting down."
#define MSG_FAILED_PCAP_FINDDEVS "Couldn't iterate over all network devices: %s."
#define MSG_FAILED_CONFIG_OPEN "Can't open configuration file %s."
#define MSG_FAILED_SOCK_INIT "Couldn't create socket."
#define MSG_FAILED_BCAST_FLAG "Couldn't set broadcast flag on socket."

extern char *logfile;
extern short int verbose, debug, background;

#define eprintf(format, ...)\
    do{\
        fprintf(stderr, format,##__VA_ARGS__);\
        fprintf(stderr, "\n");\
        FILE *ptr;\
        ptr=fopen(logfile,"a+");\
        time_t tt=time(NULL);\
        char *t=ctime(&tt);\
        t[strlen(t)-1]=0;\
        fprintf(ptr,"%s - Error: ",t);\
        fprintf(ptr,format,##__VA_ARGS__);\
        fprintf(ptr, "\n");\
        fclose(ptr);\
        exit(1);\
    }\
    while(0)

#define vprintf(format, ...)\
    do{\
        if(verbose){\
            if (!background) {\
                fprintf(stdout,format,##__VA_ARGS__);\
                fprintf(stdout, "\n");\
            }\
            else {\
                FILE *ptr;\
                ptr=fopen(logfile,"a+");\
                time_t tt=time(NULL);\
                char *t=ctime(&tt);\
                t[strlen(t)-1]=0;\
                fprintf(ptr,"%s - Info: ",t);\
                fprintf(ptr,format,##__VA_ARGS__);\
                fprintf(ptr, "\n");\
                fclose(ptr);\
            }\
        }\
    }\
    while(0)

#define dprintf(format, ...)\
    do{\
        if(debug){\
            if (!background) {\
                fprintf(stdout,format,##__VA_ARGS__);\
                fprintf(stdout, "\n");\
            }\
            else {\
                FILE *ptr;\
                ptr=fopen(logfile,"a+");\
                time_t tt=time(NULL);\
                char *t=ctime(&tt);\
                t[strlen(t)-1]=0;\
                fprintf(ptr,"%s - Debug: ",t);\
                fprintf(ptr,format,##__VA_ARGS__);\
                fprintf(ptr, "\n");\
                fclose(ptr);\
            }\
        }\
    }\
    while(0)

#endif
