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

#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/limits.h>
#include <sys/stat.h>

#include "include/errors.h"
#include "include/safermem.h"
#include "include/system.h"

void daemonize(void)
{
    pid_t pid, sid;
    char * curdir = getcwd(NULL, 0);
    pid = fork();
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
    {
        exit(EXIT_SUCCESS);
    }
    umask(0);
    sid = setsid();
    if (sid < 0)
    {
        exit(EXIT_FAILURE);
    }
    if ((chdir(curdir)) < 0)
    {
        EPRINTF(MSG_CHANGE_CURDIR, curdir);
    }
    DPRINTF(MSG_CURDIR, curdir);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
}

char * get_lockfile(void)
{
    char * bspth = getenv("HOME");
    if (bspth == NULL || bspth[0] != '/')
        EPRINTF(MSG_NO_HOMEDIR);
    char * lockfile = s_malloc(strlen(bspth) + (sizeof("/"LCKFD)));
    strcpy(lockfile, bspth);
    s_strcat(&lockfile, "/"LCKFD);
    return lockfile;
}

int set_lock(char * lockfile)
{
    int fd;
    struct flock fdfl;
    fdfl.l_type = F_WRLCK;
    fdfl.l_whence = SEEK_SET;
    fdfl.l_start = 0;
    fdfl.l_len = 0;

    fd = open(lockfile, O_RDWR|O_CREAT, 0600);
    if (fd == -1)
        EPRINTF(MSG_NO_LOCKFILE);

    if (fcntl(fd, F_SETLK, &fdfl) == -1)
        EPRINTF(MSG_NOT_SINGLE_INSTANCE);

    return fd;
}

void signal_handler(int sig)
{
    signal(sig, SIG_IGN);
    VPRINTF(MSG_SIGNAL_SIGINT);
	exit(0);
}

pid_t get_pid_of_process(char * process)
{
    pid_t pid = -1;
    char * process_line = s_malloc(PID_STR);
    FILE * cmd = popen(process, "r");
    fgets(process_line, PID_STR, cmd);
    pid = (int) strtoul(process_line, NULL, PID_STR);
    return pid;
}
