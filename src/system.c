/* Copyright 2018, Timothy Demulder <timothy@syphzero.net>
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

#include <sys/stat.h>

#include "include/errors.h"
#include "include/safermem.h"
#include "include/system.h"

void daemonize()
{
    pid_t pid, sid;
    char *curdir;
    curdir = getcwd(NULL, 0);
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
        eprintf(MSG_CHANGE_CURDIR, curdir);
        exit(EXIT_FAILURE);
    }
    dprintf(MSG_CURDIR, curdir);
    free(curdir);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
}

void single_instance_check()
{
    char *lockfile;
    int fd;
	struct flock fdfl;
	fdfl.l_type = F_WRLCK;
	fdfl.l_whence = SEEK_SET;
    fdfl.l_start = 0;
    fdfl.l_len = 0;
    char *bspth = getenv("HOME");

    if (bspth == NULL || bspth[0] != '/')
        eprintf(MSG_NO_HOMEDIR);

    lockfile = s_malloc((sizeof(char)*strlen(bspth)) + (sizeof("/"LCKFD)));

    strcpy(lockfile, bspth);
    strcat(lockfile, "/"LCKFD);
    fd = open(lockfile, O_RDWR|O_CREAT, 0600);

    if (fd == -1)
        eprintf(MSG_NO_LOCKFILE);

    if (fcntl(fd, F_SETLK, &fdfl) == -1)
        eprintf(MSG_NOT_SINGLE_INSTANCE);
}

void signal_handler(int sig)
{
    signal(sig, SIG_IGN);
    vprintf(MSG_SIGNAL_SIGINT);
	exit(0);
}
