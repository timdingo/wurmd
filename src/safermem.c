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

#include <stdlib.h>
#include <string.h>

#include "include/safermem.h"
#include "include/errors.h"

void *s_malloc(size_t size)
{
    /* NOTE: C std currently guarantees sizeof(char) to be 1.
     *       and nearly every s_malloc() called assumes so. */
    void *ptr = malloc(size);
    if (ptr == NULL)
        eprintf(MSG_MALLOC_FAILED);
    return ptr;
}

size_t s_strlen(const char *string)
{
    return (strlen(string) + 1);
}

char *s_strcat(char **target, char *append)
{
    *target = realloc(*target, strlen(*target) + s_strlen(append));
    if (target == NULL)
        eprintf(MSG_MALLOC_FAILED);
    strcat(*target, append);
    return *target;
}
