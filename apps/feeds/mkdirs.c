/*
 * Copyright (c) 2020 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#include "mkdirs.h"

static
int mkdir_internal(const char *path, mode_t mode)
{
    struct stat st;
    int rc = 0;

    if (stat(path, &st) != 0) {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            rc = -1;
    } else if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        rc = -1;
    }

    return rc;
}

int mkdirs(const char *path, mode_t mode)
{
    int rc = 0;
    char *pp;
    char *sp;
    char copypath[PATH_MAX];

    strncpy(copypath, path, sizeof(copypath));
    copypath[sizeof(copypath) - 1] = 0;

    pp = copypath;
    while (rc == 0 && (sp = strchr(pp, '/')) != 0) {
        if (sp != pp) {
            /* Neither root nor double slash in path */
            *sp = '\0';
            rc = mkdir_internal(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }

    if (rc == 0)
        rc = mkdir_internal(path, mode);

    return rc;
}

