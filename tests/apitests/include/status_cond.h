/*
 * Copyright (c) 2018 Elastos Foundation
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

#ifndef __API_TESTS_STATUS_COND_H__
#define __API_TESTS_STATUS_COND_H__

#include <time.h>
#include <errno.h>
#include <pthread.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include <crystal.h>

#include "cond.h"

typedef struct StatusCondition {
    Condition cond;
} StatusCondition;

#define DEFINE_STATUS_COND(obj) obj = { .cond = COND_INITIALIZER }

static inline void status_cond_wait(StatusCondition *cond, Carrier *c,
                                    const char *friend_id, CarrierConnectionStatus status)
{
    while (true) {
        CarrierFriendInfo fi;

        carrier_get_friend_info(c, friend_id, &fi);
        if (fi.status != status) {
            cond_wait(&cond->cond);
            continue;
        }

        break;
    }
}

static inline void status_cond_signal(StatusCondition *cond)
{
    cond_signal(&cond->cond);
}

static inline void status_cond_reset(StatusCondition *cond)
{
    // do nothing
}

#endif /* __API_TESTS_STATUS_COND_H__*/
