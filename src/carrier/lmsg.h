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

#ifndef __LMSG_H__
#define __LMSG_H__

#include "elacp.h"

typedef struct LMsgManager LMsgManager;

LMsgManager *lmsg_mgr_create(ElaCarrier *c,
                              void (*on_msg)(ElaCarrier *w,
                                                const char *from,
                                                const void *msg,
                                                size_t len,
                                                void *context),
                              void *context);

int send_lmsg(LMsgManager *mgr, uint32_t to, const void *msg, size_t len);

void feed_lmsg_seg(LMsgManager *mgr, const char *from, ElaCP *cp);

void notify_lmsg_mgr_disconnection(LMsgManager *mgr, const char *friendid);

void lmsg_mgr_delete(LMsgManager *mgr);

#endif // __LMSG_H__
