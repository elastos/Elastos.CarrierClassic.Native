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
#ifndef __EXPRESS_CONNECTOR__
#define __EXPRESS_CONNECTOR__

#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ElaCarrier           ElaCarrier;
typedef struct ExpressConnector     ExpressConnector;

typedef void (*ExpressOnRecvCallback)(ElaCarrier *carrier,
                                     const char *from,
                                     const uint8_t *message, size_t len);

ExpressConnector *express_connector_create(ElaCarrier *w, ExpressOnRecvCallback on_msg_cb, ExpressOnRecvCallback on_req_cb);

void express_connector_kill(ExpressConnector *);

int express_enqueue_pull_messages(ExpressConnector *);

int express_enqueue_friend_message(ExpressConnector *, const char *friendid, const void *, size_t);

int express_enqueue_friend_request(ExpressConnector *, const char *address, const void *, size_t);

#ifdef __cplusplus
}
#endif

#endif //__EXPRESS_CONNECTOR__
