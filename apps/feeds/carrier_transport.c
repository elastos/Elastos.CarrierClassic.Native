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

#include <string.h>

#include <crystal.h>

#include "carrier_transport.h"

struct CarrierTransport {
    ElaCarrier *carrier;
    hashtable_t *seg_pool;
    void (*on_data_cb)(CarrierTransport *, const char *, const void *, size_t, void *);
    void *context;
};

typedef struct {
    hash_entry_t he;
    char node_id[ELA_MAX_ID_LEN + 1];
    enum {
        IDLE = 0,
        ASSEMBLING,
        ERRORED,
    } state;
    uint32_t total_len;
    uint32_t asm_len;
    uint32_t buf_len;
    void *buf;
} Segmentation;

static
void segmentation_destructor(void *obj)
{
    Segmentation *seg = (Segmentation *)obj;

    deref(seg->buf);
}

static
Segmentation *segmentation_create(CarrierTransport *ct, const char *node_id,
                                  uint32_t init_buf_len)
{
    Segmentation *s;

    s = rc_zalloc(sizeof(Segmentation), segmentation_destructor);
    if (!s)
        return NULL;

    s->buf = rc_zalloc(init_buf_len, NULL);
    if (!s->buf) {
        deref(s);
        return NULL;
    }

    strcpy(s->node_id, node_id);
    s->buf_len = init_buf_len;
    s->he.data = s;
    s->he.key = s->node_id;
    s->he.keylen = strlen(s->node_id);

    hashtable_put(ct->seg_pool, &s->he);

    return s;
}

static
void carrier_transport_destructor(void *obj)
{
    CarrierTransport *ct = (CarrierTransport *)obj;

    if (ct->seg_pool) {
        hashtable_clear(ct->seg_pool);
        deref(ct->seg_pool);
    }
}

CarrierTransport *carrier_transport_create(ElaCarrier *c,
                                           void (*on_data)(CarrierTransport *ct,
                                                           const char *from,
                                                           const void *msg,
                                                           size_t len,
                                                           void *context),
                                           void *context)
{
    CarrierTransport *ct;

    ct = rc_zalloc(sizeof(CarrierTransport), carrier_transport_destructor);
    if (!ct)
        return NULL;

    ct->seg_pool = hashtable_create(8, 0, NULL, NULL);
    if (!ct->seg_pool) {
        deref(ct);
        return NULL;
    }

    ct->carrier = c;
    ct->on_data_cb = on_data;
    ct->context = context;

    return ct;
}

int carrier_transport_send_message(CarrierTransport *ct, const char *to,
                                   const void *msg, size_t len)
{
    void *buf;
    int rc;
    size_t seg_len;

    if (len < ELA_MAX_APP_MESSAGE_LEN)
        return ela_send_friend_message(ct->carrier, to, msg, len, NULL);

    buf = alloca(ELA_MAX_APP_MESSAGE_LEN);
    seg_len = ELA_MAX_APP_MESSAGE_LEN - sizeof(uint32_t);

    *(uint32_t *)buf = htonl(len);
    memcpy(buf + sizeof(uint32_t), msg, seg_len);

    rc =  ela_send_friend_message(ct->carrier, to, buf, ELA_MAX_APP_MESSAGE_LEN, NULL);
    if (rc < 0)
        return -1;

    msg += seg_len;
    len -= seg_len;

    while (len) {
        seg_len = len > ELA_MAX_APP_MESSAGE_LEN ? ELA_MAX_APP_MESSAGE_LEN : len;

        rc =  ela_send_friend_message(ct->carrier, to, msg, seg_len, NULL);
        if (rc < 0)
            return -1;

        msg += seg_len;
        len -= seg_len;
    }

    return 0;
}

void carrier_transport_friend_disconnected(CarrierTransport *ct, const char *friendid)
{
    deref(hashtable_remove(ct->seg_pool, friendid, strlen(friendid)));
}

void carrier_transport_message_received(CarrierTransport *ct, const char *from,
                                        const void *msg, size_t len)
{
    Segmentation *s;
    const void *seg;
    uint32_t seg_len;
    uint32_t total_len;

    s = hashtable_get(ct->seg_pool, from, strlen(from));
    if (s && s->state == ERRORED) {
        deref(s);
        return;
    }

    if (s && s->state == ASSEMBLING) {
        if (len > s->total_len - s->asm_len) {
            deref(s->buf);
            s->buf = NULL;
            s->buf_len = 0;
            s->state = ERRORED;
            deref(s);
            return;
        }

        memcpy(s->buf + s->asm_len, msg, len);
        s->asm_len += len;

        if (s->total_len != s->asm_len) {
            deref(s);
            return;
        }

        ct->on_data_cb(ct, from, s->buf, s->total_len, ct->context);
        s->state = IDLE;
        s->total_len = 0;
        s->asm_len = 0;
        deref(s);

        return;
    }

    if (len < ELA_MAX_APP_MESSAGE_LEN) {
        ct->on_data_cb(ct, from, msg, len, ct->context);
        deref(s);
        return;
    }

    total_len = ntohl(*(uint32_t *)msg);
    seg = msg + sizeof(uint32_t);
    seg_len = len - sizeof(uint32_t);

    if (!s && !(s = segmentation_create(ct, from, total_len)))
        return;

    if (s->buf_len < total_len) {
        void *buf;

        buf = rc_realloc(s->buf, total_len);
        if (!buf) {
            deref(s->buf);
            s->buf = NULL;
            s->buf_len = 0;
            s->state = ERRORED;
            deref(s);
            return;
        }

        s->buf = buf;
        s->buf_len = total_len;
    }

    s->total_len = total_len;
    s->asm_len = seg_len;
    memcpy(s->buf, seg, seg_len);
    s->state = ASSEMBLING;
    deref(s);
}

void carrier_transport_delete(CarrierTransport *ct)
{
    deref(ct);
}
