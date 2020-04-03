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

#include <crystal.h>

#include "lmsg.h"
#include "dht.h"
#include "ela_carrier_impl.h"

struct LMsgManager {
    ElaCarrier *carrier;
    hashtable_t *msg_pool;
    void (*on_msg)(ElaCarrier *carrier, const char *from,
                        const void *msg, size_t len, void *context);
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
} LMsg;

static
void lmsg_dtor(void *obj)
{
    LMsg *msg = (LMsg *)obj;

    deref(msg->buf);
}

static
LMsg *lmsg_create(LMsgManager *mgr, const char *node_id, uint32_t init_buf_len)
{
    LMsg *msg;

    msg = rc_zalloc(sizeof(LMsg), lmsg_dtor);
    if (!msg)
        return NULL;

    msg->buf = rc_zalloc(init_buf_len, NULL);
    if (!msg->buf) {
        deref(msg);
        return NULL;
    }

    strcpy(msg->node_id, node_id);
    msg->buf_len = init_buf_len;
    msg->he.data = msg;
    msg->he.key = msg->node_id;
    msg->he.keylen = strlen(msg->node_id);

    hashtable_put(mgr->msg_pool, &msg->he);

    return msg;
}

void feed_lmsg_seg(LMsgManager *mgr, const char *from, ElaCP *cp)
{
    LMsg *msg;
    const void *seg;
    size_t seg_len;
    size_t msg_len;

    seg  = elacp_get_raw_data(cp);
    msg_len = elacp_get_raw_data_length(cp);
    seg_len = elacp_get_seg_length(cp);

    msg = hashtable_get(mgr->msg_pool, from, strlen(from));
    if (msg && msg->state == ERRORED) {
        deref(msg);
        return;
    }

    if (msg && msg->state == ASSEMBLING) {
        if (seg_len > msg->total_len - msg->asm_len) {
            deref(msg->buf);
            msg->buf = NULL;
            msg->buf_len = 0;
            msg->state = ERRORED;
            deref(msg);
            return;
        }

        memcpy((char *)msg->buf + msg->asm_len, seg, seg_len);
        msg->asm_len += seg_len;

        if (msg->total_len != msg->asm_len) {
            deref(msg);
            return;
        }

        if (mgr->on_msg)
            mgr->on_msg(mgr->carrier, from, msg->buf, msg->total_len, mgr->context);
        msg->state = IDLE;
        msg->total_len = 0;
        msg->asm_len = 0;
        deref(msg);

        return;
    }

    if (seg_len == msg_len) {
        if (mgr->on_msg)
            mgr->on_msg(mgr->carrier, from, seg, seg_len, mgr->context);
        deref(msg);
        return;
    }

    if (!msg && !(msg = lmsg_create(mgr, from, msg_len)))
        return;

    if (msg->buf_len < msg_len) {
        void *buf;

        buf = rc_realloc(msg->buf, msg_len);
        if (!buf) {
            deref(msg->buf);
            msg->buf = NULL;
            msg->buf_len = 0;
            msg->state = ERRORED;
            deref(msg);
            return;
        }

        msg->buf = buf;
        msg->buf_len = msg_len;
    }

    msg->total_len = msg_len;
    msg->asm_len = seg_len;
    memcpy(msg->buf, seg, seg_len);
    msg->state = ASSEMBLING;
    deref(msg);
}

static
void mgr_dtor(void *obj)
{
    LMsgManager *mgr = (LMsgManager *)obj;

    if (mgr->msg_pool) {
        hashtable_clear(mgr->msg_pool);
        deref(mgr->msg_pool);
    }
}

LMsgManager *lmsg_mgr_create(ElaCarrier *c,
                              void (*on_msg)(ElaCarrier *w,
                                                const char *from,
                                                const void *msg,
                                                size_t len,
                                                void *context),
                              void *context)
{
    LMsgManager *mgr;

    mgr = rc_zalloc(sizeof(LMsgManager), mgr_dtor);
    if (!mgr)
        return NULL;

    mgr->msg_pool = hashtable_create(8, 0, NULL, NULL);
    if (!mgr->msg_pool) {
        deref(mgr);
        return NULL;
    }

    mgr->carrier = c;
    mgr->on_msg = on_msg;
    mgr->context = context;

    return mgr;
}

int send_lmsg(LMsgManager *mgr, uint32_t to, const void *msg, size_t len)
{
    size_t len2tx = len;
    const char *cursor = msg;
    int rc;

    while (len2tx) {
        size_t seg_len = len2tx < ELA_MAX_APP_MESSAGE_LEN ?
                         len2tx : ELA_MAX_APP_MESSAGE_LEN;
        ElaCP *cp;
        uint8_t *data;
        size_t data_len;

        cp = elacp_create(ELACP_TYPE_LARGE_MESSAGE, NULL);
        if (!cp)
            return ELA_GENERAL_ERROR(ELAERR_OUT_OF_MEMORY);

        elacp_set_raw_data(cp, cursor, len);
        elacp_set_seg_length(cp, seg_len);

        data = elacp_encode(cp, &data_len);
        elacp_free(cp);

        if (!data)
            return ELA_GENERAL_ERROR(ELAERR_OUT_OF_MEMORY);

        rc = dht_friend_message(&mgr->carrier->dht, to, data, data_len);
        free(data);
        if (rc < 0)
            return rc;

        cursor += seg_len;
        len2tx -= seg_len;
    }

    return 0;
}

void notify_lmsg_mgr_disconnection(LMsgManager *mgr, const char *friendid)
{
    deref(hashtable_remove(mgr->msg_pool, friendid, strlen(friendid)));
}

void lmsg_mgr_delete(LMsgManager *mgr)
{
    deref(mgr);
}

