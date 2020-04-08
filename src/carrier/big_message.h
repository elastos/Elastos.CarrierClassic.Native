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

#ifndef __BIG_MESSAGE_H__
#define __BIG_MESSAGE_H__

#include <crystal.h>

typedef struct {
    hash_entry_t he;
    uint32_t friend_number;
    enum {
        IDLE = 0,
        ASSEMBLING,
        ERRORED,
    } state;
    uint32_t total_len;
    uint32_t asm_len;
    uint32_t buf_len;
    void *buf;
} BigMessage;

static inline
BigMessage *big_message_get(hashtable_t *pool, uint32_t friend_number)
{
    assert(pool);
    assert(friend_number != UINT32_MAX);

    return (BigMessage *)hashtable_get(pool, &friend_number, sizeof(uint32_t));
}

static inline
void big_message_put(hashtable_t *pool, BigMessage *msg)
{
    assert(pool);
    assert(msg);

    msg->he.data = msg;
    msg->he.key = &msg->friend_number;
    msg->he.keylen = sizeof(msg->friend_number);

    hashtable_put(pool, &msg->he);
}

static inline
BigMessage *big_message_remove(hashtable_t *pool, uint32_t friend_number)
{
    assert(pool);
    assert(friend_number != UINT32_MAX);

    return hashtable_remove(pool, &friend_number, sizeof(uint32_t));
}

static inline
void big_message_destructor(void *obj)
{
    BigMessage *msg = (BigMessage *)obj;
    deref(msg->buf);
}

static inline
BigMessage *big_message_create(uint32_t friend_number, uint32_t buf_len)
{
    BigMessage *msg;

    msg = rc_zalloc(sizeof(BigMessage), big_message_destructor);
    if (!msg)
        return NULL;

    msg->buf = rc_zalloc(buf_len, NULL);
    if (!msg->buf) {
        deref(msg);
        return NULL;
    }

    msg->friend_number = friend_number;
    msg->buf_len = buf_len;

    return msg;
}

static inline
int big_message_pool_key_compare(const void *key1, size_t len1,
                                 const void *key2, size_t len2)
{
    assert(key1 && sizeof(uint32_t) == len1);
    assert(key2 && sizeof(uint32_t) == len2);

    return memcmp(key1, key2, sizeof(uint32_t));
}

static inline
hashtable_t *big_message_pool_create(int capacity)
{
    return hashtable_create(capacity, 1, NULL,
                            big_message_pool_key_compare);
}

#endif // __BIG_MESSAGE_H__
