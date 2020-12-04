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

#ifndef __UNCONFIRMED_MSGS_H__
#define __UNCONFIRMED_MSGS_H__

#include <crystal.h>
#include "carrier.h"

typedef struct UnconfirmedMsg {
    hash_entry_t he;

    char to[ELA_MAX_ID_LEN + 1];
    uint32_t msgid;
    int offline_sending;

    ElaFriendMessageReceiptCallback *callback;
    void *context;

    size_t size;
    uint8_t data[0];
} UnconfirmedMsg;

static inline
hashtable_t *unconfirmed_create()
{
    return hashtable_create(0, 0, NULL, NULL);
}

static inline
UnconfirmedMsg *unconfirmed_get(hashtable_t *msgs, uint32_t msgid)
{
    assert(msgs);
    assert(msgid);

    return hashtable_get(msgs, &msgid, sizeof(msgid));
}

static inline
void unconfirmed_put(hashtable_t *msgs, UnconfirmedMsg *item)
{
    assert(msgs);
    assert(item);

    item->he.data = item;
    item->he.key = &item->msgid;
    item->he.keylen = sizeof(item->msgid);

    hashtable_put(msgs, &item->he);
}

static inline
UnconfirmedMsg *unconfirmed_remove(hashtable_t *msgs, int32_t msgid)
{
    assert(msgs);
    return hashtable_remove(msgs, &msgid, sizeof(msgid));
}

static inline
hashtable_iterator_t *unconfirmed_iterate(hashtable_t *msgs,
                                          hashtable_iterator_t *iterator)
{
    assert(msgs);
    assert(iterator);

    return hashtable_iterate(msgs, iterator);
}

static inline
int unconfirmed_iterator_next(hashtable_iterator_t *iterator, UnconfirmedMsg **item)
{
    assert(item);
    assert(iterator);

    return hashtable_iterator_next(iterator, NULL, NULL, (void **)item);
}

static inline
int unconfirmed_iterator_has_next(hashtable_iterator_t *iterator)
{
    assert(iterator);
    return hashtable_iterator_has_next(iterator);
}

static inline
int unconfirmed_iterator_remove(hashtable_iterator_t *iterator)
{
    assert(iterator);
    return hashtable_iterator_remove(iterator);
}

#endif // __UNCONFIRMED_MSGS_H__
