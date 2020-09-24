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

#ifndef __MSG_OTF_H__
#define __MSG_OTF_H__

#include <crystal.h>
#include "ela_carrier.h"

typedef struct MessageOnTheFly {
    hash_entry_t he;

    char to[ELA_MAX_ID_LEN + 1];
    MsgCh msgch;
    int64_t msgid;

    ElaFriendMessageReceiptCallback *callback;
    void *context;

    size_t size;
    uint8_t data[0];
} MessageOnTheFly;

static inline
hashtable_t *motfs_create()
{
    return hashtable_create(0, 0, NULL, NULL);
}

static inline
MessageOnTheFly *motf_get(hashtable_t *motfs, int64_t msgid)
{
    assert(motfs);
    assert(msgid);

    return hashtable_get(motfs, &msgid, sizeof(msgid));
}

static inline
void motf_put(hashtable_t *motfs, MessageOnTheFly *motf)
{
    assert(motfs);
    assert(motf);

    motf->he.data = motf;
    motf->he.key = &motf->msgid;
    motf->he.keylen = sizeof(motf->msgid);

    hashtable_put(motfs, &motf->he);
}

static inline
MessageOnTheFly *motf_remove(hashtable_t *motfs, int64_t msgid)
{
    assert(motfs);

    return hashtable_remove(motfs, &msgid, sizeof(msgid));
}

static inline
hashtable_iterator_t *motfs_iterate(hashtable_t *motfs,
                                    hashtable_iterator_t *iterator)
{
    assert(motfs);
    assert(iterator);

    return hashtable_iterate(motfs, iterator);
}

static inline
int motfs_iterator_next(hashtable_iterator_t *iterator, MessageOnTheFly **item)
{
    assert(item);
    assert(iterator);

    return hashtable_iterator_next(iterator, NULL, NULL, (void **)item);
}

static inline
int motfs_iterator_has_next(hashtable_iterator_t *iterator)
{
    assert(iterator);
    return hashtable_iterator_has_next(iterator);
}

static inline
int motfs_iterator_remove(hashtable_iterator_t *iterator)
{
    assert(iterator);
    return hashtable_iterator_remove(iterator);
}

#endif // __MSG_OTF_H__
