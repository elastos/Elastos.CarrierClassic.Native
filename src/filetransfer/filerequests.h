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

#ifndef __FILEREQUESTS_H__
#define __FILEREQUESTS_H__

#include <assert.h>
#include <stddef.h>
#include <crystal.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#define FILE_TRANSFER_REQUEST_EXPIRE_INTERVAL (5 * 60) // 5m

typedef struct FileRequest {
    linked_hash_entry_t he;

    struct timeval expire_time;
    char from[CARRIER_MAX_ID_LEN + 1 + 36];
    char *sdp;
    size_t sdp_len;
} FileRequest;

static
int filereqs_from_compare(const void *key1, size_t len1,
                          const void *key2, size_t len2)
{
    return strcmp((const char *)key1, (const char *)key2);
}

static inline
linked_hashtable_t *filereqs_create(int capacity)
{
    return linked_hashtable_create(capacity, 1, NULL, filereqs_from_compare);
}

static inline
int filereqs_exist(linked_hashtable_t *filereqs, const char *from)
{
    assert(filereqs);
    assert(from);

    return linked_hashtable_exist(filereqs, from, strlen(from));
}

static inline
void filereqs_put(linked_hashtable_t *filereqs, FileRequest *fr)
{
    struct timeval now, interval;

    assert(filereqs);
    assert(fr);

    fr->he.data = fr;
    fr->he.key = fr->from;
    fr->he.keylen = strlen(fr->from);

    gettimeofday(&now, NULL);
    interval.tv_sec = FILE_TRANSFER_REQUEST_EXPIRE_INTERVAL;
    interval.tv_usec = 0;
    timeradd(&now, &interval, &fr->expire_time);

    linked_hashtable_put(filereqs, &fr->he);
}

static inline
FileRequest *filereqs_get(linked_hashtable_t *filereqs, const char *from)
{
    assert(filereqs);
    assert(from);

    return (FileRequest *)linked_hashtable_get(filereqs, from, strlen(from));
}

static inline
FileRequest *filereqs_remove(linked_hashtable_t *filereqs, const char *from)
{
    assert(filereqs);
    assert(from);

    return (FileRequest *)linked_hashtable_remove(filereqs, from, strlen(from));
}

static inline
void filereqs_clear(linked_hashtable_t *filereqs)
{
    assert(filereqs);
    linked_hashtable_clear(filereqs);
}

static inline
linked_hashtable_iterator_t *filereqs_iterate(linked_hashtable_t *filereqs,
                                       linked_hashtable_iterator_t *iterator)
{
    assert(filereqs && iterator);
    return linked_hashtable_iterate(filereqs, iterator);
}

static inline
int filereqs_iterator_next(linked_hashtable_iterator_t *iterator, FileRequest **fr)
{
    assert(iterator && fr);
    return linked_hashtable_iterator_next(iterator, NULL, NULL, (void **)fr);
}

static inline
int filereqs_iterator_has_next(linked_hashtable_iterator_t *iterator)
{
    assert(iterator);
    return linked_hashtable_iterator_has_next(iterator);
}

#endif /* __FILEREQUESTS_H__ */
