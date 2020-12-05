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

#ifndef __CARRIER_EXTENSIONS_H__
#define __CARRIER_EXTENSIONS_H__

#include <string.h>
#include <assert.h>
#include <crystal.h>

typedef struct ExtensionHolder ExtensionHolder;

static
int name_compare(const void *key1, size_t len1, const void *key2, size_t len2)
{
    assert(key1 && strlen(key1) == len1);
    assert(key2 && strlen(key2) == len2);

    return strcmp(key1, key2);
}

static inline
hashtable_t *extensions_create(int capacity)
{
    return hashtable_create(capacity, 1, NULL, name_compare);
}

static inline
int extensions_exist(hashtable_t *exts, const char *name)
{
    assert(exts);
    assert(name);

    return hashtable_exist(exts, name, strlen(name));
}

static inline
void extensions_put(hashtable_t *exts, ExtensionHolder *ext)
{
    assert(exts);
    assert(ext);
    assert(ext->name);

    ext->he.data = ext;
    ext->he.key = ext->name;
    ext->he.keylen = strlen(ext->name);

    hashtable_put(exts, &ext->he);
}

static inline
ExtensionHolder *extensions_get(hashtable_t *exts, const char *name)
{
    assert(exts);
    assert(name);

    return (ExtensionHolder *)hashtable_get(exts, name, strlen(name));
}

static inline
ExtensionHolder *extensions_remove(hashtable_t *exts, const char *name)
{
    assert(exts);
    assert(name);

    return hashtable_remove(exts, name, strlen(name));
}

static inline
void extensions_clear(hashtable_t *exts)
{
    assert(exts);
    hashtable_clear(exts);
}

static inline
hashtable_iterator_t *extensions_iterate(hashtable_t *exts,
                                         hashtable_iterator_t *iterator)
{
    assert(exts);
    assert(iterator);

    return hashtable_iterate(exts, iterator);
}

static inline
int extensions_iterator_next(hashtable_iterator_t *iterator, char **name,
                             ExtensionHolder **ext)
{
    assert(iterator);
    return hashtable_iterator_next(iterator, (void **)name, NULL, (void **)ext);
}

static inline
int extensions_iterator_has_next(hashtable_iterator_t *iterator)
{
    assert(iterator);
    return hashtable_iterator_has_next(iterator);
}

#endif /* __CARRIER_EXTENSIONS_H__ */
