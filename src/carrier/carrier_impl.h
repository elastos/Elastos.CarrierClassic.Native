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

#ifndef __CARRIER_IMPL_H__
#define __CARRIER_IMPL_H__

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include <crystal.h>
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "dht.h"
#include "dht_callbacks.h"

#include "carrier.h"
#include "express.h"
#include "carrier_extension.h"
#include "carrier_impl.h"
#include "managed_group_client.h"
#include "managed_group_server.h"

#define BOOTSTRAP_DEFAULT_PORT 33445

typedef struct DHT {
    uint8_t padding[32];  // reserved for DHT.
} DHT;

typedef struct BootstrapNodeBuf {
    char *ipv4;
    char *ipv6;
    uint16_t port;
    uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
} BootstrapNodeBuf;

typedef struct ExpressNodeBuf {
    char *ipv4;
    uint16_t port;
    uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
} ExpressNodeBuf;

typedef struct Preferences {
    char *data_location;
    bool udp_enabled;

    size_t bootstrap_size;
    BootstrapNodeBuf *bootstrap_nodes;

    size_t express_size;
    ExpressNodeBuf *express_nodes;
} Preferences;

typedef struct EventBase EventBase;
struct EventBase {
    void (*handle)(EventBase *, Carrier *);
    linked_list_entry_t le;
};

typedef struct FriendEvent {
    EventBase base;
    CarrierFriendInfo fi;
} FriendEvent;

typedef struct OfflineEvent {
    EventBase base;
    char from [CARRIER_MAX_ADDRESS_LEN + 1];
    int64_t timestamp;
    size_t length;
    uint8_t data[0];
} OfflineEvent;

typedef struct MsgidEvent {
    EventBase base;
    char friendid[CARRIER_MAX_ADDRESS_LEN + 1];
    uint32_t msgid;
    int errcode;
} MsgidEvent;

/*
typedef enum MsgCh {
    MSGCH_DHT = 1,
    MSGCH_EXPRESS = 2,
} MsgCh;
*/

struct Carrier {
    DHT dht;

    Preferences pref;

    uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
    uint8_t address[DHT_ADDRESS_SIZE];
    char base58_addr[CARRIER_MAX_ADDRESS_LEN + 1];

    CarrierUserInfo me;
    CarrierPresenceStatus presence_status;
    CarrierConnectionStatus connection_status;
    bool is_ready;

    CarrierCallbacks callbacks;
    CarrierGroupCallbacks group_callbacks;
    void *context;

    DHTCallbacks dht_callbacks;

    linked_list_t *friend_events; // for friend_added/removed.
    linked_hashtable_t *friends;

    ExpressConnector *connector;
    uint32_t offmsgid;
    struct timeval express_expiretime;

    linked_hashtable_t *tcallbacks;
    linked_hashtable_t *thistory;

    linked_hashtable_t *tassembly_ireqs;
    linked_hashtable_t *tassembly_irsps;

    linked_hashtable_t *bulkmsgs;
    linked_hashtable_t *unconfirmed;

    linked_hashtable_t *exts;
    pthread_t main_thread;

    ManagedGroupClient *mgrp_client;
    ManagedGroupServer *mgrp_server;

    int running;
    int quit;
};

typedef struct ExtensionHolder {
    char name[CARRIER_MAX_EXTENSION_NAME_LEN+1];
    CarrierCallbacks callbacks;
    ExtensionAPIs apis;
    CarrierExtension *ext;
    linked_hash_entry_t he;
} ExtensionHolder;

#define list_foreach(list, entry, task)                      \
    do {                                                     \
        linked_list_iterator_t __it;                         \
        void *__entry;                                       \
        if (!(list))                                         \
            break;                                           \
        for (linked_list_iterate((list), &__it);             \
             linked_list_iterator_next(&__it, &__entry) == 1;\
             deref(__entry)) {                               \
            (entry) = __entry;                               \
            task                                             \
        }                                                    \
    } while (0)

#define list_foreach_break \
    {                      \
        deref(__entry);    \
        break;             \
    }

#define list_foreach_goto(label) \
    {                            \
        deref(__entry);          \
        goto label;              \
    }

#define list_foreach_return \
    {                       \
        deref(__entry);     \
        return;             \
    }

#define list_foreach_return_val(val) \
    {                                \
        deref(__entry);              \
        return (val);                \
    }

#define list_foreach_remove_cur_entry() linked_list_iterator_remove(&__it)

#define hashtable_foreach(htab, entry, task)                                             \
    do {                                                                                 \
        linked_hashtable_iterator_t __it;                                                \
        void *__entry;                                                                   \
        if (!(htab))                                                                     \
            break;                                                                       \
        for (linked_hashtable_iterate((htab), &__it);                                    \
            linked_hashtable_iterator_next(&__it, NULL, NULL, (void **)&(__entry)) == 1; \
            deref(__entry)) {                                                            \
            (entry) = __entry;                                                           \
            task                                                                         \
        }                                                                                \
    } while (0)

#define hashtable_foreach_break \
    {                           \
        deref(__entry);         \
        break;                  \
    }

#define hashtable_foreach_goto(label) \
    {                                 \
        deref(__entry);               \
        goto label;                   \
    }

#define hashtable_foreach_return \
    {                            \
        deref(__entry);          \
        return;                  \
    }

#define hashtable_foreach_return_val(val) \
    {                                     \
        deref(__entry);                   \
        return (val);                     \
    }

#define hashtable_foreach_remove_cur_entry() linked_hashtable_iterator_remove(&__it)

CARRIER_API
int carrier_leave_all_groups(Carrier *w);

static int get_friend_number(Carrier *w, const char *friendid, uint32_t *friend_number)
{
    uint8_t pk[DHT_PUBLIC_KEY_SIZE];
    ssize_t len;
    int rc;

    assert(w);
    assert(friendid);
    assert(friend_number);

    len = base58_decode(friendid, strlen(friendid), pk, sizeof(pk));
    if (len != DHT_PUBLIC_KEY_SIZE) {
        vlogE("Carrier: friendid %s is not base58-encoded string", friendid);
        return CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS);
    }

    rc = dht_get_friend_number(&w->dht, pk, friend_number);
    if (rc < 0) {
        //vlogE("Carrier: friendid %s is not friend yet.", friendid);
        return CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST);
    }

    return rc;
}

static inline bool is_valid_key(const char *key)
{
    char result[DHT_PUBLIC_KEY_SIZE];
    ssize_t len;

    len = base58_decode(key, strlen(key), result, sizeof(result));
    return len == DHT_PUBLIC_KEY_SIZE;
}

static int mkdir_internal(const char *path, mode_t mode)
{
    struct stat st;
    int rc = 0;

    if (stat(path, &st) != 0) {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            rc = -1;
    } else if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        rc = -1;
    }

    return rc;
}

static int mkdirs(const char *path, mode_t mode)
{
    int rc = 0;
    char *pp;
    char *sp;
    char copypath[PATH_MAX];

    strncpy(copypath, path, sizeof(copypath));
    copypath[sizeof(copypath) - 1] = 0;

    pp = copypath;
    while (rc == 0 && (sp = strchr(pp, '/')) != 0) {
        if (sp != pp) {
            /* Neither root nor double slash in path */
            *sp = '\0';
            rc = mkdir_internal(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }

    if (rc == 0)
        rc = mkdir_internal(path, mode);

    return rc;
}

static inline
CarrierConnectionStatus connection_status(bool connected)
{
    return connected ? CarrierConnectionStatus_Connected :
                       CarrierConnectionStatus_Disconnected;
}

static inline
void gettimeofday_elapsed(struct timeval *tm, int elapsed)
{
    struct timeval interval;

    interval.tv_sec  = elapsed;
    interval.tv_usec = 0;

    gettimeofday(tm, NULL);
    timeradd(tm, &interval, tm);
}

#ifdef __cplusplus
}
#endif

#endif /* __CARRIER_IMPL_H__ */
