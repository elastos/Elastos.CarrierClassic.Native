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

#include <stdlib.h>
#include <crystal.h>

#include "carrier.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "dht.h"
#include "dht_callbacks.h"

#include "express.h"
#include "carrier_extension.h"
#include "carrier_impl.h"

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
    list_entry_t le;
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

    list_t *friend_events; // for friend_added/removed.
    hashtable_t *friends;

    ExpressConnector *connector;
    uint32_t offmsgid;
    struct timeval express_expiretime;

    hashtable_t *tcallbacks;
    hashtable_t *thistory;

    hashtable_t *tassembly_ireqs;
    hashtable_t *tassembly_irsps;

    hashtable_t *bulkmsgs;
    hashtable_t *unconfirmed;

    hashtable_t *exts;
    pthread_t main_thread;

    int running;
    int quit;
};

typedef struct ExtensionHolder {
    char name[CARRIER_MAX_EXTENSION_NAME_LEN+1];
    CarrierCallbacks callbacks;
    ExtensionAPIs apis;
    CarrierExtension *ext;
    hash_entry_t he;
} ExtensionHolder;

CARRIER_API
int carrier_leave_all_groups(Carrier *w);


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
