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

#ifndef __SESSION_H__
#define __SESSION_H__

#include <pthread.h>

#ifdef __APPLE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdocumentation"
#endif

#ifdef __APPLE__
#pragma GCC diagnostic pop
#endif

#include <crystal.h>

#include "carrier_extension.h"
#include "carrier_session.h"
#include "carrier_error.h"
#include "stream_handler.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_STREAM_ID       256

typedef void Timer;
typedef bool TimerCallback(void *user_data);

typedef struct SessionExtension     SessionExtension;
typedef struct TransportWorker      TransportWorker;
typedef struct CarrierTransport     CarrierTransport;
typedef struct CarrierSession       CarrierSession;
typedef struct CarrierStream        CarrierStream;

typedef struct IceTransportOptions {
    const char *stun_host;
    const char *stun_port;
    const char *turn_host;
    const char *turn_port;
    const char *turn_username;
    const char *turn_password;
    const char *turn_realm;
} IceTransportOptions;

struct BundledRequestCallback {
    linked_list_entry_t            le;
    CarrierSessionRequestCallback *callback;
    void                    *context;
    char                    prefix[1];
};

struct SessionExtension {
    CarrierExtension        base;

    CarrierSessionRequestCallback *default_callback;
    void                    *default_context;

    pthread_rwlock_t        callbacks_lock;
    linked_list_t                  *callbacks;

    CarrierTransport        *transport;

    IDS_HEAP(stream_ids, MAX_STREAM_ID);

    int (*create_transport)(CarrierTransport **transport);
};

struct CarrierTransport {
    SessionExtension        *ext;
    linked_list_t                  *workers;

    int (*create_worker)   (CarrierTransport *transport, IceTransportOptions *opts,
                            TransportWorker **worker);
    int (*create_session)  (CarrierTransport *transport, CarrierSession **session);
};

struct TransportWorker {
    int                     id;

    linked_list_entry_t            le;

    void (*stop)           (TransportWorker *worker);
    int  (*create_timer)   (TransportWorker *worker, int id, unsigned long interval,
                            TimerCallback *callback, void *user_data, Timer **timer);
    void (*schedule_timer) (TransportWorker *worker, Timer *timer,
                            unsigned long next);
    void (*destroy_timer)  (TransportWorker *worker, Timer *timer);
};

typedef struct CarrierSession {
    CarrierTransport        *transport;
    char                    *to;

    TransportWorker         *worker;

    int                     offerer;

    CarrierSessionRequestCompleteCallback *complete_callback;
    void                    *context;

    void                    *userdata;
    linked_list_t                  *streams;

    uint8_t                 public_key[PUBLIC_KEY_BYTES];
    uint8_t                 secret_key[SECRET_KEY_BYTES];

    uint8_t                 peer_pubkey[PUBLIC_KEY_BYTES];

    uint8_t                 nonce[NONCE_BYTES];
    uint8_t                 credential[NONCE_BYTES];

    struct {
        int enabled;
        uint8_t key[SYMMETRIC_KEY_BYTES];
    }  crypto;

    struct {
        int enabled;
        linked_hashtable_t *services;
    } portforwarding;

    int  (*init)            (CarrierSession *session);
    int  (*create_stream)   (CarrierSession *session, CarrierStream **stream);
    bool (*set_offer)       (CarrierSession *session, bool offerer);
    int  (*encode_local_sdp)(CarrierSession *session, char *sdp, size_t len);
    int  (*apply_remote_sdp)(CarrierSession *session, const char *sdp, size_t sdp_len);
} CarrierSession;

typedef struct Multiplexer  Multiplexer;

struct CarrierStream {
    StreamHandler           pipeline;
    Multiplexer             *mux;

    linked_list_entry_t            le;
    int                     id;
    CarrierSession          *session;
    CarrierStreamType       type;
    CarrierStreamState      state;

    int                     compress;
    int                     unencrypt;
    int                     reliable;
    int                     multiplexing;
    int                     portforwarding;
    int                     deactivate;

    CarrierStreamCallbacks  callbacks;
    void *context;

    int  (*get_info)        (CarrierStream *stream, CarrierTransportInfo *info);
    void (*fire_state_changed)(CarrierStream *stream, int state);
    void (*lock)            (CarrierStream *stream);
    void (*unlock)          (CarrierStream *stream);
};

void transport_base_destroy(void *p);

void session_base_destroy(void *p);

void stream_base_destroy(void *p);

static inline
SessionExtension *stream_get_extension(CarrierStream *stream)
{
    return stream->session->transport->ext;
}

static inline
CarrierTransport *stream_get_transport(CarrierStream *stream)
{
    return stream->session->transport;
}

static inline
TransportWorker *stream_get_worker(CarrierStream *stream)
{
    return stream->session->worker;
}

static inline
CarrierSession *stream_get_session(CarrierStream *stream)
{
    return stream->session;
}

static inline
bool stream_is_reliable(CarrierStream *stream)
{
    return stream->reliable != 0;
}

static inline
SessionExtension *session_get_extension(CarrierSession *session)
{
    return session->transport->ext;
}

static inline
CarrierTransport *session_get_transport(CarrierSession *session)
{
    return session->transport;
}

static inline
TransportWorker *session_get_worker(CarrierSession *session)
{
    return session->worker;
}

CARRIER_API
int carrier_session_register_strerror();

#ifdef __cplusplus
}
#endif

#endif /* __SESSION_H__ */
