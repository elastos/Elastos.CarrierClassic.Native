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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <crystal.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <ela_carrier.h>
#include <cjson/cJSON.h>
#include <crystal.h>

#include "jsonrpc.h"
#include "carrier_transport.h"
#include "error_code.h"
#include "db.h"
#include "carrier_config.h"
#include "config.h"
#include "mkdirs.h"

typedef struct {
    hash_entry_t he;
    char node_id[ELA_MAX_ID_LEN + 1];
} Publisher;

typedef struct {
    hash_entry_t he;
    hashtable_t *active_subscribers;
    uint64_t id;
    uint64_t next_seqno;
    Publisher *publisher;
    char *name;
    char *desc;
    char buf[0];
} Topic;

typedef struct {
    hash_entry_t he;
    char node_id[ELA_MAX_ID_LEN + 1];
    size_t users;
} Subscriber;

typedef struct {
    hash_entry_t he;
    Subscriber *s;
} SubscriberEntry;

#define TOPIC_SEQNO_START (1)
#define TOPIC_ID_START (1)

#define hashtable_foreach(htab, entry) \
    for (hashtable_iterate((htab), &it); \
         hashtable_iterator_next(&it, NULL, NULL, (void **)&(entry)); \
         deref((entry)))

static uint64_t next_topic_id = TOPIC_ID_START;
static hashtable_t *active_subscribers;
static hashtable_t *publishers;
static hashtable_t *topics;
static ElaCarrier *carrier;
static CarrierTransport *ct;
static cJSON *null_json;
static bool stop;

static
int send_notification(const char *to, const char *method, const cJSON *params)
{
    char *notification;
    int rc;

    notification = jsonrpc_encode_notification(method, params);
    if (!notification)
        return -1;

    rc = carrier_transport_send_message(ct, to, notification, strlen(notification) + 1);
    free(notification);
    return rc;
}

static
int send_error_response(const char *to, int code, const char *msg,
                        const cJSON *data, const cJSON *id)
{
    char *resp;
    int rc;

    resp = jsonrpc_encode_error_response(code, msg, data, id);
    if (!resp)
        return -1;

    rc = carrier_transport_send_message(ct, to, resp, strlen(resp) + 1);
    free(resp);
    return rc;
}

static
int send_success_response(const char *to, const cJSON *result, const cJSON *id)
{
    char *resp;
    int rc;

    resp = jsonrpc_encode_success_response(result, id);
    if (!resp)
        return -1;

    rc = carrier_transport_send_message(ct, to, resp, strlen(resp) + 1);
    free(resp);
    return rc;
}

static
void notify_of_new_message(const Subscriber *s, const char *topic,
                           const char *event, uint64_t seqno, uint64_t ts)
{
    cJSON *result;

    result = cJSON_CreateObject();
    if (!result)
        return;

    if (!cJSON_AddStringToObject(result, "topic", topic)) {
        cJSON_Delete(result);
        return;
    }

    if (!cJSON_AddStringToObject(result, "event", event)) {
        cJSON_Delete(result);
        return;
    }

    if (!cJSON_AddNumberToObject(result, "seqno", seqno)) {
        cJSON_Delete(result);
        return;
    }

    if (!cJSON_AddNumberToObject(result, "ts", ts)) {
        cJSON_Delete(result);
        return;
    }

    send_notification(s->node_id, "new_event", result);
    cJSON_Delete(result);
}

static
Publisher *publisher_create(const char *node_id)
{
    Publisher *p;

    p = rc_zalloc(sizeof(Publisher), NULL);
    if (!p)
        return NULL;

    strcpy(p->node_id, node_id);

    p->he.data = p;
    p->he.key = p->node_id;
    p->he.keylen = strlen(p->node_id);

    return p;
}

static
void topic_destructor(void *obj)
{
    Topic *t = (Topic *)obj;

    if (t->active_subscribers) {
        hashtable_clear(t->active_subscribers);
        deref(t->active_subscribers);
    }

    deref(t->publisher);
}

static
Topic *topic_create(uint64_t id, const char *name, const char *desc,
                    uint64_t next_seqno, Publisher *p)
{
    Topic *t;

    t = rc_zalloc(sizeof(Topic) + strlen(name) + strlen(desc) + 2, topic_destructor);
    if (!t)
        return NULL;

    t->active_subscribers = hashtable_create(8, 0, NULL, NULL);
    if (!t->active_subscribers) {
        deref(t);
        return NULL;
    }

    t->id = id;
    t->next_seqno = next_seqno;
    t->publisher = ref(p);

    strcpy(t->buf, name);
    t->name = t->buf;

    strcpy(t->buf + strlen(t->buf) + 1, desc);
    t->desc = t->buf + strlen(t->buf) + 1;

    t->he.data = t;
    t->he.key = t->name;
    t->he.keylen = strlen(t->name);

    return t;
}

static
Subscriber *subscriber_create(const char *node_id)
{
    Subscriber *s;

    s = rc_zalloc(sizeof(Subscriber), NULL);
    if (!s)
        return NULL;

    strcpy(s->node_id, node_id);

    s->he.data = s;
    s->he.key = s->node_id;
    s->he.keylen = strlen(s->node_id);

    return s;
}

static
void subscriber_entry_destructor(void *obj)
{
    SubscriberEntry *se = (SubscriberEntry *)obj;
    Subscriber *s = se->s;

    if (s && !--s->users)
        deref(hashtable_remove(active_subscribers, se->s->node_id, strlen(se->s->node_id)));

    deref(se->s);
}

static
SubscriberEntry *subscriber_entry_create(const char *node_id)
{
    SubscriberEntry *se;
    Subscriber *s;

    se = rc_zalloc(sizeof(SubscriberEntry), subscriber_entry_destructor);
    if (!se)
        return NULL;

    s = hashtable_get(active_subscribers, node_id, strlen(node_id));
    if (!s) {
        s = subscriber_create(node_id);
        if (!s) {
            deref(se);
            return NULL;
        }
        hashtable_put(active_subscribers, &s->he);
    }

    se->s = s;
    ++s->users;

    se->he.data = se;
    se->he.key = s->node_id;
    se->he.keylen = strlen(s->node_id);

    return se;
}

static
void handle_create_topic_request(const char *from, const cJSON *req)
{
    const cJSON *params;
    const cJSON *topic;
    const cJSON *desc;
    Publisher *p = NULL;
    Topic *t = NULL;
    int rc;

    params = jsonrpc_get_params(req);
    if (!params || !cJSON_IsObject(params) ||
        !(topic = cJSON_GetObjectItemCaseSensitive(params, "topic")) ||
        !cJSON_IsString(topic) || !topic->valuestring[0] ||
        !(desc = cJSON_GetObjectItemCaseSensitive(params, "desc")) ||
        !cJSON_IsString(desc) || !desc->valuestring[0]) {
        rc = JSONRPC_EINVALID_PARAMS;
        send_error_response(from, rc, jsonrpc_error_message(rc), NULL,
                            jsonrpc_get_id(req));
        goto finally;
    }

    p = hashtable_get(publishers, from, strlen(from));
    if (!p) {
        send_error_response(from, JSONRPC_EINVALID_PARAMS,
                            error_code_strerror(FEEDS_ENOT_AUTHORIZED),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    if (hashtable_exist(topics, topic->valuestring, strlen(topic->valuestring))) {
        send_error_response(from, JSONRPC_EINVALID_PARAMS,
                            error_code_strerror(FEEDS_EALREADY_EXISTS),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    t = topic_create(next_topic_id++, topic->valuestring,
                     desc->valuestring, TOPIC_SEQNO_START, p);
    if (!t) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    rc = db_add_topic(topic->valuestring, p->node_id, desc->valuestring);
    if (rc < 0) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    hashtable_put(topics, &t->he);

    send_success_response(from, null_json, jsonrpc_get_id(req));

finally:
    deref(t);
    deref(p);
}

static
void handle_post_event_request(const char *from, const cJSON *req)
{
    const cJSON *params;
    const cJSON *topic;
    const cJSON *event;
    uint64_t seqno;
    hashtable_iterator_t it;
    SubscriberEntry *se;
    Topic *t = NULL;
    int rc;
    time_t now;

    params = jsonrpc_get_params(req);
    if (!params || !cJSON_IsObject(params) ||
        !(topic = cJSON_GetObjectItemCaseSensitive(params, "topic")) ||
        !(event = cJSON_GetObjectItemCaseSensitive(params, "event")) ||
        !cJSON_IsString(topic) || !topic->valuestring[0] ||
        !cJSON_IsString(event) || !event->valuestring[0]) {
        rc = JSONRPC_EINVALID_PARAMS;
        send_error_response(from, rc, jsonrpc_error_message(rc), NULL,
                            jsonrpc_get_id(req));
        goto finally;
    }

    t = hashtable_get(topics, topic->valuestring, strlen(topic->valuestring));
    if (!t) {
        send_error_response(from, JSONRPC_EINVALID_PARAMS,
                            error_code_strerror(FEEDS_ENOT_EXISTS),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    if (!t->publisher || strcmp(t->publisher->node_id, from)) {
        send_error_response(from, JSONRPC_EINVALID_PARAMS,
                            error_code_strerror(FEEDS_ENOT_AUTHORIZED),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    seqno = t->next_seqno++;
    rc = db_add_event(t->id, seqno, event->valuestring,
                      strlen(event->valuestring) + 1, now = time(NULL));
    if (rc < 0) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    send_success_response(from, null_json, jsonrpc_get_id(req));

    hashtable_foreach(t->active_subscribers, se)
        notify_of_new_message(se->s, topic->valuestring, event->valuestring, seqno, now);

finally:
    deref(t);
}

static
void handle_list_owned_topics_request(const char *from, const cJSON *req)
{
    cJSON *result;
    int rc;

    rc = db_list_owned_topics(from, &result);
    if (rc < 0) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        return;
    }

    send_success_response(from, result, jsonrpc_get_id(req));

    cJSON_Delete(result);
}

static
void handle_subscribe_request(const char *from, const cJSON *req)
{
    Topic *t;
    const cJSON *params;
    const cJSON *topic;
    int rc;

    params = jsonrpc_get_params(req);
    if (!params || !cJSON_IsObject(params) ||
        !(topic = cJSON_GetObjectItemCaseSensitive(params, "topic")) ||
        !cJSON_IsString(topic) || !topic->valuestring[0]) {
        rc = JSONRPC_EINVALID_PARAMS;
        send_error_response(from, rc, jsonrpc_error_message(rc), NULL,
                            jsonrpc_get_id(req));
        return;
    }

    t = hashtable_get(topics, topic->valuestring, strlen(topic->valuestring));
    if (!t) {
        send_error_response(from, JSONRPC_EINVALID_PARAMS,
                            error_code_strerror(FEEDS_ENOT_EXISTS),
                            NULL, jsonrpc_get_id(req));
        return;
    }

    rc = db_add_subscriber(t->id, from);
    deref(t);
    if (rc < 0) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        return;
    }

    send_success_response(from, null_json, jsonrpc_get_id(req));
}

static
void handle_unsubscribe_request(const char *from, const cJSON *req)
{
    const cJSON *params;
    const cJSON *topic;
    Topic *t;
    int rc;

    params = jsonrpc_get_params(req);
    if (!params || !cJSON_IsObject(params) ||
        !(topic = cJSON_GetObjectItemCaseSensitive(params, "topic")) ||
        !cJSON_IsString(topic) || !topic->valuestring[0]) {
        rc = JSONRPC_EINVALID_PARAMS;
        send_error_response(from, rc, jsonrpc_error_message(rc), NULL,
                            jsonrpc_get_id(req));
        return;
    }

    t = hashtable_get(topics, topic->valuestring, strlen(topic->valuestring));
    if (!t) {
        send_error_response(from, JSONRPC_EINVALID_PARAMS,
                            error_code_strerror(FEEDS_ENOT_EXISTS),
                            NULL, jsonrpc_get_id(req));
        return;
    }

    rc = db_unsubscribe(t->id, from);
    if (rc < 0) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        deref(t);
        return;
    }

    deref(hashtable_remove(t->active_subscribers, from, strlen(from)));
    deref(t);

    send_success_response(from, null_json, jsonrpc_get_id(req));
}

static
void handle_explore_topics_request(const char *from, const cJSON *req)
{
    hashtable_iterator_t it;
    cJSON *result;
    Topic *t;
    int rc;

    result = cJSON_CreateArray();
    if (!result) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        return;
    }

    hashtable_foreach(topics, t) {
        cJSON *topic;

        topic = cJSON_CreateObject();
        if (!topic)
            goto failure;
        cJSON_AddItemToArray(result, topic);

        if (!cJSON_AddStringToObject(topic, "name", t->name))
            goto failure;

        if (!cJSON_AddStringToObject(topic, "desc", t->desc))
            goto failure;
    }

    send_success_response(from, result, jsonrpc_get_id(req));
    cJSON_Delete(result);
    return;

failure:
    rc = JSONRPC_EINTERNAL_ERROR;
    send_error_response(from, rc, jsonrpc_error_message(rc),
                        NULL, jsonrpc_get_id(req));
    cJSON_Delete(result);
}

static
void handle_list_subscribed_topics_request(const char *from, const cJSON *req)
{
    cJSON *result;
    int rc;

    rc = db_list_subscribed_topics(from, &result);
    if (rc < 0) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        return;
    }

    send_success_response(from, result, jsonrpc_get_id(req));
    cJSON_Delete(result);
}

static
void handle_fetch_unreceived_request(const char *from, const cJSON *req)
{
    const cJSON *params;
    const cJSON *topic;
    const cJSON *since;
    cJSON *result;
    Topic *t = NULL;
    SubscriberEntry *se = NULL;
    int rc;

    params = jsonrpc_get_params(req);
    if (!params || !cJSON_IsObject(params) ||
        !(topic = cJSON_GetObjectItemCaseSensitive(params, "topic")) ||
        !(since = cJSON_GetObjectItemCaseSensitive(params, "since")) ||
        !cJSON_IsString(topic) || !topic->valuestring[0] || !cJSON_IsNumber(since)) {
        rc = JSONRPC_EINVALID_PARAMS;
        send_error_response(from, rc, jsonrpc_error_message(rc), NULL,
                            jsonrpc_get_id(req));
        goto finally;
    }

    t = hashtable_get(topics, topic->valuestring, strlen(topic->valuestring));
    if (!t) {
        send_error_response(from, JSONRPC_EINVALID_PARAMS,
                            error_code_strerror(FEEDS_ENOT_EXISTS),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    if (hashtable_exist(t->active_subscribers, from, strlen(from))) {
        send_error_response(from, JSONRPC_EINVALID_PARAMS,
                            error_code_strerror(FEEDS_EWRONG_STATE),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    if (!db_is_subscriber(t->id, from)) {
        send_error_response(from, JSONRPC_EINVALID_PARAMS,
                            error_code_strerror(FEEDS_EWRONG_STATE),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    se = subscriber_entry_create(from);
    if (!se) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    rc = db_fetch_events(t->id, since->valuedouble, &result);
    if (rc < 0) {
        rc = JSONRPC_EINTERNAL_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, jsonrpc_get_id(req));
        goto finally;
    }

    hashtable_put(t->active_subscribers, &se->he);

    send_success_response(from, result, jsonrpc_get_id(req));

    cJSON_Delete(result);

finally:
    deref(t);
    deref(se);
}

typedef void MethodHandler(const char *from, const cJSON *req);
static struct {
    char *name;
    MethodHandler *handler;
} method_handlers[] = {
    {"create_topic"          , handle_create_topic_request          },
    {"post_event"            , handle_post_event_request            },
    {"list_owned_topics"     , handle_list_owned_topics_request     },
    {"subscribe"             , handle_subscribe_request             },
    {"unsubscribe"           , handle_unsubscribe_request           },
    {"explore_topics"        , handle_explore_topics_request        },
    {"list_subscribed_topics", handle_list_subscribed_topics_request},
    {"fetch_unreceived"      , handle_fetch_unreceived_request      }
};

static
MethodHandler *get_method_handler(const char *method)
{
    int i;

    for (i = 0; i < sizeof(method_handlers) / sizeof(method_handlers[0]); ++i) {
        if (!strcmp(method, method_handlers[i].name))
            return method_handlers[i].handler;
    }

    return NULL;
}

static
void on_receiving_request(CarrierTransport *ct, const char *from,
                          const void *data, size_t len, void *context)
{
    int rc;
    cJSON *req;
    MethodHandler *handler;
    JsonRPCType type;

    rc = jsonrpc_decode(data, len, &req, &type);
    if (rc < 0) {
        rc = JSONRPC_EPARSE_ERROR;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, NULL);
        return;
    }

    if (type != JSONRPC_TYPE_REQUEST) {
        cJSON_Delete(req);
        return;
    }

    handler = get_method_handler(jsonrpc_get_method(req));
    if (!handler) {
        rc = JSONRPC_EMETHOD_NOT_FOUND;
        send_error_response(from, rc, jsonrpc_error_message(rc),
                            NULL, NULL);
        cJSON_Delete(req);
        return;
    }

    handler(from, req);
    cJSON_Delete(req);
}

static
int load_topic_from_db(uint64_t id, const char *name, const char *desc,
                       uint64_t next_seqno, const char *publisher)
{
    Publisher *p;
    Topic *t;

    p = hashtable_get(publishers, publisher, strlen(publisher));

    t = topic_create(id, name, desc, next_seqno, p);
    deref(p);
    if (!t)
        return -1;

    hashtable_put(topics, &t->he);
    deref(t);

    if (id >= next_topic_id)
        next_topic_id = id + 1;

    return 0;
}

static
void feeds_finalize()
{
    if (publishers) {
        hashtable_clear(publishers);
        deref(publishers);
    }

    if (topics) {
        hashtable_clear(topics);
        deref(topics);
    }

    if (active_subscribers) {
        hashtable_clear(active_subscribers);
        deref(active_subscribers);
    }

    if (null_json)
        cJSON_Delete(null_json);

    if (carrier)
        ela_kill(carrier);
}

static
void idle_callback(ElaCarrier *c, void *context)
{
    if (stop) {
        ela_kill(carrier);
        carrier = NULL;
    }
}

static
void friend_connection_callback(ElaCarrier *c, const char *friend_id,
                                ElaConnectionStatus status, void *context)
{
    hashtable_iterator_t it;
    Topic *t;

    if (status == ElaConnectionStatus_Connected)
        return;

    hashtable_foreach(topics, t)
        deref(hashtable_remove(t->active_subscribers, friend_id, strlen(friend_id)));

    carrier_transport_friend_disconnected(ct, friend_id);
}

static
void friend_request_callback(ElaCarrier *c, const char *user_id,
                             const ElaUserInfo *info, const char *hello,
                             void *context)
{
    ela_accept_friend(c, user_id);
}

static
void message_callback(ElaCarrier *c, const char *from,
                      const void *msg, size_t len, bool is_offline, void *context)
{
    carrier_transport_message_received(ct, from, msg, len);
}

static
int feeds_initialize(FeedsConfig *cfg)
{
    ElaCallbacks callbacks;
    char fpath[PATH_MAX];
    char addr[ELA_MAX_ADDRESS_LEN + 1];
    int rc;
    int i;
    int fd;

    publishers = hashtable_create(8, 0, NULL, NULL);
    if (!publishers)
        return -1;

    topics = hashtable_create(8, 0, NULL, NULL);
    if (!topics)
        goto failure;

    active_subscribers = hashtable_create(8, 0, NULL, NULL);
    if (!active_subscribers)
        goto failure;

    for (i = 0; i < cfg->publishers_cnt; ++i) {
        Publisher *p;

        p = publisher_create(cfg->publishers[i]);
        if (!p)
            goto failure;

        hashtable_put(publishers, &p->he);
        deref(p);
    }

    rc = db_iterate_topics(load_topic_from_db);
    if (rc < 0)
        goto failure;

    null_json = cJSON_CreateNull();
    if (!null_json)
        goto failure;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.idle = idle_callback;
    callbacks.friend_connection = friend_connection_callback;
    callbacks.friend_request = friend_request_callback;
    callbacks.friend_message = message_callback;

    carrier = ela_new(&cfg->ela_options, &callbacks, NULL);
    if (!carrier)
        goto failure;

    sprintf(fpath, "%s/address.txt", cfg->ela_options.persistent_location);
    fd = open(fpath, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0)
        goto failure;

    ela_get_address(carrier, addr, sizeof(addr));
    rc = write(fd, addr, strlen(addr));
    close(fd);
    if (rc < 0)
        goto failure;

    return 0;

failure:
    feeds_finalize();
    return -1;
}

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>

static
int sys_coredump_set(bool enable)
{
    const struct rlimit rlim = {
        enable ? RLIM_INFINITY : 0,
        enable ? RLIM_INFINITY : 0
    };

    return setrlimit(RLIMIT_CORE, &rlim);
}
#endif

static
void usage(void)
{
    printf("Elastos feeds server.\n");
    printf("Usage: elafeeds [OPTION]...\n");
    printf("\n");
    printf("First run options:\n");
    printf("  -d, --daemon              Run as daemon.\n");
    printf("  -c, --config=CONFIG_FILE  Set config file path.\n");
    printf("      --udp-enabled=0|1     Enable UDP, override the option in config.\n");
    printf("      --log-level=LEVEL     Log level(0-7), override the option in config.\n");
    printf("      --log-file=FILE       Log file name, override the option in config.\n");
    printf("      --data-dir=PATH       Data location, override the option in config.\n");
    printf("\n");
    printf("Debugging options:\n");
    printf("      --debug               Wait for debugger attach after start.\n");
    printf("\n");
}

#define CONFIG_NAME "feeds.conf"
static const char *default_config_files[] = {
    "./"CONFIG_NAME,
    "../etc/carrier/"CONFIG_NAME,
    "/usr/local/etc/carrier/"CONFIG_NAME,
    "/etc/carrier/"CONFIG_NAME,
    NULL
};

static
void shutdown_process(int signum)
{
    stop = true;
}

static
int daemonize()
{
    pid_t pid;
    struct sigaction sa;

    /*
     * Clear file creation mask.
     */
    umask(0);

    /*
     * Become a session leader to lose controlling TTY.
     */
    if ((pid = fork()) < 0)
        return -1;
    else if (pid != 0) /* parent */
        exit(0);
    setsid();

    /*
     * Ensure future opens won’t allocate controlling TTYs.
     */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
        return -1;
    if ((pid = fork()) < 0)
        return -1;
    else if (pid != 0) /* parent */
        exit(0);

    /*
     * Change the current working directory to the root so
     * we won’t prevent file systems from being unmounted.
     */
    if (chdir("/") < 0)
        return -1;

    /* Attach file descriptors 0, 1, and 2 to /dev/null. */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);

    return 0;
}

int main(int argc, char *argv[])
{
    char buf[ELA_MAX_ADDRESS_LEN + 1];
    const char *config_file = NULL;
    int wait_for_attach = 0;
    char db_file[PATH_MAX];
    FeedsConfig cfg;
    int daemon = 0;
    int rc;

    int opt;
    int idx;
    struct option options[] = {
        { "daemon",      no_argument,        NULL, 'd' },
        { "config",      required_argument,  NULL, 'c' },
        { "udp-enabled", required_argument,  NULL, 1 },
        { "log-level",   required_argument,  NULL, 2 },
        { "log-file",    required_argument,  NULL, 3 },
        { "data-dir",    required_argument,  NULL, 4 },
        { "debug",       no_argument,        NULL, 5 },
        { "help",        no_argument,        NULL, 'h' },
        { NULL,          0,                  NULL, 0 }
    };

#ifdef HAVE_SYS_RESOURCE_H
    sys_coredump_set(true);
#endif

    while ((opt = getopt_long(argc, argv, "dc:h?", options, &idx)) != -1) {
        switch (opt) {
        case 'd':
            daemon = 1;
            break;

        case 'c':
            config_file = optarg;
            break;

        case 1:
        case 2:
        case 3:
        case 4:
            break;

        case 5:
            wait_for_attach = 1;
            break;

        case 'h':
        case '?':
        default:
            usage();
            exit(-1);
        }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    if (wait_for_attach) {
        printf("Wait for debugger attaching, process id is: %d.\n", getpid());
        printf("After debugger attached, press any key to continue......");
        getchar();
    }

    config_file = get_config_file(config_file, default_config_files);
    if (!config_file) {
        fprintf(stderr, "Error: Missing config file.\n");
        usage();
        return -1;
    }

    memset(&cfg, 0, sizeof(cfg));
    if (!load_config(config_file, &cfg)) {
        fprintf(stderr, "loading configure failed!\n");
        return -1;
    }

    carrier_config_update(&cfg.ela_options, argc, argv);

    rc = mkdirs(cfg.ela_options.persistent_location, S_IRWXU);
    if (rc < 0) {
        free_config(&cfg);
        return -1;
    }

    sprintf(db_file, "%s/feeds.sqlite3", cfg.ela_options.persistent_location);
    rc = db_initialize(db_file);
    if (rc < 0) {
        free_config(&cfg);
        return -1;
    }

    rc = feeds_initialize(&cfg);
    free_config(&cfg);
    if (rc < 0) {
        db_finalize();
        return -1;
    }

    ct = carrier_transport_create(carrier, on_receiving_request, NULL);
    if (rc < 0) {
        feeds_finalize();
        db_finalize();
        return -1;
    }

    signal(SIGINT, shutdown_process);
    signal(SIGTERM, shutdown_process);
    signal(SIGSEGV, shutdown_process);

    printf("Carrier node identities:\n");
    printf("   Node ID: %s\n", ela_get_nodeid(carrier, buf, sizeof(buf)));
    printf("   User ID: %s\n", ela_get_userid(carrier, buf, sizeof(buf)));
    printf("   Address: %s\n", ela_get_address(carrier, buf, sizeof(buf)));

    if (daemon && daemonize() < 0) {
        fprintf(stderr, "daemonize failure!\n");
        free_config(&cfg);
        return -1;
    }

    rc = ela_run(carrier, 10);

    feeds_finalize();
    carrier_transport_delete(ct);
    db_finalize();

    return rc;
}