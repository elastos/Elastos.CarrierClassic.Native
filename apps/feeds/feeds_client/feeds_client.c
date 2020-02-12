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

#include <string.h>
#include <pthread.h>
#include <crystal.h>

#include "feeds_client.h"
#include "../carrier_transport.h"
#include "../jsonrpc.h"

struct FeedsClient {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    ElaCarrier *carrier;
    CarrierTransport *ct;
    cJSON *null_json;
    cJSON *new_events;
    cJSON *response;
    JsonRPCType response_type;
    bool waiting_response;
    pthread_t carrier_routine_tid;
};

static
void connection_callback(ElaCarrier *w, ElaConnectionStatus status, void *context)
{
    FeedsClient *fc = (FeedsClient *)context;

    pthread_mutex_lock(&fc->lock);
    pthread_mutex_unlock(&fc->lock);
    pthread_cond_signal(&fc->cond);
}

static
void friend_connection_callback(ElaCarrier *w, const char *friendid,
                                ElaConnectionStatus status, void *context)
{
    FeedsClient *fc = (FeedsClient *)context;

    pthread_mutex_lock(&fc->lock);
    pthread_mutex_unlock(&fc->lock);
    pthread_cond_signal(&fc->cond);

    if (status == ElaConnectionStatus_Disconnected)
        carrier_transport_friend_disconnected(fc->ct, friendid);
}

static
void message_callback(ElaCarrier *w, const char *from,
                      const void *msg, size_t len, bool is_offline, void *context)
{
    FeedsClient *fc = (FeedsClient *)context;

    carrier_transport_message_received(fc->ct, from, msg, len);
}

static
void on_receiving_response(CarrierTransport *ct, const char *from,
                           const void *data, size_t len, void *context)
{
    FeedsClient *fc = (FeedsClient *)context;
    JsonRPCType type;
    cJSON *json;
    int rc;

    rc = jsonrpc_decode(data, len, &json, &type);
    if (rc < 0 || type == JSONRPC_TYPE_REQUEST)
        return;

    if (type == JSONRPC_TYPE_NOTIFICATION) {
        cJSON *params;
        cJSON *topic;
        cJSON *event;
        cJSON *seqno;
        cJSON *ts;

        if (strcmp(jsonrpc_get_method(json), "new_event")) {
            cJSON_Delete(json);
            return;
        }

        if (!(params = (cJSON *)jsonrpc_get_params(json)) ||
            !(topic = cJSON_GetObjectItemCaseSensitive(params, "topic")) ||
            !(event = cJSON_GetObjectItemCaseSensitive(params, "event")) ||
            !(seqno = cJSON_GetObjectItemCaseSensitive(params, "seqno")) ||
            !(ts = cJSON_GetObjectItemCaseSensitive(params, "ts")) ||
            !cJSON_IsString(topic) || !topic->valuestring[0] ||
            !cJSON_IsString(event) || !event->valuestring[0] ||
            !cJSON_IsNumber(seqno) || !cJSON_IsNumber(ts)) {
            cJSON_Delete(json);
            return;
        }

        cJSON_DetachItemViaPointer(json, params);

        pthread_mutex_lock(&fc->lock);
        cJSON_AddItemToArray(fc->new_events, params);
        pthread_mutex_unlock(&fc->lock);

        cJSON_Delete(json);

        return;
    }

    pthread_mutex_lock(&fc->lock);

    if (fc->waiting_response) {
        fc->response = json;
        fc->response_type = type;
        pthread_cond_signal(&fc->cond);
    } else
        cJSON_Delete(json);

    pthread_mutex_unlock(&fc->lock);
}

static
void *carrier_routine(void *arg)
{
    ela_run((ElaCarrier *)arg, 10);
    return NULL;
}

static
void feeds_client_destructor(void *obj)
{
    FeedsClient *fc = (FeedsClient *)obj;

    pthread_mutex_destroy(&fc->lock);
    pthread_cond_destroy(&fc->cond);

    if (fc->carrier)
        ela_kill(fc->carrier);

    if (fc->ct)
        carrier_transport_delete(fc->ct);

    if (fc->null_json)
        cJSON_Delete(fc->null_json);

    if (fc->new_events)
        cJSON_Delete(fc->new_events);

    if (fc->response)
        cJSON_Delete(fc->response);
}

FeedsClient *feeds_client_create(ElaOptions *opts)
{
    ElaCallbacks callbacks;
    FeedsClient *fc;
    int rc;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.connection_status = connection_callback;
    callbacks.friend_connection = friend_connection_callback;
    callbacks.friend_message = message_callback;

    fc = rc_zalloc(sizeof(FeedsClient), feeds_client_destructor);
    if (!fc)
        return NULL;

    pthread_mutex_init(&fc->lock, NULL);
    pthread_cond_init(&fc->cond, NULL);

    fc->carrier = ela_new(opts, &callbacks, fc);
    if (!fc->carrier) {
        deref(fc);
        return NULL;
    }

    fc->ct = carrier_transport_create(fc->carrier, on_receiving_response, fc);
    if (!fc->ct) {
        deref(fc);
        return NULL;
    }

    fc->null_json = cJSON_CreateNull();
    if (!fc->null_json) {
        deref(fc);
        return NULL;
    }

    fc->new_events = cJSON_CreateArray();
    if (!fc->new_events) {
        deref(fc);
        return NULL;
    }

    rc = pthread_create(&fc->carrier_routine_tid, NULL, carrier_routine, fc->carrier);
    if (rc < 0) {
        deref(fc);
        return NULL;
    }

    return fc;
}

void feeds_client_wait_until_online(FeedsClient *fc)
{
    pthread_mutex_lock(&fc->lock);
    while (!ela_is_ready(fc->carrier))
        pthread_cond_wait(&fc->cond, &fc->lock);
    pthread_mutex_unlock(&fc->lock);
}

void feeds_client_delete(FeedsClient *fc)
{
    pthread_t tid = fc->carrier_routine_tid;

    deref(fc);
    pthread_join(tid, NULL);
}

ElaCarrier *feeds_client_get_carrier(FeedsClient *fc)
{
    return fc->carrier;
}

int feeds_client_friend_add(FeedsClient *fc, const char *address, const char *hello)
{
    char node_id[ELA_MAX_ID_LEN + 1];
    int rc = 0;

    ela_get_id_by_address(address, node_id, sizeof(node_id));
    if (!ela_is_friend(fc->carrier, node_id)) {
        rc = ela_add_friend(fc->carrier, address, hello);
        if (rc < 0)
            return -1;
    }

    feeds_client_wait_until_friend_connected(fc, node_id);

    return rc;
}

int feeds_client_wait_until_friend_connected(FeedsClient *fc, const char *friend_node_id)
{
    ElaFriendInfo info;
    int rc;

    pthread_mutex_lock(&fc->lock);
    while (1) {
        rc = ela_get_friend_info(fc->carrier, friend_node_id, &info);
        if (rc < 0)
            break;

        if (info.status != ElaConnectionStatus_Connected)
            pthread_cond_wait(&fc->cond, &fc->lock);
        else
            break;
    }
    pthread_mutex_unlock(&fc->lock);

    return rc;
}

int feeds_client_friend_remove(FeedsClient *fc, const char *user_id)
{
    return ela_remove_friend(fc->carrier, user_id);
}

static
int transaction_start(FeedsClient *fc, const char *svc_addr, const void *req,
                      size_t len, cJSON **resp, JsonRPCType *type)
{
    int rc;

    pthread_mutex_lock(&fc->lock);

    fc->waiting_response = true;
    rc = carrier_transport_send_message(fc->ct, svc_addr, req, len);
    if (rc < 0) {
        fc->waiting_response = false;
        pthread_mutex_unlock(&fc->lock);
        return -1;
    }

    while (!fc->response)
        pthread_cond_wait(&fc->cond, &fc->lock);

    *resp = fc->response;
    *type = fc->response_type;
    fc->response = NULL;
    fc->waiting_response = false;

    pthread_mutex_unlock(&fc->lock);

    return 0;
}

int feeds_client_create_topic(FeedsClient *fc, const char *svc_addr, const char *name,
                              const char *desc, cJSON **resp)
{
    JsonRPCType type;
    cJSON *params;
    char *req;
    int rc;

    *resp = NULL;

    params = cJSON_CreateObject();
    if (!params)
        return -1;

    if (!cJSON_AddStringToObject(params, "topic", name)) {
        cJSON_Delete(params);
        return -1;
    }

    if (!cJSON_AddStringToObject(params, "desc", desc)) {
        cJSON_Delete(params);
        return -1;
    }

    req = jsonrpc_encode_request("create_topic", params, fc->null_json);
    cJSON_Delete(params);
    if (!req)
        return -1;

    rc = transaction_start(fc, svc_addr, req, strlen(req) + 1, resp, &type);
    free(req);
    if (rc < 0 || type == JSONRPC_TYPE_ERROR_RESPONSE)
        return -1;

    return 0;
}

int feeds_client_post_event(FeedsClient *fc, const char *svc_addr, const char *topic,
                            const char *content, cJSON **resp)
{
    JsonRPCType type;
    cJSON *params;
    char *req;
    int rc;

    *resp = NULL;

    params = cJSON_CreateObject();
    if (!params)
        return -1;

    if (!cJSON_AddStringToObject(params, "topic", topic)) {
        cJSON_Delete(params);
        return -1;
    }

    if (!cJSON_AddStringToObject(params, "event", content)) {
        cJSON_Delete(params);
        return -1;
    }

    req = jsonrpc_encode_request("post_event", params, fc->null_json);
    cJSON_Delete(params);
    if (!req)
        return -1;

    rc = transaction_start(fc, svc_addr, req, strlen(req) + 1, resp, &type);
    free(req);
    if (rc < 0 || type == JSONRPC_TYPE_ERROR_RESPONSE)
        return -1;

    return 0;
}

int feeds_client_list_owned_topics(FeedsClient *fc, const char *svc_node_id, cJSON **resp)
{
    const cJSON *result;
    const cJSON *topic;
    const cJSON *name;
    const cJSON *desc;
    JsonRPCType type;
    char *req;
    int rc;

    *resp = NULL;

    req = jsonrpc_encode_request("list_owned_topics", NULL, fc->null_json);
    if (!req)
        return -1;

    rc = transaction_start(fc, svc_node_id, req, strlen(req) + 1, resp, &type);
    free(req);
    if (rc < 0 || type == JSONRPC_TYPE_ERROR_RESPONSE)
        return -1;

    result = jsonrpc_get_result(*resp);
    if (!cJSON_IsArray(result)) {
        cJSON_Delete(*resp);
        *resp = NULL;
        return -1;
    }

    cJSON_ArrayForEach(topic, result) {
        if (!cJSON_IsObject(topic) ||
            !(name = cJSON_GetObjectItemCaseSensitive(topic, "name")) ||
            !(desc = cJSON_GetObjectItemCaseSensitive(topic, "desc")) ||
            !cJSON_IsString(name) || !name->valuestring[0] ||
            !cJSON_IsString(desc) || !desc->valuestring[0]) {
            cJSON_Delete(*resp);
            *resp = NULL;
            return -1;
        }
    }

    return 0;
}

int feeds_client_subscribe(FeedsClient *fc, const char *svc_node_id, const char *topic,
                           cJSON **resp)
{
    JsonRPCType type;
    cJSON *params;
    char *req;
    int rc;

    *resp = NULL;

    params = cJSON_CreateObject();
    if (!params)
        return -1;

    if (!cJSON_AddStringToObject(params, "topic", topic)) {
        cJSON_Delete(params);
        return -1;
    }

    req = jsonrpc_encode_request("subscribe", params, fc->null_json);
    cJSON_Delete(params);
    if (!req)
        return -1;

    rc = transaction_start(fc, svc_node_id, req, strlen(req) + 1, resp, &type);
    free(req);
    if (rc < 0 || type == JSONRPC_TYPE_ERROR_RESPONSE)
        return -1;

    return 0;
}

int feeds_client_unsubscribe(FeedsClient *fc, const char *svc_node_id,
                             const char *topic, cJSON **resp)
{
    JsonRPCType type;
    cJSON *params;
    char *req;
    int rc;

    *resp = NULL;

    params = cJSON_CreateObject();
    if (!params)
        return -1;

    if (!cJSON_AddStringToObject(params, "topic", topic)) {
        cJSON_Delete(params);
        return -1;
    }

    req = jsonrpc_encode_request("unsubscribe", params, fc->null_json);
    cJSON_Delete(params);
    if (!req)
        return -1;

    rc = transaction_start(fc, svc_node_id, req, strlen(req) + 1, resp, &type);
    free(req);
    if (rc < 0 || type == JSONRPC_TYPE_ERROR_RESPONSE)
        return -1;

    return 0;
}

int feeds_client_explore_topics(FeedsClient *fc, const char *svc_node_id, cJSON **resp)
{
    JsonRPCType type;
    const cJSON *result;
    const cJSON *topic;
    const cJSON *name;
    const cJSON *desc;
    char *req;
    int rc;

    *resp = NULL;

    req = jsonrpc_encode_request("explore_topics", NULL, fc->null_json);
    if (!req)
        return -1;

    rc = transaction_start(fc, svc_node_id, req, strlen(req) + 1, resp, &type);
    free(req);
    if (rc < 0 || type == JSONRPC_TYPE_ERROR_RESPONSE)
        return -1;

    result = jsonrpc_get_result(*resp);
    if (!cJSON_IsArray(result)) {
        cJSON_Delete(*resp);
        *resp = NULL;
        return -1;
    }

    cJSON_ArrayForEach(topic, result) {
        if (!cJSON_IsObject(topic) ||
            !(name = cJSON_GetObjectItemCaseSensitive(topic, "name")) ||
            !(desc = cJSON_GetObjectItemCaseSensitive(topic, "desc")) ||
            !cJSON_IsString(name) || !name->valuestring[0] ||
            !cJSON_IsString(desc) || !desc->valuestring[0]) {
            cJSON_Delete(*resp);
            *resp = NULL;
            return -1;
        }
    }

    return 0;
}

int feeds_client_list_subscribed(FeedsClient *fc, const char *svc_node_id, cJSON **resp)
{
    JsonRPCType type;
    const cJSON *result;
    const cJSON *topic;
    const cJSON *name;
    const cJSON *desc;
    char *req;
    int rc;

    *resp = NULL;

    req = jsonrpc_encode_request("list_subscribed_topics", NULL, fc->null_json);
    if (!req)
        return -1;

    rc = transaction_start(fc, svc_node_id, req, strlen(req) + 1, resp, &type);
    free(req);
    if (rc < 0 || type == JSONRPC_TYPE_ERROR_RESPONSE)
        return -1;

    result = jsonrpc_get_result(*resp);
    if (!cJSON_IsArray(result)) {
        cJSON_Delete(*resp);
        *resp = NULL;
        return -1;
    }

    cJSON_ArrayForEach(topic, result) {
        if (!cJSON_IsObject(topic) ||
            !(name = cJSON_GetObjectItemCaseSensitive(topic, "name")) ||
            !(desc = cJSON_GetObjectItemCaseSensitive(topic, "desc")) ||
            !cJSON_IsString(name) || !name->valuestring[0] ||
            !cJSON_IsString(desc) || !desc->valuestring[0]) {
            cJSON_Delete(*resp);
            *resp = NULL;
            return -1;
        }
    }

    return 0;
}

int feeds_client_fetch_unreceived(FeedsClient *fc, const char *svc_node_id,
                                  const char *topic, size_t since, cJSON **resp)
{
    JsonRPCType type;
    const cJSON *result;
    const cJSON *elem;
    cJSON *params;
    cJSON *event;
    cJSON *seqno;
    cJSON *ts;
    char *req;
    int rc;

    *resp = NULL;

    params = cJSON_CreateObject();
    if (!params)
        return -1;

    if (!cJSON_AddStringToObject(params, "topic", topic)) {
        cJSON_Delete(params);
        return -1;
    }

    if (!cJSON_AddNumberToObject(params, "since", since)) {
        cJSON_Delete(params);
        return -1;
    }

    req = jsonrpc_encode_request("fetch_unreceived", params, fc->null_json);
    cJSON_Delete(params);
    if (!req)
        return -1;

    rc = transaction_start(fc, svc_node_id, req, strlen(req) + 1, resp, &type);
    free(req);
    if (rc < 0 || type == JSONRPC_TYPE_ERROR_RESPONSE)
        return -1;

    result = jsonrpc_get_result(*resp);
    if (!cJSON_IsArray(result)) {
        cJSON_Delete(*resp);
        *resp = NULL;
        return -1;
    }

    cJSON_ArrayForEach(elem, result) {
        if (!(event = cJSON_GetObjectItemCaseSensitive(elem, "event")) ||
            !(seqno = cJSON_GetObjectItemCaseSensitive(elem, "seqno")) ||
            !(ts = cJSON_GetObjectItemCaseSensitive(elem, "ts")) ||
            !cJSON_IsString(event) || !event->valuestring[0] ||
            !cJSON_IsNumber(seqno) || !cJSON_IsNumber(ts)) {
            cJSON_Delete(*resp);
            *resp = NULL;
            return -1;
        }
    }

    return 0;
}

cJSON *feeds_client_get_new_events(FeedsClient *fc)
{
    cJSON *evs = NULL;
    int size;
    int i;

    pthread_mutex_lock(&fc->lock);

    size = cJSON_GetArraySize(fc->new_events);
    if (size) {
        evs = cJSON_CreateArray();
        if (evs) {
            for (i = 0; i < size; ++i)
                cJSON_AddItemToArray(evs,
                                     cJSON_DetachItemFromArray(fc->new_events,
                                                                     0));
        }
    }

    pthread_mutex_unlock(&fc->lock);

    return evs;
}
