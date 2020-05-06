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
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#if defined(_WIN32) || defined(_WIN64)
#include <io.h>
#endif

#include <cjson/cJSON.h>
#include <crystal.h>

#include "dht.h"
#include "ela_carrier.h"
#include "ela_carrier_impl.h"
#include "http_client.h"
#include "express.h"

struct ExpressConnector {
    ElaCarrier *carrier;
    ExpressOnRecvCallback on_msg_cb;
    ExpressOnRecvCallback on_req_cb;
    ExpressOnStatCallback on_stat_cb;
    http_client_t *http_client;

    list_t *tasklets;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    int stopped;

    const char* base_url;
    uint8_t shared_key[SYMMETRIC_KEY_BYTES];
};

typedef struct Tasklet {
    list_entry_t entry;
    ExpressConnector *connector;

    void (*handle_cb)(struct Tasklet *);
} Tasklet;

typedef struct SendTasklet {
    Tasklet base;
    int64_t msgid;
    char to[ELA_MAX_ADDRESS_LEN + 1];
    size_t length;
    uint8_t data[0];
} SendTasklet;

typedef struct PullTasklet {
    Tasklet base;
} PullTasklet;

static inline uint8_t *get_shared_key(Tasklet *task)
{
    return task->connector->shared_key;
}

static inline http_client_t *get_http_client(Tasklet *task)
{
    return task->connector->http_client;
}

static inline char *get_my_userid(Tasklet *task)
{
    return task->connector->carrier->me.userid;
}

static const int  URL_MAX_SIZE = 1024;

static int compute_sharedkey(ElaCarrier *w, uint8_t *pk, uint8_t *shared_key)
{
    uint8_t sk[SECRET_KEY_BYTES];
    ssize_t rc;

    dht_self_get_secret_key(&w->dht, sk);
    crypto_compute_symmetric_key(pk, sk, shared_key);

    return 0;
}

static ssize_t encrypt_data(uint8_t *key,
                            uint8_t *plain_data, size_t plain_len,
                            uint8_t *crypted_data)
{
    ssize_t rc;

    crypto_random_nonce(crypted_data);
    rc = crypto_encrypt(key, crypted_data, plain_data, plain_len, crypted_data + NONCE_BYTES);
    if (rc < 0)
        return ELA_GENERAL_ERROR(ELAERR_ENCRYPT);

    return rc + NONCE_BYTES;
}

static ssize_t decrypt_data(uint8_t *key,
                            uint8_t *crypted_data, size_t crypted_len,
                            uint8_t *plain_data)
{
    ssize_t rc;

    rc = crypto_decrypt(key, crypted_data, crypted_data + NONCE_BYTES, crypted_len - NONCE_BYTES, plain_data);
    if (rc < 0)
        return ELA_GENERAL_ERROR(ELAERR_ENCRYPT);

    return rc;
}

static int express_http_do(ExpressConnector *connector,
                           http_client_t *http_client, const char* path,
                           http_method_t method, uint8_t **data, size_t *size)
{
    http_client_reset(http_client);
    char url[URL_MAX_SIZE];
    snprintf(url, sizeof(url), "%s/%s", connector->base_url, path);

    const char* dowhat = (method == HTTP_METHOD_POST ? "pushing"
                       : (method == HTTP_METHOD_GET ? "pulling"
                       : (method == HTTP_METHOD_DELETE ? "deleting"
                       : "unknown")));
    vlogD("Express: %s message, url: %s", dowhat, url);

    int rc = http_client_set_url(http_client, url);
    if(rc != 0) {
        vlogE("Express: Failed to set http url.(CURLE: %d)", rc);
        return -1; // TODO: workaround
    }

    rc = http_client_set_method(http_client, method);
    if(rc != 0) {
        vlogE("Express: Failed to set http method.(CURLE: %d)", rc);
        return -1; // TODO: workaround
    }

    if (method == HTTP_METHOD_POST) {
        http_client_set_header(http_client, "Content-Type", "application/binary");

        rc = http_client_set_request_body_instant(http_client, *data, *size);
        if (rc != 0) {
            vlogE("Express: Failed to set http request body.(CURLE: %d)", rc);
            return -1;  // TODO: workaround
        }
    }


    http_client_enable_response_body(http_client);
    http_client_set_timeout(connector->http_client, 30000);
    rc = http_client_request(http_client);
    if(rc != 0) {
        vlogE("Express: Failed to perform http request.(CURLE: %d)", rc);
        return -1; // TODO: workaround
    }

    long http_client_rescode = 0;
    rc = http_client_get_response_code(http_client, &http_client_rescode);
    if(rc != 0) {
        vlogE("Express: Failed to get http response code.(CURLE: %d)", rc);
        return -1; // TODO: workaround
    }
    if((method == HTTP_METHOD_POST && http_client_rescode != 201)
    || (method == HTTP_METHOD_GET && http_client_rescode != 200)
    || (method == HTTP_METHOD_DELETE && http_client_rescode != 205)) {
        vlogE("Express: Failed to %s message from server rescode=%d.(CURLE: %d)", dowhat, http_client_rescode, rc);
        return -1; // TODO: workaround
    }

    if (method == HTTP_METHOD_GET) {
        *data = (uint8_t *)http_client_get_response_body(http_client);
        *size = http_client_get_response_body_length(http_client);
        if (*data == NULL || *size <= 0) {
            vlogE("Express: Failed to receive body from server.");
            return -1;  // TODO: workaround
        }
    }

    vlogD("Express: Success to %s message, url: %s", dowhat, url);

    return 0;
}

static int express_del_msgs(http_client_t *httpc, Tasklet *task, uint64_t last_msg_time)
{
    if(last_msg_time <= 0)
        return 0;

    char last_msg_time_str[256];
    snprintf(last_msg_time_str, sizeof(last_msg_time_str), "%lld", last_msg_time);
    int last_msg_time_strlen = strlen(last_msg_time_str);

    uint8_t *crypted_data = alloca(NONCE_BYTES + last_msg_time_strlen + ZERO_BYTES);
    int crypted_data_len = encrypt_data(get_shared_key(task), (uint8_t*)last_msg_time_str, last_msg_time_strlen, crypted_data);
    if(crypted_data_len < 0) {
        vlogE("Express: Failed to express encrypt data.(%d)", crypted_data_len);
        return crypted_data_len;
    }

    size_t encoded_data_len = crypted_data_len * 1.4f + 1;
    char encoded_data[encoded_data_len];
    char* base58_rc = base58_encode(crypted_data, crypted_data_len, encoded_data, &encoded_data_len);
    if(base58_rc == NULL || encoded_data_len <= 0) {
        vlogE("Express: Failed to encode last time.(%p)", base58_rc);
        return ELA_GENERAL_ERROR(ELAERR_INVALID_CREDENTIAL);
    }

    char path[URL_MAX_SIZE];
    snprintf(path, sizeof(path), "%s?until=%s", task->connector->carrier->me.userid, encoded_data);
    int rc = express_http_do(task->connector, httpc, path,
                                 HTTP_METHOD_DELETE, NULL, 0);
    if(rc < 0) {
        vlogE("Express: Failed to delete message.(%d)", rc);
        return rc;
    }

    return 0;
}

static int parse_message_item(Tasklet *task, cJSON *json, uint64_t *timestamp)
{
    ExpressConnector *connector = task->connector;
    cJSON *item;
    char *from;
    char *type;
    char *msg;
    size_t msgsz;

    item = cJSON_GetObjectItem(json, "id");
    if (!item || !cJSON_IsNumber(item)) {
        vlogE("Express: Message with invalid message id, dropped.");
        return -1;
    }

    item = cJSON_GetObjectItem(json, "from");
    if (!item || !cJSON_IsString(item)) {
        vlogE("Express: Message with invalid message source, dropped.");
        return -1;
    }
    from = item->valuestring;

    item = cJSON_GetObjectItem(json, "type");
    if (!item || !cJSON_IsString(item)) {
        vlogE("Express: Message with invalid message type, dropped.");
        return -1;
    }
    type = item->valuestring;

    if (strcmp(type, "R") == 0) {
        item = cJSON_GetObjectItem(json, "address");
        if (!item || !cJSON_IsString(item)) {
            vlogE("Express: Friend request with invalid address, dropped");
            return -1;
        }

        char addr[ELA_MAX_ADDRESS_LEN + 1];
        if (strcmp(item->valuestring, ela_get_address(task->connector->carrier, addr, sizeof(addr)))) {
            vlogE("Express: Friend request with unmatched address, dropped");
            return -1;
        }
    } else if (strcmp(type, "M") == 0) {
        if (!ela_is_friend(task->connector->carrier, from)) {
            vlogE("Express: Friend message not frond friend, dropped");
            return -1;
        }
    } else {
        vlogE("Express: Unsupported message type %s, dropped", type);
        return -1;
    }

    item = cJSON_GetObjectItem(json, "createAt");
    if (!item || !cJSON_IsNumber(item)) {
        vlogE("Express: Message with invalid created timestamp, dropped.");
        return -1;
    }
    *timestamp = (uint64_t)item->valuedouble;

    item = cJSON_GetObjectItem(json, "msg");
    if (!item || !cJSON_IsString(item)) {
        vlogE("Express: Message with invalid message body, dropped.");
        return -1;
    }
    msg = item->valuestring;
    msgsz = strlen(msg);

    size_t msg_maxsize = msgsz;
    uint8_t *msg_data = calloc(1, msg_maxsize);

    ssize_t msg_size = base58_decode(msg, msgsz, msg_data, msg_maxsize);

    // base58_decode origin data size must be the real size.
    msg_size = base58_decode(msg, strlen(msg), msg_data, msg_size);

#if 0
    vlogV("Express: received message data: (%d) 0x%02x 0x%02x ~ 0x%02x 0x%02x",
          msg_size, msg_data[0], msg_data[1], msg_data[msg_size - 2], msg_data[msg_size - 1]);
#endif

    if (strcmp(type, "M") == 0) {
        connector->on_msg_cb(connector->carrier, from, msg_data, msg_size, *timestamp);
    } else if (strcmp(type, "R") == 0) {
        connector->on_req_cb(connector->carrier, from, msg_data, msg_size, *timestamp);
    }

    free(msg_data);
    return 0;
}

static int parse_messages(Tasklet *task, uint8_t *data, uint64_t *timestamp)
{
    cJSON *root;
    cJSON *list;
    cJSON *item;
    int rc = 0;
    int sz;
    int i;

    *timestamp = 0;

    root = cJSON_Parse((char *)data);
    if (!root) {
        vlogE("Express: Parse json data error");
        return -1;
    }

    list = cJSON_GetObjectItem(root, "messages");
    if (!list) {
        vlogE("Express: Missing 'messages' field");
        cJSON_Delete(root);
        return -1;
    }

    sz = cJSON_GetArraySize(list);
    vlogI("Express: Found offline message. size=%d", sz);
    for (i = 0; i < sz; i++) {
        item = cJSON_GetArrayItem(list, i);
        if (!item) {
            vlogE("Express: Get %d message item error");
            continue;
        }

        int rc = parse_message_item(task, item, timestamp);
        if (rc < 0) {
            vlogE("Express: Parse message item error.");
            continue;
        }
    }

    cJSON_Delete(root);
    return rc;
}

static void express_send_msg(Tasklet *base)
{
    SendTasklet *task = (SendTasklet *)base;
    ExpressConnector *connector = task->base.connector;
    char path[URL_MAX_SIZE] = {0};
    uint8_t *encrypted;
    ssize_t  encrypted_sz;
    int rc;

#if 0
    vlogV("Express: send message data: (%d) 0x%02x 0x%02x ~ 0x%02x 0x%02x",
          length, data[0], data[1], data[length - 2], data[length - 1]);
#endif

    encrypted = (uint8_t *)calloc(1, task->length + NONCE_BYTES + ZERO_BYTES);
    if (!encrypted) {
        connector->on_stat_cb(connector->carrier, task->to, task->msgid, false);
        return;
    }

    encrypted_sz = encrypt_data(get_shared_key(base), task->data, task->length, encrypted);
    if(encrypted_sz < 0) {
        vlogE("Express: Encrypt data error");
        free(encrypted);
        connector->on_stat_cb(connector->carrier, task->to, task->msgid, false);
        return;
    }

    snprintf(path, sizeof(path), "%s/%s", task->to, get_my_userid(base));
    rc = express_http_do(base->connector, get_http_client(base), path,
                         HTTP_METHOD_POST,
                         &encrypted, (size_t *)&encrypted_sz);
    free(encrypted);

    if(rc < 0) {
        vlogE("Express: Failed to send message.(%d)", rc);
        connector->on_stat_cb(connector->carrier, task->to, task->msgid, false);
        return;
    }

    vlogI("Express: Success to offline message to %s.", task->to);
    connector->on_stat_cb(connector->carrier, task->to, task->msgid, true);
}

static void express_pull_msgs(Tasklet *base)
{
    PullTasklet *task = (PullTasklet *)base;
    uint8_t *data = NULL;
    size_t length = 0;
    int rc;

    uint8_t *plain_data;
    ssize_t  plain_data_sz;

    rc = express_http_do(base->connector, get_http_client(base),
                         get_my_userid(base),
                         HTTP_METHOD_GET, &data, &length);
    if(rc < 0) {
        vlogE("Express: Get messages with http method error (%x).",rc);
        return;
    }

    plain_data = (uint8_t *)calloc(1, length);
    if (!plain_data)
        return;

    plain_data_sz = decrypt_data(get_shared_key(base), data, length,
                                 plain_data);
    if(plain_data_sz < 0) {
        vlogE("Express: Decrypt data error");
        free(plain_data);
        return;
    }

    uint64_t last_timestamp = -1;
    rc = parse_messages(base, plain_data, &last_timestamp);
    free(plain_data);

    if(rc < 0)
        vlogE("Express: Deserialize data error");

    if(last_timestamp > 0) {
        rc = express_del_msgs(get_http_client(base), base, last_timestamp);
        if(rc < 0)
            vlogE("Express: Failed to delete data.(%x)", rc);
    }
    
}

static int enqueue_send_tasklet(ExpressConnector *connector, const char *to,
                                const void *data, size_t length, int64_t msgid)
{
    SendTasklet *task;

    task = (SendTasklet *)rc_zalloc(sizeof(SendTasklet) + length, NULL);
    if (!task)
        return ELA_GENERAL_ERROR(ELAERR_OUT_OF_MEMORY);

    task->base.entry.data = task;
    task->base.connector = connector;
    task->base.handle_cb = express_send_msg;

    task->msgid = msgid;
    strcpy(task->to, to);
    memcpy(task->data, data, length);
    task->length = length;

    pthread_mutex_lock(&connector->lock);
    list_push_head(connector->tasklets, &task->base.entry);
    pthread_mutex_unlock(&connector->lock);

    deref(task);
    pthread_cond_signal(&connector->cond);

    return 0;
}



int express_enqueue_friend_message(ExpressConnector *connector,
                                  const char *friendid,
                                  const void *data, size_t length)
{
    return enqueue_send_tasklet(connector, friendid, data, length, 0);
}

int express_enqueue_friend_request(ExpressConnector *connector,
                                  const char *address,
                                  const void *hello, size_t length)
{
    return enqueue_send_tasklet(connector, address, hello, length, 0);
}

int express_enqueue_friend_message_with_receipt(ExpressConnector *connector, const char *friendid,
                                                const void *data, size_t length,
                                                int64_t msgid)
{
    return enqueue_send_tasklet(connector, friendid, data, length, msgid);
}

int express_enqueue_pull_messages(ExpressConnector *connector)
{
    PullTasklet *task;
    assert(connector);

    task = (PullTasklet *)rc_zalloc(sizeof(PullTasklet), NULL);
    if (!task)
        return ELA_GENERAL_ERROR(ELAERR_OUT_OF_MEMORY);

    task->base.entry.data = task;
    task->base.connector = connector;
    task->base.handle_cb = express_pull_msgs;

    pthread_mutex_lock(&connector->lock);
    list_push_head(connector->tasklets, &task->base.entry);
    pthread_mutex_unlock(&connector->lock);

    deref(task);
    pthread_cond_signal(&connector->cond);

    return 0;
}

static void *express_connector_laundry(void *arg)
{
    ExpressConnector *connector = (ExpressConnector *)arg;
    Tasklet *task;

    vlogI("Express: Express connector start to running.");

    pthread_mutex_lock(&connector->lock);
    while(!connector->stopped) {
        if (list_is_empty(connector->tasklets)) {
            pthread_cond_wait(&connector->cond, &connector->lock);
            continue;
        }

        task = list_pop_tail(connector->tasklets);
        assert(task);

        pthread_mutex_unlock(&connector->lock);

        task->handle_cb(task);
        deref(task);

        pthread_mutex_lock(&connector->lock);
    }
    pthread_mutex_unlock(&connector->lock);

    deref(connector);
    deref(connector->carrier);

    vlogI("Express: Express connector exited gracefully.");

    return NULL;
}

static void express_connector_destroy(void *arg)
{
    ExpressConnector *connector = (ExpressConnector *)arg;
    assert(connector);

    if (connector->http_client) {
        http_client_close(connector->http_client);
        connector->http_client = NULL;
    }

    if (connector->tasklets) {
        deref(connector->tasklets);
        connector->tasklets = NULL;
    }

    if (connector->carrier)
        connector->carrier = NULL;

    if (connector->base_url) {
        free((void*)connector->base_url);
        connector->base_url = NULL;
    }

    pthread_mutex_destroy(&connector->lock);
    pthread_cond_destroy (&connector->cond);
}

ExpressConnector *express_connector_create(ElaCarrier *w,
                                           ExpressOnRecvCallback on_msg_cb,
                                           ExpressOnRecvCallback on_req_cb,
                                           ExpressOnStatCallback on_stat_cb)
{
    ExpressConnector *connector;
    pthread_t tid;
    int rc;

    connector = rc_zalloc(sizeof(ExpressConnector), express_connector_destroy);
    if (!connector) {
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_OUT_OF_MEMORY));
        return NULL;
    }

    connector->http_client = http_client_new();
    if (!connector->http_client) {
        deref(connector);
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_OUT_OF_MEMORY));
        return NULL;
    }

    pthread_mutex_init(&connector->lock, NULL);
    pthread_cond_init (&connector->cond, NULL);

    connector->tasklets = list_create(0, NULL);
    if (!connector->tasklets) {
        deref(connector);
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_OUT_OF_MEMORY));
        return NULL;
    }

    connector->carrier = w;
    connector->stopped = 0;

    connector->on_msg_cb = on_msg_cb;
    connector->on_req_cb = on_req_cb;
    connector->on_stat_cb = on_stat_cb;

    if (w->pref.express_bootstraps_size < 0) {
        deref(connector);
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_INVALID_ARGS));
        return NULL;
    }

    DhtBootstrapNodeBuf *express_bootstrap_0 = &w->pref.express_bootstraps[0];
    char base_url[URL_MAX_SIZE];
    snprintf(base_url, sizeof(base_url), "http://%s:%d",
             strlen(express_bootstrap_0->ipv4) != 0 ? express_bootstrap_0->ipv4 : express_bootstrap_0->ipv6,
             express_bootstrap_0->port);
    connector->base_url = strdup(base_url);

    rc = compute_sharedkey(w, express_bootstrap_0->public_key, connector->shared_key);
    if (rc < 0) {
        deref(connector);
        ela_set_error(rc);
        return NULL;
    }

    ref(w);
    ref(connector);

    rc = pthread_create(&tid, NULL, express_connector_laundry, connector);
    if (rc != 0) {
        deref(connector);
        deref(connector);
        deref(w);
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_OUT_OF_MEMORY));
        return NULL;
    }

    pthread_detach(tid);

    return connector;
}

void express_connector_kill(ExpressConnector *connector)
{
    assert(connector);

    pthread_mutex_lock(&connector->lock);
    connector->stopped = 1;
    pthread_cond_signal(&connector->cond);
    pthread_mutex_unlock(&connector->lock);
}
