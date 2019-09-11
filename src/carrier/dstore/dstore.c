/*
 * Copyright (c) 2019 Elastos Foundation
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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <crystal.h>
#include <cjson/cJSON.h>

#include <crystal.h>

#include "dstore.h"
#include "http_client.h"

#define MAX_IPV4_ADDRESS_LEN (15)
#define MAX_IPV6_ADDRESS_LEN (47)

#define HttpStatus_OK 200

#define DSTORE_UID "uid-2041b18e-ca86-4962-9a21-d477f7f627ce"

#define MSG_PATH "/messages"

typedef struct rpc_node {
    char ipv4[MAX_IPV4_ADDRESS_LEN + 1];
    char ipv6[MAX_IPV6_ADDRESS_LEN + 1];
    uint16_t port;
} rpc_node_t;

struct dstore {
    char current_node_ip[MAX_IPV6_ADDRESS_LEN + 1];
    uint16_t current_node_port;
    size_t rpc_nodes_count;
    rpc_node_t rpc_nodes[0];
};

static int ipfs_rest_get_node_version(const char *node_ip, uint16_t node_port)
{
    char url[MAXPATHLEN + 1];
    http_client_t *httpc;
    int rc;
    long resp_code;

    rc = snprintf(url, sizeof(url), "http://%s:%d/version", node_ip, node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_request_body_instant(httpc, NULL, 0);
    http_client_set_timeout(httpc, 5);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    http_client_close(httpc);
    if (rc)
        return -1;

    if (resp_code != HttpStatus_OK)
        return -1;

    return 0;

error_exit:
    http_client_close(httpc);
    return -1;
}

static int ipfs_rest_get_uid_info(const char *node_ip, uint16_t node_port,
                                  const char *uid, char **resp)
{
    char url[MAXPATHLEN + 1];
    http_client_t *httpc;
    long resp_code = 0;
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%d/api/v0/uid/info",
                  node_ip, node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "uid", uid);
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_request_body_instant(httpc, NULL, 0);
    if (resp)
        http_client_enable_response_body(httpc);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    if (rc)
        goto error_exit;

    if (resp_code != HttpStatus_OK)
        goto error_exit;

    if (resp) {
        char *p;

        p = http_client_move_response_body(httpc, NULL);
        if (!p)
            goto error_exit;

        *resp = p;
    }

    http_client_close(httpc);
    return 0;

error_exit:
    http_client_close(httpc);
    return -1;
}

static int ipfs_rest_resolve(const char *node_ip, uint16_t node_port,
                             const char *peerid, char **resp)
{
    char url[MAXPATHLEN + 1];
    http_client_t *httpc;
    long resp_code = 0;
    char *p;
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%u/api/v0/name/resolve",
                  node_ip, (unsigned)node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "arg", peerid);
    http_client_set_method(httpc, HTTP_METHOD_GET);
    http_client_enable_response_body(httpc);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    if (rc)
        goto error_exit;

    if (resp_code != HttpStatus_OK)
        goto error_exit;

    p = http_client_move_response_body(httpc, NULL);
    http_client_close(httpc);

    if (!p)
        return -1;

    *resp = p;
    return 0;

error_exit:
    http_client_close(httpc);
    return -1;
}

static int ipfs_rest_login(const char *node_ip, uint16_t node_port,
                           const char *uid, const char *root_hash)
{
    char url[MAXPATHLEN + 1];
    http_client_t *httpc;
    long resp_code = 0;
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%u/api/v0/uid/login",
                  node_ip, (unsigned)node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "uid", uid);
    http_client_set_query(httpc, "hash", root_hash);
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_request_body_instant(httpc, NULL, 0);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    http_client_close(httpc);

    if (rc)
        return -1;

    if (resp_code != HttpStatus_OK)
        return -1;

    return 0;

error_exit:
    http_client_close(httpc);
    return -1;
}

static int ipfs_rest_list_files(const char *node_ip, uint16_t node_port,
                                const char *uid, const char *path, char **resp)
{
    char url[MAXPATHLEN + 1];
    http_client_t *httpc;
    long resp_code;
    char *p;
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%u/api/v0/files/ls",
                  node_ip, (unsigned)node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "uid", uid);
    http_client_set_query(httpc, "path", path);
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_request_body_instant(httpc, NULL, 0);
    http_client_enable_response_body(httpc);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    if (rc)
        goto error_exit;

    if (resp_code != HttpStatus_OK)
        goto error_exit;

    p = http_client_move_response_body(httpc, NULL);
    http_client_close(httpc);

    if (!p)
        return -1;

    *resp = p;
    return 0;

error_exit:
    http_client_close(httpc);
    return -1;
}

static int ipfs_rest_file_stat(const char *node_ip, uint16_t node_port,
                               const char *uid, const char *path, char **resp)
{
    char url[MAXPATHLEN + 1];
    http_client_t *httpc;
    long resp_code = 0;
    char *p;
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%u/api/v0/files/stat",
                  node_ip, (unsigned)node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "uid", uid);
    http_client_set_query(httpc, "path", path);
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_request_body_instant(httpc, NULL, 0);
    http_client_enable_response_body(httpc);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    if (rc)
        goto error_exit;

    if (resp_code != HttpStatus_OK)
        goto error_exit;

    p = http_client_move_response_body(httpc, NULL);
    http_client_close(httpc);

    if (!p)
        return -1;

    *resp = p;
    return 0;

error_exit:
    http_client_close(httpc);
    return -1;
}

static size_t read_response_body_cb(char *buffer,
                                    size_t size, size_t nitems, void *userdata)
{
    char *buf = (char *)(((void **)userdata)[0]);
    size_t bufsz = *((size_t *)(((void **)userdata)[1]));
    size_t *nrd = (size_t *)(((void **)userdata)[2]);
    size_t total_sz = size * nitems;

    if (*nrd + total_sz > bufsz)
        return 0;

    memcpy(buf + *nrd, buffer, total_sz);
    *nrd += total_sz;

    return total_sz;
}

static ssize_t ipfs_rest_file_read(const char *node_ip, uint16_t node_port,
                                   const char *uid, const char *path, size_t offset,
                                   void *buf, size_t len)
{
    char url[MAXPATHLEN + 1];
    char header[128];
    http_client_t *httpc;
    long resp_code = 0;
    size_t nrd = 0;
    void *user_data[] = {buf, &len, &nrd};
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%u/api/v0/files/read",
                  node_ip, (unsigned)node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "uid", uid);
    http_client_set_query(httpc, "path", path);
    sprintf(header, "%zu", offset);
    http_client_set_query(httpc, "offset", header);
    sprintf(header, "%zu", len);
    http_client_set_query(httpc, "count", header);
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_request_body_instant(httpc, NULL, 0);
    http_client_set_response_body(httpc, read_response_body_cb, user_data);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    http_client_close(httpc);
    if (rc)
        return -1;

    if (resp_code != HttpStatus_OK)
        return -1;

    return nrd;

error_exit:
    http_client_close(httpc);
    return -1;
}

static int ipfs_rest_mkdir(const char *node_ip, uint16_t node_port,
                           const char *uid, const char *path)
{
    char url[MAXPATHLEN + 1];
    http_client_t *httpc;
    long resp_code;
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%u/api/v0/files/mkdir",
                  node_ip, (unsigned)node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "uid", uid);
    http_client_set_query(httpc, "path", path);
    http_client_set_query(httpc, "parents", "true");
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_request_body_instant(httpc, NULL, 0);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    http_client_close(httpc);
    if (rc)
        return -1;

    if (resp_code != HttpStatus_OK)
        return -1;

    return 0;

error_exit:
    http_client_close(httpc);
    return -1;
}

static int ipfs_rest_publish(const char *node_ip, uint16_t node_port,
                             const char *uid, const char *hash)
{
    char url[MAXPATHLEN + 1];
    http_client_t *httpc;
    long resp_code = 0;
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%u/api/v0/name/publish",
                  node_ip, (unsigned)node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "uid", uid);
    http_client_set_query(httpc, "path", hash);
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_request_body_instant(httpc, NULL, 0);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    http_client_close(httpc);
    if (rc)
        return -1;

    if (resp_code != HttpStatus_OK)
        return -1;

    return 0;

error_exit:
    http_client_close(httpc);
    return -1;
}

static ssize_t ipfs_rest_file_write(const char *node_ip, uint16_t node_port,
                                    const char *uid, const char *path, size_t offset,
                                    const uint8_t *value, size_t len)
{
    char url[MAXPATHLEN + 1];
    char header[128];
    http_client_t *httpc;
    long resp_code = 0;
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%u/api/v0/files/write",
                  node_ip, (unsigned)node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "uid", uid);
    http_client_set_query(httpc, "path", path);
    sprintf(header, "%zu", offset);
    http_client_set_query(httpc, "offset", header);
    sprintf(header, "%zu", len);
    http_client_set_query(httpc, "count", header);
    http_client_set_query(httpc, "create", "true");
    http_client_set_mime_instant(httpc, "file", NULL, NULL, (const char *)value, len);
    http_client_set_method(httpc, HTTP_METHOD_POST);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    http_client_close(httpc);
    if (rc)
        return -1;

    if (resp_code != HttpStatus_OK)
        return -1;

    return len;

error_exit:
    http_client_close(httpc);
    return -1;
}

static int ipfs_rest_rm(const char *node_ip, uint16_t node_port,
                        const char *uid, const char *path)
{
    char url[MAXPATHLEN + 1];
    http_client_t *httpc;
    long resp_code;
    int rc;

    rc = snprintf(url, sizeof(url), "http://%s:%u/api/v0/files/rm",
                  node_ip, (unsigned)node_port);
    if (rc < 0 || rc >= sizeof(url))
        return -1;

    httpc = http_client_new();
    if (!httpc)
        return -1;

    http_client_set_url(httpc, url);
    http_client_set_query(httpc, "uid", uid);
    http_client_set_query(httpc, "path", path);
    http_client_set_query(httpc, "recursive", "true");
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_request_body_instant(httpc, NULL, 0);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    http_client_close(httpc);
    if (rc)
        return -1;

    if (resp_code != HttpStatus_OK)
        return -1;

    return 0;

error_exit:
    http_client_close(httpc);
    return -1;
}

static int select_bootstrap(DStore *ds)
{
    rpc_node_t *rpc_nodes = ds->rpc_nodes;
    size_t base;
    size_t i;
    int rc;

    srand((unsigned)time(NULL));
    base = (size_t)rand() % ds->rpc_nodes_count;
    i = base;

    do {
        if (rpc_nodes[i].ipv4[0]) {
            rc = ipfs_rest_get_node_version(rpc_nodes[i].ipv4, rpc_nodes[i].port);
            if (!rc) {
                strcpy(ds->current_node_ip, rpc_nodes[i].ipv4);
                ds->current_node_port = rpc_nodes[i].port;
                return 0;
            }
        }

        if (rpc_nodes[i].ipv6[0]) {
            rc = ipfs_rest_get_node_version(rpc_nodes[i].ipv6, rpc_nodes[i].port);
            if (!rc) {
                strcpy(ds->current_node_ip, rpc_nodes[i].ipv6);
                ds->current_node_port = rpc_nodes[i].port;
                return 0;
            }
        }

        i = (i + 1) % ds->rpc_nodes_count;
    } while (i != base);

    return -1;
}

static int synchronize_data_to_current_node(DStore *ds)
{
    char *resp;
    cJSON *json = NULL;
    cJSON *peer_id;
    cJSON *hash;
    int rc;

    rc = ipfs_rest_get_uid_info(ds->current_node_ip,
                                ds->current_node_port,
                                DSTORE_UID, &resp);
    if (rc < 0)
        return rc;

    json = cJSON_Parse(resp);
    free(resp);
    if (!json)
        return -1;

    peer_id = cJSON_GetObjectItemCaseSensitive(json, "PeerID");
    if (!cJSON_IsString(peer_id) || !peer_id->valuestring || !*peer_id->valuestring) {
        cJSON_Delete(json);
        return -1;
    }

    rc = ipfs_rest_resolve(ds->current_node_ip,
                           ds->current_node_port,
                           peer_id->valuestring, &resp);
    cJSON_Delete(json);
    if (rc < 0)
        return rc;

    json = cJSON_Parse(resp);
    free(resp);
    if (!json)
        return -1;

    hash = cJSON_GetObjectItemCaseSensitive(json, "Path");
    if (!cJSON_IsString(hash) || !hash->valuestring || !*hash->valuestring) {
        cJSON_Delete(json);
        return -1;
    }

    rc = ipfs_rest_login(ds->current_node_ip, ds->current_node_port,
                         DSTORE_UID, hash->valuestring);
    cJSON_Delete(json);
    if (rc < 0)
        return rc;

    return 0;
}

static int setup_working_node(DStore *ds)
{
    int rc;

    rc = select_bootstrap(ds);
    if (rc < 0)
        return -1;

    rc = synchronize_data_to_current_node(ds);
    if (rc < 0)
        return -1;

    return 0;
}


DStore *dstore_create(dstorec_node *bootstraps, size_t sz)
{
    DStore *ds;
    size_t i;
    int rc;

    ds = rc_zalloc(sizeof(DStore) + sizeof(rpc_node_t) * sz, NULL);
    if (!ds)
        return NULL;

    ds->rpc_nodes_count = sz;

    for (i = 0; i < sz ; ++i) {
        rpc_node_t *rpc = ds->rpc_nodes + i;
        dstorec_node *nd = bootstraps + i;

        if (nd->ipv4)
            strcpy(rpc->ipv4, nd->ipv4);

        if (nd->ipv6)
            strcpy(rpc->ipv6, nd->ipv6);

        rpc->port = nd->port;
    }

    rc = setup_working_node(ds);
    if (rc < 0) {
        deref(ds);
        return NULL;
    }

    return ds;
}

void dstore_destroy(DStore *dstore)
{
    deref(dstore);
}

static cJSON *parse_list_files_response(const char *response)
{
    cJSON *json;
    cJSON *entries;
    cJSON *entry;

    assert(response);

    json = cJSON_Parse(response);
    if (!json)
        return NULL;

    entries = cJSON_GetObjectItemCaseSensitive(json, "Entries");
    if (!entries || (!cJSON_IsArray(entries) && !cJSON_IsNull(entries))) {
        cJSON_Delete(json);
        return NULL;
    }

    if (cJSON_IsNull(entries))
        return json;

    cJSON_ArrayForEach(entry, entries) {
        cJSON *name;

        if (!cJSON_IsObject(entry)) {
            cJSON_Delete(json);
            return NULL;
        }

        name = cJSON_GetObjectItemCaseSensitive(entry, "Name");
        if (!name || !cJSON_IsString(name) || !name->valuestring ||
            !*name->valuestring) {
            cJSON_Delete(json);
            return NULL;
        }
    }

    return json;
}

static int read_file(DStore *ds, const char *path, void **pdata, size_t *plen)
{
    int rc;
    cJSON *json;
    cJSON *size;
    char *resp;
    size_t len;
    void *data;
    ssize_t nrd;

    rc = ipfs_rest_file_stat(ds->current_node_ip, ds->current_node_port,
                             DSTORE_UID, path, &resp);
    if (rc < 0) {
        setup_working_node(ds);
        return -1;
    }

    json = cJSON_Parse(resp);
    free(resp);
    if (!json) {
        setup_working_node(ds);
        return -1;
    }

    size = cJSON_GetObjectItem(json, "Size");
    if (!size || !cJSON_IsNumber(size)) {
        setup_working_node(ds);
        cJSON_Delete(json);
        return -1;
    }

    len = (size_t)size->valuedouble;
    cJSON_Delete(json);

    data = malloc(len);
    if (!data)
        return -1;

    nrd = ipfs_rest_file_read(ds->current_node_ip, ds->current_node_port,
                              DSTORE_UID, path, 0, data, len);
    if (nrd < 0)
        return -1;

    *pdata = data;
    *plen = nrd;
    return 0;
}

int dstore_get_values(DStore *ds, const char *key,
                      bool (*cb)(const char *key, const uint8_t *value,
                                 size_t length, void *ctx),
                      void *ctx)
{
    char path[MAXPATHLEN + 1];
    cJSON *resp_json;
    cJSON *entries;
    cJSON *entry;
    char *resp;
    int rc;

    sprintf(path, "%s/%s", MSG_PATH, key);
    rc = ipfs_rest_list_files(ds->current_node_ip, ds->current_node_port,
                              DSTORE_UID, path, &resp);
    if (rc < 0) {
        setup_working_node(ds);
        return -1;
    }

    resp_json = parse_list_files_response(resp);
    free(resp);
    if (!resp_json) {
        setup_working_node(ds);
        return -1;
    }

    entries = cJSON_GetObjectItemCaseSensitive(resp_json, "Entries");
    if (cJSON_IsArray(entries)) {
        cJSON_ArrayForEach(entry, entries) {
            char fpath[MAXPATHLEN + 1];
            cJSON *name;
            void *data;
            size_t len;
            bool resume;

            name = cJSON_GetObjectItemCaseSensitive(entry, "Name");
            sprintf(fpath, "%s/%s", path, name->valuestring);

            rc = read_file(ds, fpath, &data, &len);
            if (rc < 0) {
                setup_working_node(ds);
                cJSON_Delete(resp_json);
                return -1;
            }

            resume = cb(key, data, len, ctx);
            free(data);
            if (!resume) {
                cJSON_Delete(resp_json);
                return 0;
            }
        }
    }
    cJSON_Delete(resp_json);
    return 0;
}

static int get_root_hash(DStore *ds, char *buf, size_t bufsz)
{
    int rc;
    char *resp;
    cJSON *json;
    cJSON *hash;

    rc = ipfs_rest_file_stat(ds->current_node_ip, ds->current_node_port,
                             DSTORE_UID, "/", &resp);
    if (rc < 0) {
        setup_working_node(ds);
        return -1;
    }

    json = cJSON_Parse(resp);
    free(resp);
    if (!json) {
        setup_working_node(ds);
        return -1;
    }

    hash = cJSON_GetObjectItem(json, "Hash");
    if (!cJSON_IsString(hash) || !hash->valuestring || !*hash->valuestring) {
        setup_working_node(ds);
        cJSON_Delete(json);
        return -1;
    }

    rc = snprintf(buf, bufsz, "/ipfs/%s", hash->valuestring);
    cJSON_Delete(json);
    if (rc < 0 || rc >= bufsz)
        return -1;

    return 0;
}

static int publish_root_hash(DStore *ds)
{
    int rc;
    char hash[1024];

    rc = get_root_hash(ds, hash, sizeof(hash));
    if (rc < 0)
        return -1;

    rc = ipfs_rest_publish(ds->current_node_ip, ds->current_node_port,
                           DSTORE_UID, hash);
    if (rc < 0) {
        setup_working_node(ds);
        return -1;
    }

    return 0;
}

int dstore_add_value(DStore *ds, const char *key, const uint8_t *value, size_t len)
{
    char path[MAXPATHLEN + 1];
    int rc;
    ssize_t nwr;

    sprintf(path, "%s/%s", MSG_PATH, key);
    rc = ipfs_rest_mkdir(ds->current_node_ip, ds->current_node_port, DSTORE_UID, path);
    if (rc < 0) {
        setup_working_node(ds);
        return -1;
    }

    sprintf(path + strlen(path), "/%llu", (unsigned long long)time(NULL));
    nwr = ipfs_rest_file_write(ds->current_node_ip, ds->current_node_port, DSTORE_UID,
                               path, 0, value, len);
    if (nwr < 0) {
        setup_working_node(ds);
        return -1;
    }

    rc = publish_root_hash(ds);
    if (rc < 0)
        return -1;

    return 0;
}

int dstore_remove_values(DStore *ds, const char *key)
{
    char path[MAXPATHLEN + 1];
    int rc;
    ssize_t nwr;

    sprintf(path, "%s/%s", MSG_PATH, key);
    rc = ipfs_rest_rm(ds->current_node_ip, ds->current_node_port, DSTORE_UID, path);
    if (rc < 0) {
        setup_working_node(ds);
        return -1;
    }

    rc = publish_root_hash(ds);
    if (rc < 0)
        return -1;

    return 0;
}
