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

#include <limits.h>
#include <fcntl.h>
#include <errno.h>

#include "managed_group_client.h"
#include "carrier_impl.h"
#include "carrier_extension.h"
#include "hashtable_friends.h"
#include "carrier_error.h"
#include "packet.h"

struct ManagedGroupClient {
    Carrier *w;
    linked_hashtable_t *svrs;
    linked_hashtable_t *grps;
    linked_list_t *evs;
    sqlite3 *db;
};

typedef struct {
    pthread_mutex_t lock;
    enum {
        __SERVER_STATE_OUTOFSYNC,
        __SERVER_STATE_SYNCING,
        __SERVER_STATE_SYNCED,
        __SERVER_STATE_NOTANYLONGER
    } state;
    struct {
        bool is_on;
        char gid[CARRIER_MAX_ID_LEN + 1];
        uint64_t join_at_ver;
    } join_mode;
    char id[CARRIER_MAX_ID_LEN + 1];
    uint32_t friend_number;
    linked_hash_entry_t he;
    uint64_t ver;
    linked_list_t *pending_reqs;
    linked_list_t *ongoing_reqs;
} server_t;

typedef struct {
    linked_hash_entry_t he;
    bool is_joining;
    server_t *svr;
    char id[CARRIER_MAX_ID_LEN + 1];
    char admin[CARRIER_MAX_ID_LEN + 1];
    char title[CARRIER_MAX_GROUP_TITLE_LEN + 1];
} group_t;

typedef struct request req_t;
typedef struct event event_t;
struct request {
    linked_list_entry_t le;
    int type;
    char gid[CARRIER_MAX_ID_LEN + 1];
    server_t *svr;
    void (*on_rsp)(Carrier *, req_t *, Packet *);
    void (*abort)(Carrier *, req_t *, int);
    void *bin;
    size_t len;
    void *usr_cb;
    void *usr_ctx;
};

typedef struct {
    req_t base;
} sync_req_t;

struct event {
    linked_list_entry_t le;
    void (*cb)(Carrier *, event_t *);
};

typedef struct {
    req_t base;
    char title[CARRIER_MAX_GROUP_TITLE_LEN + 1];
} new_req_t;

typedef struct {
    event_t base;
    new_req_t *req;
    int status;
} new_rsp_ev_t;

typedef struct {
    req_t base;
} leave_req_t;

typedef struct {
    event_t base;
    leave_req_t *req;
    int status;
} leave_rsp_ev_t;

typedef struct {
    req_t base;
    char peer_id[CARRIER_MAX_ID_LEN + 1];
} invite_req_t;

typedef struct {
    req_t base;
} join_req_t;

typedef struct {
    event_t base;
    join_req_t *req;
    int status;
} join_rsp_ev_t;

typedef struct {
    req_t base;
    char peer_id[CARRIER_MAX_ID_LEN + 1];
} kick_req_t;

typedef struct {
    event_t base;
    kick_req_t *req;
    int status;
} kick_rsp_ev_t;

typedef struct {
    req_t base;
    size_t len;
    char msg[0];
} msg_req_t;

typedef struct {
    event_t base;
    msg_req_t *req;
    int status;
} msg_rsp_ev_t;

typedef struct {
    req_t base;
    char title[CARRIER_MAX_GROUP_TITLE_LEN + 1];
} title_req_t;

typedef struct {
    event_t base;
    title_req_t *req;
    int status;
} title_rsp_ev_t;

typedef struct {
    req_t base;
    char name[CARRIER_MAX_USER_NAME_LEN + 1];
} name_req_t;

typedef struct {
    event_t base;
    name_req_t *req;
    int status;
} name_rsp_ev_t;

typedef struct {
    event_t base;
    char id[CARRIER_MAX_ID_LEN + 1];
} new_grp_ev_t;

typedef struct {
    event_t base;
    char id[CARRIER_MAX_ID_LEN + 1];
} dismiss_ev_t;

typedef struct {
    event_t base;
    char id[CARRIER_MAX_ID_LEN + 1];
    char title[CARRIER_MAX_GROUP_TITLE_LEN + 1];
} title_ev_t;

typedef struct {
    event_t base;
    char id[CARRIER_MAX_ID_LEN + 1];
    char peer_id[CARRIER_MAX_ID_LEN + 1];
} join_ev_t;

typedef struct {
    event_t base;
    char id[CARRIER_MAX_ID_LEN + 1];
    char peer_id[CARRIER_MAX_ID_LEN + 1];
} leave_ev_t;

typedef struct {
    event_t base;
    char id[CARRIER_MAX_ID_LEN + 1];
    char peer_id[CARRIER_MAX_ID_LEN + 1];
} kick_ev_t;

typedef struct {
    event_t base;
    char id[CARRIER_MAX_ID_LEN + 1];
    char peer_id[CARRIER_MAX_ID_LEN + 1];
    char name[CARRIER_MAX_USER_NAME_LEN + 1];
} name_ev_t;

typedef struct {
    event_t base;
    char id[CARRIER_MAX_ID_LEN + 1];
    char peer_id[CARRIER_MAX_ID_LEN + 1];
    size_t len;
    char msg[0];
} msg_ev_t;

typedef struct {
    event_t base;
    char id[CARRIER_MAX_ID_LEN + 1];
    CarrierManagedGroupStatus stat;
} stat_ev_t;

#define NOT_A_VER (0)

static void *__list_pop_head(linked_list_t *list)
{
    return linked_list_is_empty(list) ? NULL : linked_list_pop_head(list);
}

static void __db_deinit(ManagedGroupClient *client)
{
    sqlite3_close(client->db);
    sqlite3_shutdown();
}

static void __ext_cleanup(Carrier *w);
static void __client_dtor(void *obj)
{
    ManagedGroupClient *client = obj;

    __ext_cleanup(client->w);

    if (client->evs)
        deref(client->evs);

    if (client->grps)
        deref(client->grps);

    if (client->svrs)
        deref(client->svrs);

    __db_deinit(client);
}

static int __db_init(ManagedGroupClient *client, Carrier *w)
{
    char db_path[PATH_MAX];
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    rc = mkdirs(w->pref.data_location, S_IRWXU);
    if (rc < 0)
        return CARRIER_SYS_ERROR(errno);

    sqlite3_initialize();

    snprintf(db_path, sizeof(db_path), "%s/mgrp_client.sqlite3", w->pref.data_location);
    rc = sqlite3_open_v2(db_path, &client->db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                         NULL);
    if (rc) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    /* ================================= stmt-sep ================================= */
    sql = "PRAGMA foreign_keys = ON";
    rc = sqlite3_prepare_v2(client->db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS servers ("
          "  server_id TEXT    PRIMARY KEY,"
          "  version   INTEGER NOT NULL DEFAULT 0"
          ")";
    rc = sqlite3_prepare_v2(client->db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS groups ("
          "  group_id  TEXT PRIMARY KEY,"
          "  server_id TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,"
          "  admin_id  TEXT NOT NULL,"
          "  title     TEXT NOT NULL,"
          "  joining   BOOLEAN NOT NULL"
          ")";
    rc = sqlite3_prepare_v2(client->db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS peers ("
          "  group_id  TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,"
          "  peer_id   TEXT NOT NULL,"
          "  peer_name TEXT NOT NULL,"
          "  PRIMARY KEY(group_id, peer_id)"
          ")";
    rc = sqlite3_prepare_v2(client->db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    /* ================================= stmt-sep ================================= */
    sql = "DELETE FROM groups WHERE joining = 1";
    rc = sqlite3_prepare_v2(client->db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_deinit(client);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    return 0;
}

static int __db_get_svrs(ManagedGroupClient *client,
                         int (*cb)(ManagedGroupClient *,
                                                  const char *svr_id,
                                                  uint64_t ver))
{
    sqlite3 *db = client->db;
    sqlite3_stmt *stmt;
    char *sql;
    int rc;

    sql = "SELECT server_id, version FROM servers";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int err = cb(client,
                     (const char *)sqlite3_column_text(stmt, 0),
                     sqlite3_column_int64(stmt, 1));
        if (err) {
            sqlite3_finalize(stmt);
            return err;
        }
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
}

static void __svr_dtor(void *obj)
{
    server_t *svr = obj;

    pthread_mutex_destroy(&svr->lock);
    deref(svr->pending_reqs);
    deref(svr->ongoing_reqs);
}

static server_t *__server_create(const FriendInfo *fi, uint64_t ver)
{
    server_t *svr;

    svr = rc_zalloc(sizeof(*svr), __svr_dtor);
    if (!svr)
        return NULL;

    pthread_mutex_init(&svr->lock, NULL);

    svr->pending_reqs = linked_list_create(0, NULL);
    if (!svr->pending_reqs) {
        deref(svr);
        return NULL;
    }

    svr->ongoing_reqs = linked_list_create(0, NULL);
    if (!svr->ongoing_reqs) {
        deref(svr);
        return NULL;
    }

    strcpy(svr->id, fi->info.user_info.userid);
    svr->friend_number = fi->friend_number;
    svr->ver = ver;

    svr->he.data = svr;
    svr->he.key = svr->id;
    svr->he.keylen = strlen(svr->id);

    return svr;
}

static int __load_svr(ManagedGroupClient *client, const char *svr_id, uint64_t ver)
{
    server_t *svr;
    FriendInfo *fi;
    uint32_t friend_number;
    int rc;

    rc = get_friend_number(client->w, svr_id, &friend_number);
    if (rc < 0)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    fi = friends_get(client->w->friends, friend_number);
    if (!fi)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    svr = __server_create(fi, ver);
    deref(fi);
    if (!svr)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    linked_hashtable_put(client->svrs, &svr->he);
    deref(svr);

    return 0;
}

static int __db_get_svr_grps(ManagedGroupClient *client,
                             server_t *svr,
                             int (*cb)(ManagedGroupClient *, server_t *,
                                       const char *grp_id, const char *admin,
                                       const char *title))
{
    sqlite3 *db = client->db;
    sqlite3_stmt *stmt;
    char *sql;
    int rc;

    sql = "SELECT group_id, admin_id, title FROM groups WHERE server_id = :server_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":server_id"),
                           svr->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int err = cb(client, svr,
                     (const char *)sqlite3_column_text(stmt, 0),
                     (const char *)sqlite3_column_text(stmt, 1),
                     (const char *)sqlite3_column_text(stmt, 2));
        if (err) {
            sqlite3_finalize(stmt);
            return err;
        }
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
}

static void __group_dtor(void *obj)
{
    group_t *grp = obj;

    deref(grp->svr);
}

static group_t *__group_create(server_t *svr, const char *id, const char *admin_id,
                               const char *title, bool is_joining)
{
    group_t *grp;

    grp = rc_zalloc(sizeof(*grp), __group_dtor);
    if (!grp)
        return NULL;

    grp->svr = ref(svr);
    strcpy(grp->id, id);
    strcpy(grp->admin, admin_id);
    strcpy(grp->title, title);
    grp->is_joining = is_joining;

    grp->he.data = grp;
    grp->he.key = grp->id;
    grp->he.keylen = strlen(grp->id);

    return grp;
}

static int __load_grp(ManagedGroupClient *client,
                      server_t *svr,
                      const char *grp_id, const char *admin,
                      const char *title)
{
    group_t *grp;

    grp = __group_create(svr, grp_id, admin, title, false);
    if (!grp)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    linked_hashtable_put(client->grps, &grp->he);
    deref(grp);

    return 0;
}

static int __db_load(ManagedGroupClient *client)
{
    int rc;
    server_t *svr;

    rc = __db_get_svrs(client, __load_svr);
    if (rc < 0)
        return rc;

    hashtable_foreach(client->svrs, svr, {
        rc = __db_get_svr_grps(client, svr, __load_grp);
        if (rc < 0)
            return rc;
    });

    return 0;
}

static void *__enc_rsp(int rc, uint64_t ver, size_t *len)
{
    Packet *cp;
    void *rsp;

    cp = packet_create(PACKET_TYPE_MGRP_RESP, NULL);
    if (!cp)
        return NULL;

    packet_set_status(cp, rc);
    packet_set_ver(cp, ver);

    rsp = packet_encode(cp, len);
    packet_free(cp);

    return rsp;
}

static const char *__ext_name = "managed-group-client";
static void __ext_reply(Carrier *w, const char *to, int status)
{
    char *ext_to;
    void *rsp;
    size_t len;

    ext_to = (char *)alloca(CARRIER_MAX_ID_LEN + strlen(__ext_name) + 2);
    strcpy(ext_to, to);
    strcat(ext_to, ":");
    strcat(ext_to, __ext_name);

    rsp = __enc_rsp(status, NOT_A_VER, &len);
    if (!rsp)
        return;

    carrier_reply_friend_invite(w, ext_to, NULL, 0, NULL, rsp, len);
    free(rsp);
}

static void __ext_on_friend_invite(Carrier *w, const char *from, const char *bundle,
                                   const void *data, size_t len, void *context)
{
    const char *grp_id;
    const char *svr_id;
    const char *title;
    Packet *cp;

    cp = packet_decode(data, len);
    if (!cp) {
        __ext_reply(w, from, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_INVITE_REQ) {
        __ext_reply(w, from, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        packet_free(cp);
        return;
    }

    grp_id = packet_get_group_id(cp);
    svr_id = packet_get_server_id(cp);
    title = packet_get_title(cp);

    if (!grp_id || !*grp_id || !is_valid_key(grp_id) || !svr_id ||
        !*svr_id || !is_valid_key(svr_id) || !title || !*title ||
        strlen(title) > CARRIER_MAX_GROUP_TITLE_LEN) {
        __ext_reply(w, from, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        packet_free(cp);
        return;
    }

    if (!w->callbacks.managed_group_invite) {
        __ext_reply(w, from, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        packet_free(cp);
        return;
    }

    w->callbacks.managed_group_invite(w, grp_id, from, svr_id, title, w->context);
    __ext_reply(w, from, 0);

    packet_free(cp);
}

static int __ext_init(Carrier *w)
{
    CarrierCallbacks cbs;
    CarrierExtension *ext;
    int rc;

    ext = (CarrierExtension *)rc_zalloc(sizeof(*ext), NULL);
    if (!ext)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    memset(&cbs, 0, sizeof(cbs));
    cbs.friend_invite = __ext_on_friend_invite;

    ext->carrier = w;

    rc = carrier_register_extension(w, __ext_name, ext, &cbs);
    if (rc != 0)
        deref(ext);

    return 0;
}

void __ext_on_friend_invite_reply(Carrier *w, const char *from, const char *bundle,
                                  int status, const char *reason,
                                  const void *data, size_t len,
                                  void *context)
{
    invite_req_t *req = context;
    Packet *cp;

    if (!data) {
        req->base.on_rsp(w, &req->base, NULL);
        deref(req);
        return;
    }

    cp = packet_decode(data, len);
    if (!cp) {
        req->base.on_rsp(w, &req->base, NULL);
        deref(req);
        return;
    }

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_RESP) {
        req->base.on_rsp(w, &req->base, NULL);
        deref(req);
        packet_free(cp);
        return;
    }

    req->base.on_rsp(w, &req->base, cp);
    deref(req);
    packet_free(cp);
}

static invite_req_t *__invite_req_create(group_t *grp, const char *peer_id,
                                         void *usr_cb, void *usr_ctx);
static int __ext_invite(Carrier *w, const char *friend_id, group_t *grp,
                        CarrierManagedGroupInviteCallback *cb, void *ctx)
{
    invite_req_t *req;
    char *ext_to;
    int rc;

    req = __invite_req_create(grp, friend_id, cb, ctx);
    if (!req)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    ext_to = (char *)alloca(CARRIER_MAX_ID_LEN + strlen(__ext_name) + 2);
    strcpy(ext_to, friend_id);
    strcat(ext_to, ":");
    strcat(ext_to, __ext_name);

    rc = carrier_invite_friend(w, ext_to, NULL, req->base.bin, req->base.len,
                           __ext_on_friend_invite_reply, req);
    if (rc < 0)
        deref(req);

    return rc;
}

static void __ext_cleanup(Carrier *w)
{
    CarrierExtension *ext;

    if (!w)
        return;

    ext = carrier_get_extension(w, __ext_name);
    if (!ext)
        return;

    carrier_unregister_extension(w, __ext_name);
    deref(ext);
}

ManagedGroupClient *managed_group_client_create(Carrier *w)
{
    ManagedGroupClient *client;
    int rc;

    client = rc_zalloc(sizeof(*client), __client_dtor);
    if (!client)
        return NULL;

    client->w = w;

    client->evs = linked_list_create(1, NULL);
    if (!client->evs) {
        deref(client);
        return NULL;
    }

    client->grps = linked_hashtable_create(0, 1, NULL, NULL);
    if (!client->grps) {
        deref(client);
        return NULL;
    }

    client->svrs = linked_hashtable_create(0, 1, NULL, NULL);
    if (!client->svrs) {
        deref(client);
        return NULL;
    }

    rc = __db_init(client, w);
    if (rc < 0) {
        deref(client);
        return NULL;
    }

    rc = __db_load(client);
    if (rc < 0) {
        deref(client);
        return NULL;
    }

    rc = __ext_init(w);
    if (rc < 0) {
        deref(client);
        return NULL;
    }

    return client;
}

static void __svr_send_reqs(Carrier *w, server_t *svr)
{
    req_t *req;
    int rc;

    pthread_mutex_lock(&svr->lock);

    list_foreach(svr->pending_reqs, req, {
        rc = dht_friend_message(&w->dht, svr->friend_number, req->bin, req->len, 0);
        if (rc < 0)
            list_foreach_break;

        list_foreach_remove_cur_entry();
        linked_list_push_tail(svr->ongoing_reqs, &req->le);
    });

    pthread_mutex_unlock(&svr->lock);
}

static void __send_reqs(ManagedGroupClient *client)
{
    server_t *svr;

    hashtable_foreach(client->svrs, svr, {
        __svr_send_reqs(client->w, svr);
    });
}

static void __dispatch_evs(ManagedGroupClient *client)
{
    event_t *ev;

    list_foreach(client->evs, ev, {
        list_foreach_remove_cur_entry();
        ev->cb(client->w, ev);
    });
}

void managed_group_client_do_backgroud_routine(ManagedGroupClient *client)
{
    __send_reqs(client);
    __dispatch_evs(client);
}

static void __grp_stat_cb(Carrier *w, event_t *base)
{
    stat_ev_t *ev = (stat_ev_t *)base;

    if (w->callbacks.managed_group_callbacks.group_status)
        w->callbacks.managed_group_callbacks.group_status(w, ev->id, ev->stat, w->context);
}

static stat_ev_t *__create_grp_stat_ev(Carrier *w,
                                       const char *grp_id,
                                       CarrierManagedGroupStatus stat)
{
    stat_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), NULL);
    if (!ev)
        return NULL;

    ev->base.cb = __grp_stat_cb;
    ev->base.le.data = ev;
    strcpy(ev->id, grp_id);
    ev->stat = stat;

    return ev;
}

static int __create_svr_grps_stat_evs(ManagedGroupClient *client, server_t *svr,
                                      CarrierManagedGroupStatus stat, linked_list_t **evs)
{
    stat_ev_t *ev;
    linked_list_t *__evs;
    group_t *grp;

    assert(!svr->join_mode.is_on);

    __evs = linked_list_create(0, NULL);
    if (!__evs)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    hashtable_foreach(client->grps, grp, {
        if (grp->svr != svr)
            continue;

        ev = __create_grp_stat_ev(client->w, grp->id, stat);
        if (!ev) {
            deref(__evs);
            return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
        }

        linked_list_push_tail(__evs, &ev->base.le);
        deref(ev);
    });

    *evs = __evs;

    return 0;
}

static void __svr_set_out_of_sync(ManagedGroupClient *c, server_t *svr, int rc);
void managed_group_client_end_backgroud_routine(ManagedGroupClient *client)
{
    server_t *svr;

    hashtable_foreach(client->svrs, svr, {
        pthread_mutex_lock(&svr->lock);
        if (svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED)
            __svr_set_out_of_sync(client, svr, CARRIER_GENERAL_ERROR(ERROR_FRIEND_OFFLINE));
        pthread_mutex_unlock(&svr->lock);
    });

    __dispatch_evs(client);
}

static void __sync_req_on_rsp(Carrier *w, req_t *base, Packet *cp)
{
    sync_req_t *req = (sync_req_t *)base;
    server_t *svr = req->base.svr;
    linked_list_t *evs;
    event_t *ev;
    int rc;

    assert(svr->state == __SERVER_STATE_SYNCING);

    if (svr->join_mode.is_on) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_RESP) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    rc = packet_get_status(cp);
    if (rc < 0) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    rc = __create_svr_grps_stat_evs(w->mgrp_client, svr, CarrierManagedGroupStatus_Synced, &evs);
    if (rc < 0) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    list_foreach(evs, ev, {
        list_foreach_remove_cur_entry();
        linked_list_push_tail(w->mgrp_client->evs, &ev->le);
    });

    svr->state = __SERVER_STATE_SYNCED;

    deref(evs);
}

static int __db_del_grp(sqlite3 *db, const char *gid)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "DELETE FROM groups WHERE group_id = :group_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           gid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE )
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    return 0;
}

static int __notify_svr_grps_out_of_sync(ManagedGroupClient *c, server_t *svr)
{
    linked_list_t *evs;
    event_t *ev;
    int rc;

    assert(svr->state == __SERVER_STATE_OUTOFSYNC && !svr->join_mode.is_on);

    rc = __create_svr_grps_stat_evs(c->w->mgrp_client, svr,
                                    CarrierManagedGroupStatus_OutOfSync,
                                    &evs);
    if (rc < 0)
        return rc;

    list_foreach(evs, ev, {
        list_foreach_remove_cur_entry();
        linked_list_push_tail(c->evs, &ev->le);
    });

    deref(evs);

    return 0;
}

static void __send_reset()
{
    // TODO
}

static void __sync_req_abort(Carrier *w, req_t *base, int status)
{
    sync_req_t *req = (sync_req_t *)base;
    server_t *svr = req->base.svr;

    assert(svr->state == __SERVER_STATE_SYNCING);
    assert(linked_list_is_empty(svr->pending_reqs));
    assert(linked_list_is_empty(svr->ongoing_reqs));

    if (svr->join_mode.is_on) {
        if (__db_del_grp(w->mgrp_client->db, svr->join_mode.gid) < 0)
            abort();

        deref(linked_hashtable_remove(w->mgrp_client->grps, svr->join_mode.gid,
                               strlen(svr->join_mode.gid)));

        svr->join_mode.is_on = false;
    }

    __send_reset();

    svr->state = __SERVER_STATE_OUTOFSYNC;

    if (__notify_svr_grps_out_of_sync(w->mgrp_client, svr) < 0)
        abort();
}

static void __req_dtor(void *obj)
{
    req_t *req = obj;

    deref(req->svr);

    if (req->bin)
        free(req->bin);
}

static sync_req_t *__sync_req_create(server_t *svr)
{
    sync_req_t *req;
    Packet *cp;

    req = rc_zalloc(sizeof(*req), __req_dtor);
    if (!req)
        return NULL;

    req->base.type = PACKET_TYPE_MGRP_SYNC_REQ;
    cp = packet_create(req->base.type, NULL);
    if (!cp) {
        deref(req);
        return NULL;
    }

    packet_set_ver(cp, svr->ver);

    req->base.bin = packet_encode(cp, &req->base.len);
    packet_free(cp);
    if (!req->base.bin) {
        deref(req);
        return NULL;
    }

    req->base.le.data = req;
    req->base.on_rsp = __sync_req_on_rsp;
    req->base.abort = __sync_req_abort;
    req->base.svr = ref(svr);

    return req;
}

static server_t *__server_get(ManagedGroupClient *c, const char *sid)
{
    return linked_hashtable_get(c->svrs, sid, strlen(sid));
}

void managed_group_client_handle_server_connected(ManagedGroupClient *client, const char *server_id)
{
    sync_req_t *req;
    server_t *svr;
    linked_list_t *evs;
    event_t *ev;
    int rc;

    svr = __server_get(client, server_id);
    if (!svr)
        return;

    pthread_mutex_lock(&svr->lock);

    assert(svr->state == __SERVER_STATE_OUTOFSYNC || svr->state == __SERVER_STATE_NOTANYLONGER);

    if (svr->state == __SERVER_STATE_NOTANYLONGER) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        return;
    }

    req = __sync_req_create(svr);
    if (!req) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        return;
    }

    rc = __create_svr_grps_stat_evs(client, svr, CarrierManagedGroupStatus_Syncing, &evs);
    if (rc < 0) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        deref(req);
        return;
    }

    svr->state = __SERVER_STATE_SYNCING;

    linked_list_push_tail(svr->pending_reqs, &req->base.le);
    deref(req);

    list_foreach(evs, ev, {
        list_foreach_remove_cur_entry();
        linked_list_push_tail(client->evs, &ev->le);
    });
    deref(evs);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);
}

static void __svr_set_out_of_sync(ManagedGroupClient *c, server_t *svr, int rc)
{
    req_t *req;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    if ((req = __list_pop_head(svr->ongoing_reqs)) ||
        (req = __list_pop_head(svr->pending_reqs))) {
        req->abort(c->w, req, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(req);
        return;
    }

    assert(svr->state == __SERVER_STATE_SYNCED && !svr->join_mode.is_on);

    __send_reset();

    svr->state = __SERVER_STATE_OUTOFSYNC;

    if (__notify_svr_grps_out_of_sync(c, svr) < 0)
        abort();
}

void managed_group_client_handle_server_disconnected(ManagedGroupClient *client, const char *server_id)
{
    server_t *svr;

    svr = __server_get(client, server_id);
    if (!svr)
        return;

    pthread_mutex_lock(&svr->lock);

    if (svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED)
        __svr_set_out_of_sync(client, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));

    pthread_mutex_unlock(&svr->lock);
    deref(svr);
}

static int __db_upd_title(sqlite3 *db, const char *gid, const char *title)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "UPDATE groups"
          "  SET title = :title"
          "  WHERE group_id = :group_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":title"),
                           title, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           gid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    return 0;
}

static int __db_del_peer(sqlite3 *db, const char *gid, const char *peer_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "DELETE FROM peers WHERE group_id = :group_id AND peer_id = :peer_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           gid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           peer_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    return 0;
}

static int __db_store_svr(sqlite3 *db, server_t *svr)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "INSERT INTO servers(server_id) VALUES (:server_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":server_id"),
                           svr->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    return 0;
}

static int __server_exist(ManagedGroupClient *c, const char *sid)
{
    return linked_hashtable_exist(c->svrs, sid, strlen(sid));
}

int carrier_managed_group_mark_as_server(Carrier *w, const char *friend_id)
{
    uint32_t friend_number;
    sync_req_t *req = NULL;
    FriendInfo *fi;
    server_t *svr;
    int rc;

    if (!w || !friend_id || !*friend_id) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(friend_id)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_friend_number(w, friend_id, &friend_number);
    if (rc < 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    if (__server_exist(w->mgrp_client, friend_id)) {
        deref(fi);
        return 0;
    }

    svr = __server_create(fi, NOT_A_VER);
    deref(fi);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    if (fi->info.status == CarrierConnectionStatus_Connected) {
        req = __sync_req_create(svr);
        if (!req) {
            deref(svr);
            return -1;
        }
    }

    rc = __db_store_svr(w->mgrp_client->db, svr);
    if (rc < 0) {
        deref(svr);
        deref(req);
        carrier_set_error(rc);
        return -1;
    }

    if (req) {
        linked_list_push_tail(svr->pending_reqs, &req->base.le);
        svr->state = __SERVER_STATE_SYNCING;
        deref(req);
    }

    linked_hashtable_put(w->mgrp_client->svrs, &svr->he);
    deref(svr);

    return 0;
}

static int __db_del_svr(sqlite3 *db, server_t *svr)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "DELETE FROM servers WHERE server_id = :server_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":server_id"),
                           svr->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    return 0;
}

int carrier_managed_group_unmark_server(Carrier *w, const char *server_id)
{
    server_t *svr;
    group_t *grp;
    int rc;

    if (!w || !server_id || !*server_id) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(server_id)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __server_get(w->mgrp_client, server_id);
    if (!svr)
        return 0;

    pthread_mutex_lock(&svr->lock);

    if (svr->state == __SERVER_STATE_NOTANYLONGER) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        return 0;
    }

    if (svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED)
        __svr_set_out_of_sync(w->mgrp_client, svr, ERROR_WRONG_STATE);

    rc = __db_del_svr(w->mgrp_client->db, svr);
    if (rc < 0) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(rc);
        return -1;
    }

    hashtable_foreach(w->mgrp_client->grps, grp, {
        if (grp->svr == svr)
            hashtable_foreach_remove_cur_entry();
    });

    deref(linked_hashtable_remove(w->mgrp_client->svrs, svr->id, strlen(svr->id)));

    svr->state = __SERVER_STATE_NOTANYLONGER;

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static inline char *__gen_group_id(char *id)
{
    size_t len = CARRIER_MAX_ID_LEN + 1;
    uint8_t pk[PUBLIC_KEY_BYTES];
    uint8_t sk[PUBLIC_KEY_BYTES];

    crypto_create_keypair(pk, sk);
    return base58_encode(pk, sizeof(pk), id, &len);
}

static void __new_grp_rsp_ev_dtor(void *obj)
{
    new_rsp_ev_t *ev = obj;

    deref(ev->req);
}

static void __new_grp_rsp_ev_cb(Carrier *w, event_t *base)
{
    new_rsp_ev_t *ev = (new_rsp_ev_t *)base;
    CarrierManagedGroupNewCallback *cb = ev->req->base.usr_cb;
    void *ctx = ev->req->base.usr_ctx;

    cb(w, ev->req->base.gid, ev->req->base.svr->id, ev->req->title, ev->status, ctx);
}

static new_rsp_ev_t *__create_new_grp_rsp_ev(Carrier *w, new_req_t *req, int status)
{
    new_rsp_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), __new_grp_rsp_ev_dtor);
    if (!ev)
        return NULL;

    ev->base.cb = __new_grp_rsp_ev_cb;
    ev->base.le.data = ev;
    ev->req = ref(req);
    ev->status = status;

    return ev;
}

static int __db_store_grp(sqlite3 *db, group_t *grp)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "INSERT INTO groups(group_id, server_id, admin_id, title, joining)"
          "  VALUES (:group_id, :server_id, :admin_id, :title, :joining)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":server_id"),
                           grp->svr->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":admin_id"),
                           grp->admin, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":title"),
                           grp->title, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":joining"),
                          grp->is_joining ? 1 : 0);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    return 0;
}

static int __group_exist(ManagedGroupClient *c, const char *gid)
{
    return linked_hashtable_exist(c->grps, gid, strlen(gid));
}

static int __db_begin(sqlite3 *db)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    return 0;
}

static int __db_upd_svr_ver(sqlite3 *db, const char *sid, uint64_t ver)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "UPDATE servers SET version = :version WHERE server_id = :server_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":version"),
                            ver);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":server_id"),
                           sid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    return 0;
}

static int __db_end(sqlite3 *db)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "END";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    return 0;
}

static void __db_rollback(sqlite3 *db)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "ROLLBACK";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        abort();

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        abort();
}

static int __db_store_peer(sqlite3 *db, const char *gid, const char *peer_id, const char *name)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "INSERT INTO peers(group_id, peer_id, peer_name)"
          "  VALUES (:group_id, :peer_id, :peer_name)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           gid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           peer_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":peer_name"),
                           name, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    return 0;
}

static void __new_grp_req_on_rsp(Carrier *w, req_t *base, Packet *cp)
{
    new_req_t *req = (new_req_t *)base;
    sqlite3 *db = w->mgrp_client->db;
    server_t *svr = req->base.svr;
    const char *name;
    new_rsp_ev_t *ev;
    group_t *grp;
    uint64_t ver;
    int rc;

    assert(svr->state == __SERVER_STATE_SYNCED && !svr->join_mode.is_on);

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_NEW_RESP) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    rc = packet_get_status(cp);
    if (rc < 0) {
        ev = __create_new_grp_rsp_ev(w, req, rc);
        if (!ev) {
            base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
        deref(ev);

        return;
    }

    ver = packet_get_ver(cp);
    name = packet_get_name(cp);
    if (ver <= svr->ver || !name || strlen(name) > CARRIER_MAX_USER_NAME_LEN) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (__group_exist(w->mgrp_client, req->base.gid)) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    grp = __group_create(svr, req->base.gid, w->me.userid, req->title, false);
    if (!grp) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    ev = __create_new_grp_rsp_ev(w, req, 0);
    if (!ev) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(grp);
        return;
    }

    if (__db_begin(db) < 0 ||
        __db_store_grp(db, grp) < 0 ||
        __db_store_peer(db, req->base.gid, w->me.userid, name) < 0 ||
        __db_upd_svr_ver(db, svr->id, ver) < 0 ||
        __db_end(db) < 0) {
        __db_rollback(db);
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(grp);
        deref(ev);
        return;
    }

    linked_hashtable_put(w->mgrp_client->grps, &grp->he);
    deref(grp);
    svr->ver = ver;

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);
}

static void __new_grp_req_abort(Carrier *w, req_t *base, int status)
{
    new_req_t *req = (new_req_t *)base;
    new_rsp_ev_t *ev;

    assert(base->svr->state == __SERVER_STATE_SYNCED && !base->svr->join_mode.is_on);

    ev = __create_new_grp_rsp_ev(w, req, status);
    if (!ev)
        abort();

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);

    __svr_set_out_of_sync(w->mgrp_client, base->svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
}

static new_req_t *__new_grp_req_create(server_t *svr, const char *id, const char *title,
                                       void *usr_cb, void *usr_ctx)
{
    new_req_t *req;
    Packet *cp;

    req = rc_zalloc(sizeof(*req), __req_dtor);
    if (!req)
        return NULL;

    req->base.type = PACKET_TYPE_MGRP_NEW_REQ;
    cp = packet_create(req->base.type, NULL);
    if (!cp) {
        deref(req);
        return NULL;
    }

    packet_set_group_id(cp, id);
    packet_set_title(cp, title);

    req->base.bin = packet_encode(cp, &req->base.len);
    packet_free(cp);
    if (!req->base.bin) {
        deref(req);
        return NULL;
    }

    req->base.le.data = req;
    strcpy(req->base.gid, id);
    req->base.svr = ref(svr);
    req->base.on_rsp = __new_grp_req_on_rsp;
    req->base.abort = __new_grp_req_abort;
    req->base.usr_cb = usr_cb;
    req->base.usr_ctx = usr_ctx;
    strcpy(req->title, title);

    return req;
}

int carrier_managed_group_new(Carrier *w, const char *server_id, const char *title,
                              CarrierManagedGroupNewCallback *callback, void *context, char *group_id)
{
    new_req_t *req;
    server_t *svr;
    char gid[CARRIER_MAX_ID_LEN + 1];

    if (!w || !server_id || !*server_id || !title ||
        !*title || strlen(title) > CARRIER_MAX_GROUP_TITLE_LEN || !callback || !group_id) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(server_id)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __server_get(w->mgrp_client, server_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    req = __new_grp_req_create(svr, __gen_group_id(gid), title, callback, context);
    if (!req) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    strcpy(group_id, gid);

    linked_list_push_tail(svr->pending_reqs, &req->base.le);
    deref(req);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static server_t *__get_svr_by_gid(Carrier *w, const char *group_id)
{
    group_t *grp;
    server_t *svr;

    grp = linked_hashtable_get(w->mgrp_client->grps, group_id, strlen(group_id));
    if (!grp)
        return NULL;

    svr = ref(grp->svr);
    assert(svr);

    deref(grp);

    return svr;
}

static void __leave_rsp_ev_dtor(void *obj)
{
    leave_rsp_ev_t *ev = obj;

    deref(ev->req);
}

static void __leave_rsp_ev_cb(Carrier *w, event_t *base)
{
    leave_rsp_ev_t *ev = (leave_rsp_ev_t *)base;
    CarrierManagedGroupLeaveCallback *cb = ev->req->base.usr_cb;
    void *ctx = ev->req->base.usr_ctx;

    cb(w, ev->req->base.gid, ev->status, ctx);
}

static leave_rsp_ev_t *__create_leave_rsp_ev(Carrier *w, leave_req_t *req, int status)
{
    leave_rsp_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), __leave_rsp_ev_dtor);
    if (!ev)
        return NULL;

    ev->base.cb = __leave_rsp_ev_cb;
    ev->base.le.data = ev;
    ev->req = ref(req);
    ev->status = status;

    return ev;
}

static void __leave_req_on_rsp(Carrier *w, req_t *base, Packet *cp)
{
    leave_req_t *req = (leave_req_t *)base;
    sqlite3 *db = w->mgrp_client->db;
    server_t *svr = req->base.svr;
    stat_ev_t *grp_stat_ev;
    leave_rsp_ev_t *ev;
    uint64_t ver;
    int rc;

    assert(svr->state == __SERVER_STATE_SYNCED && !svr->join_mode.is_on);

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_RESP) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    rc = packet_get_status(cp);
    if (rc < 0) {
        ev = __create_leave_rsp_ev(w, req, rc);
        if (!ev) {
            base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
        deref(ev);
        return;
    }

    ver = packet_get_ver(cp);
    if (ver <= svr->ver) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (!__group_exist(w->mgrp_client, req->base.gid)) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    ev = __create_leave_rsp_ev(w, req, 0);
    if (!ev) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    grp_stat_ev = __create_grp_stat_ev(w, req->base.gid, CarrierManagedGroupStatus_OutOfSync);
    if (!grp_stat_ev) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(ev);
        return;
    }

    if (__db_begin(db) < 0 ||
        __db_del_grp(db, req->base.gid) < 0 ||
        __db_upd_svr_ver(db, svr->id, ver) < 0 ||
        __db_end(db) < 0) {
        __db_rollback(db);
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(ev);
        deref(grp_stat_ev);
        return;
    }

    deref(linked_hashtable_remove(w->mgrp_client->grps, req->base.gid, strlen(req->base.gid)));
    svr->ver = ver;

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);

    linked_list_push_tail(w->mgrp_client->evs, &grp_stat_ev->base.le);
    deref(grp_stat_ev);
}

static void __leave_req_abort(Carrier *w, req_t *base, int status)
{
    leave_req_t *req = (leave_req_t *)base;
    leave_rsp_ev_t *ev;

    assert(base->svr->state == __SERVER_STATE_SYNCED && !base->svr->join_mode.is_on);

    ev = __create_leave_rsp_ev(w, req, status);
    if (!ev)
        abort();

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);

    __svr_set_out_of_sync(w->mgrp_client, base->svr, status);
}

static leave_req_t *__leave_req_create(server_t *svr, const char *gid, void *usr_cb, void *usr_ctx)
{
    leave_req_t *req;
    Packet *cp;

    req = rc_zalloc(sizeof(*req), __req_dtor);
    if (!req)
        return NULL;

    req->base.type = PACKET_TYPE_MGRP_LEAVE_REQ;
    cp = packet_create(req->base.type, NULL);
    if (!cp) {
        deref(req);
        return NULL;
    }

    packet_set_group_id(cp, gid);

    req->base.bin = packet_encode(cp, &req->base.len);
    packet_free(cp);
    if (!req->base.bin) {
        deref(req);
        return NULL;
    }

    req->base.le.data = req;
    strcpy(req->base.gid, gid);
    req->base.svr = ref(svr);
    req->base.on_rsp = __leave_req_on_rsp;
    req->base.abort = __leave_req_abort;
    req->base.usr_cb = usr_cb;
    req->base.usr_ctx = usr_ctx;

    return req;
}

static group_t *__group_get(ManagedGroupClient *c, const char *gid)
{
    return linked_hashtable_get(c->grps, gid, strlen(gid));
}

int carrier_managed_group_leave(Carrier *w, const char *group_id,
                                CarrierManagedGroupLeaveCallback *callback, void *context)
{
    leave_req_t *req;
    server_t *svr;

    if (!w || !group_id || !*group_id || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    if (!__group_exist(w->mgrp_client, group_id)) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    req = __leave_req_create(svr, group_id, callback, context);
    if (!req) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    linked_list_push_tail(svr->pending_reqs, &req->base.le);
    deref(req);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static void __invite_req_on_rsp(Carrier *w, req_t *base, Packet *cp)
{
    invite_req_t *req = (invite_req_t *)base;
    CarrierManagedGroupInviteCallback *cb = req->base.usr_cb;

    cb(w, req->base.gid, req->peer_id,
       !cp ? CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE) : packet_get_status(cp),
       req->base.usr_ctx);
}

static invite_req_t *__invite_req_create(group_t *grp, const char *peer_id,
                                         void *usr_cb, void *usr_ctx)
{
    invite_req_t *req;
    Packet *cp;

    req = rc_zalloc(sizeof(*req), __req_dtor);
    if (!req)
        return NULL;

    req->base.type = PACKET_TYPE_MGRP_INVITE_REQ;
    cp = packet_create(req->base.type, NULL);
    if (!cp) {
        deref(req);
        return NULL;
    }

    packet_set_server_id(cp, grp->svr->id);
    packet_set_group_id(cp, grp->id);
    packet_set_title(cp, grp->title);

    req->base.bin = packet_encode(cp, &req->base.len);
    packet_free(cp);
    if (!req->base.bin) {
        deref(req);
        return NULL;
    }

    req->base.le.data = req;
    strcpy(req->base.gid, grp->id);
    req->base.svr = ref(grp->svr);
    req->base.on_rsp = __invite_req_on_rsp;
    req->base.usr_cb = usr_cb;
    req->base.usr_ctx = usr_ctx;

    strcpy(req->peer_id, peer_id);

    return req;
}

int carrier_managed_group_invite(Carrier *w, const char *group_id, const char *friend_id,
                                 CarrierManagedGroupInviteCallback *callback, void *context)
{
    server_t *svr;
    group_t *grp;
    uint32_t friend_number;
    int rc;

    if (!w || !group_id || !*group_id || !friend_id || !*friend_id || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(friend_id)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_friend_number(w, friend_id, &friend_number);
    if (rc < 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    grp = __group_get(w->mgrp_client, group_id);
    if (!grp) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    rc = __ext_invite(w, friend_id, grp, callback, context);
    deref(grp);
    if (rc < 0) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static void __join_rsp_ev_dtor(void *obj)
{
    join_rsp_ev_t *ev = obj;

    deref(ev->req);
}

static void join_rsp_ev_cb(Carrier *w, event_t *base)
{
    join_rsp_ev_t *ev = (join_rsp_ev_t *)base;
    CarrierManagedGroupJoinCallback *cb = ev->req->base.usr_cb;
    void *ctx = ev->req->base.usr_ctx;

    cb(w, ev->req->base.gid, ev->status, ctx);
}

static join_rsp_ev_t *__create_join_rsp_ev(Carrier *w,
                                           join_req_t *req,
                                           int status)
{
    join_rsp_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), __join_rsp_ev_dtor);
    if (!ev)
        return NULL;

    ev->base.cb = join_rsp_ev_cb;
    ev->base.le.data = ev;
    ev->req = ref(req);
    ev->status = status;

    return ev;
}

static void __join_req_on_rsp(Carrier *w, req_t *base, Packet *cp)
{
    join_req_t *req = (join_req_t *)base;
    server_t *svr = req->base.svr;
    uint64_t ver;
    int rc;

    assert(svr->state == __SERVER_STATE_SYNCED);

    if (svr->join_mode.is_on) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_RESP) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    rc = packet_get_status(cp);
    if (rc < 0) {
        join_rsp_ev_t *ev;

        ev = __create_join_rsp_ev(w, req, rc);
        if (!ev) {
            req->base.abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
        deref(ev);

        return;
    }

    ver = packet_get_ver(cp);
    if (ver <= svr->ver) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (__group_exist(w->mgrp_client, req->base.gid)) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    linked_list_push_head(svr->ongoing_reqs, &req->base.le);
    svr->join_mode.is_on = true;
    strcpy(svr->join_mode.gid, base->gid);
    svr->join_mode.join_at_ver = ver;
}

static void __join_req_abort(Carrier *w, req_t *base, int status)
{
    join_req_t *req = (join_req_t *)base;
    server_t *svr = base->svr;
    join_rsp_ev_t *ev;

    assert(base->svr->state == __SERVER_STATE_SYNCED);

    if (svr->join_mode.is_on) {
        if (__db_del_grp(w->mgrp_client->db, svr->join_mode.gid) < 0)
            abort();

        deref(linked_hashtable_remove(w->mgrp_client->grps, svr->join_mode.gid,
                               strlen(svr->join_mode.gid)));

        svr->join_mode.is_on = false;
    }

    ev = __create_join_rsp_ev(w, req, status);
    if (!ev)
        abort();

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);

    __svr_set_out_of_sync(w->mgrp_client, svr, status);
}

static join_req_t *__join_req_create(server_t *svr, const char *gid, void *usr_cb, void *usr_ctx)
{
    join_req_t *req;
    Packet *cp;

    req = rc_zalloc(sizeof(*req), __req_dtor);
    if (!req)
        return NULL;

    req->base.type = PACKET_TYPE_MGRP_JOIN_REQ;
    cp = packet_create(req->base.type, NULL);
    if (!cp) {
        deref(req);
        return NULL;
    }

    packet_set_group_id(cp, gid);

    req->base.bin = packet_encode(cp, &req->base.len);
    packet_free(cp);
    if (!req->base.bin) {
        deref(req);
        return NULL;
    }

    req->base.le.data = req;
    strcpy(req->base.gid, gid);
    req->base.svr = ref(svr);
    req->base.on_rsp = __join_req_on_rsp;
    req->base.abort = __join_req_abort;
    req->base.usr_cb = usr_cb;
    req->base.usr_ctx = usr_ctx;

    return req;
}

int carrier_managed_group_join(Carrier *w, const char *server_id, const char *group_id,
                               CarrierManagedGroupJoinCallback *callback, void *context)
{
    join_req_t *req;
    server_t *svr;
    uint32_t friend_number;
    int rc;

    if (!w || !server_id || !*server_id || !group_id || !*group_id || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(server_id)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_friend_number(w, server_id, &friend_number);
    if (rc < 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    svr = __server_get(w->mgrp_client, server_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    if (__group_exist(w->mgrp_client, group_id)) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_ALREADY_EXIST));
        return -1;
    }

    req = __join_req_create(svr, group_id, callback, context);
    if (!req) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    linked_list_push_tail(svr->pending_reqs, &req->base.le);
    deref(req);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static void __kick_rsp_ev_dtor(void *obj)
{
    kick_rsp_ev_t *ev = obj;

    deref(ev->req);
}

static void __kick_rsp_ev_cb(Carrier *w, event_t *base)
{
    kick_rsp_ev_t *ev = (kick_rsp_ev_t *)base;
    CarrierManagedGroupKickCallback *cb = ev->req->base.usr_cb;
    void *ctx = ev->req->base.usr_ctx;

    cb(w, ev->req->base.gid, ev->req->peer_id, ev->status, ctx);
}

static kick_rsp_ev_t *__create_kick_rsp_ev(Carrier *w, kick_req_t *req, int status)
{
    kick_rsp_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), __kick_rsp_ev_dtor);
    if (!ev)
        return NULL;

    ev->base.cb = __kick_rsp_ev_cb;
    ev->base.le.data = ev;
    ev->req = ref(req);
    ev->status = status;

    return ev;
}

static void __kick_req_on_rsp(Carrier *w, req_t *base, Packet *cp)
{
    kick_req_t *req = (kick_req_t *)base;
    sqlite3 *db = w->mgrp_client->db;
    server_t *svr = req->base.svr;
    kick_rsp_ev_t *ev;
    uint64_t ver;
    int rc;

    assert(svr->state == __SERVER_STATE_SYNCED && !svr->join_mode.is_on);

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_RESP) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    rc = packet_get_status(cp);
    if (rc < 0) {
        ev = __create_kick_rsp_ev(w, req, rc);
        if (!ev) {
            base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
        deref(ev);
        return;
    }

    ver = packet_get_ver(cp);
    if (ver <= svr->ver) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (!__group_exist(w->mgrp_client, req->base.gid)) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    ev = __create_kick_rsp_ev(w, req, 0);
    if (!ev) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (__db_begin(db) < 0 ||
        __db_del_peer(db, req->base.gid, req->peer_id) < 0 ||
        __db_upd_svr_ver(db, svr->id, ver) < 0 ||
        __db_end(db) < 0) {
        __db_rollback(db);
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(ev);
        return;
    }

    svr->ver = ver;

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);
}

static void __kick_req_abort(Carrier *w, req_t *base, int status)
{
    kick_req_t *req = (kick_req_t *)base;
    kick_rsp_ev_t *ev;

    assert(base->svr->state == __SERVER_STATE_SYNCED && !base->svr->join_mode.is_on);

    ev = __create_kick_rsp_ev(w, req, status);
    if (!ev)
        abort();

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);

    __svr_set_out_of_sync(w->mgrp_client, req->base.svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
}

static kick_req_t *__kick_req_create(server_t *svr, const char *gid, const char *peer_id,
                                     void *usr_cb, void *usr_ctx)
{
    kick_req_t *req;
    Packet *cp;

    req = rc_zalloc(sizeof(*req), __req_dtor);
    if (!req)
        return NULL;

    req->base.type = PACKET_TYPE_MGRP_KICK_REQ;
    cp = packet_create(req->base.type, NULL);
    if (!cp) {
        deref(req);
        return NULL;
    }

    packet_set_group_id(cp, gid);
    packet_set_peer_id(cp, peer_id);

    req->base.bin = packet_encode(cp, &req->base.len);
    packet_free(cp);
    if (!req->base.bin) {
        deref(req);
        return NULL;
    }

    req->base.le.data = req;
    strcpy(req->base.gid, gid);
    req->base.svr = ref(svr);
    req->base.on_rsp = __kick_req_on_rsp;
    req->base.abort = __kick_req_abort;
    req->base.usr_cb = usr_cb;
    req->base.usr_ctx = usr_ctx;

    strcpy(req->peer_id, peer_id);

    return req;
}

int carrier_managed_group_kick(Carrier *w, const char *group_id, const char *peer_id,
                               CarrierManagedGroupKickCallback *callback, void *context)
{
    kick_req_t *req;
    server_t *svr;
    group_t *grp;

    if (!w || !group_id || !*group_id || !peer_id || !*peer_id || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(peer_id) || strcmp(peer_id, w->me.userid) == 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    grp = __group_get(w->mgrp_client, group_id);
    if (!grp) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    if (strcmp(grp->admin, w->me.userid)) {
        pthread_mutex_unlock(&svr->lock);
        deref(grp);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }
    deref(grp);

    req = __kick_req_create(svr, group_id, peer_id, callback, context);
    if (!req) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    linked_list_push_tail(svr->pending_reqs, &req->base.le);
    deref(req);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static void __msg_rsp_ev_dtor(void *obj)
{
    msg_rsp_ev_t *ev = obj;

    deref(ev->req);
}

static void __msg_rsp_ev_cb(Carrier *w, event_t *base)
{
    msg_rsp_ev_t *ev = (msg_rsp_ev_t *)base;
    CarrierManagedGroupSendMessageCallback *cb = ev->req->base.usr_cb;
    void *ctx = ev->req->base.usr_ctx;

    cb(w, ev->req->base.gid, ev->req->msg, ev->req->len, ev->status, ctx);
}

static msg_rsp_ev_t *__create_msg_rsp_ev(Carrier *w, msg_req_t *req, int status)
{
    msg_rsp_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), __msg_rsp_ev_dtor);
    if (!ev)
        return NULL;

    ev->base.cb = __msg_rsp_ev_cb;
    ev->base.le.data = ev;
    ev->req = ref(req);
    ev->status = status;

    return ev;
}

static void __msg_req_on_rsp(Carrier *w, req_t *base, Packet *cp)
{
    msg_req_t *req = (msg_req_t *)base;
    server_t *svr = req->base.svr;
    msg_rsp_ev_t *ev;
    int rc;

    assert(svr->state == __SERVER_STATE_SYNCED && !svr->join_mode.is_on);

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_RESP) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    rc = packet_get_status(cp);
    if (rc < 0) {
        ev = __create_msg_rsp_ev(w, req, rc);
        if (!ev) {
            base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
        deref(ev);

        return;
    }

    if (!__group_exist(w->mgrp_client, req->base.gid)) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    ev = __create_msg_rsp_ev(w, req, 0);
    if (!ev) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);
}

static void __msg_req_abort(Carrier *w, req_t *base, int status)
{
    msg_req_t *req = (msg_req_t *)base;
    msg_rsp_ev_t *ev;

    assert(base->svr->state == __SERVER_STATE_SYNCED && !base->svr->join_mode.is_on);

    ev = __create_msg_rsp_ev(w, req, status);
    if (!ev)
        abort();

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);

    __svr_set_out_of_sync(w->mgrp_client, base->svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
}

static msg_req_t *__msg_req_create(server_t *svr, const char *gid, const void *msg, size_t len,
                                   void *usr_cb, void *usr_ctx)
{
    msg_req_t *req;
    Packet *cp;

    req = rc_zalloc(sizeof(*req) + len, __req_dtor);
    if (!req)
        return NULL;

    req->base.type = PACKET_TYPE_MGRP_MSG_REQ;
    cp = packet_create(req->base.type, NULL);
    if (!cp) {
        deref(req);
        return NULL;
    }

    packet_set_group_id(cp, gid);
    packet_set_raw_data(cp, msg, len);

    req->base.bin = packet_encode(cp, &req->base.len);
    packet_free(cp);
    if (!req->base.bin) {
        deref(req);
        return NULL;
    }

    req->len = len;
    memcpy(req->msg, msg, len);

    req->base.le.data = req;
    strcpy(req->base.gid, gid);
    req->base.svr = ref(svr);
    req->base.on_rsp = __msg_req_on_rsp;
    req->base.abort = __msg_req_abort;
    req->base.usr_cb = usr_cb;
    req->base.usr_ctx = usr_ctx;

    return req;
}

int carrier_managed_group_send_message(Carrier *w, const char *group_id,
                                       const void *message, size_t length,
                                       CarrierManagedGroupSendMessageCallback *callback, void *context)
{
    msg_req_t *req;
    server_t *svr;

    if (!w || !group_id || !*group_id || !message || !length ||
        length > CARRIER_MAX_APP_MESSAGE_LEN || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    if (!__group_exist(w->mgrp_client, group_id)) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    req = __msg_req_create(svr, group_id, message, length, callback, context);
    if (!req) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    linked_list_push_tail(svr->pending_reqs, &req->base.le);
    deref(req);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

int carrier_managed_group_get_server_id(Carrier *w, const char *group_id, char *server_id)
{
    server_t *svr;

    if (!w || !group_id || !*group_id || !server_id) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    strcpy(server_id, svr->id);

    deref(svr);

    return 0;
}

int carrier_managed_group_get_admin(Carrier *w, const char *group_id, char *admin_id)
{
    server_t *svr;
    group_t *grp;

    if (!w || !group_id || !*group_id || !admin_id) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    grp = __group_get(w->mgrp_client, group_id);
    if (!grp) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    strcpy(admin_id, grp->admin);
    deref(grp);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

int carrier_managed_group_get_title(Carrier *w, const char *group_id, char *title)
{
    server_t *svr;
    group_t *grp;

    if (!w || !group_id || !*group_id || !title) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    grp = __group_get(w->mgrp_client, group_id);
    if (!grp) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    strcpy(title, grp->title);
    deref(grp);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static void __title_rsp_ev_dtor(void *obj)
{
    title_rsp_ev_t *ev = obj;

    deref(ev->req);
}

static void __title_rsp_ev_cb(Carrier *w, event_t *base)
{
    title_rsp_ev_t *ev = (title_rsp_ev_t *)base;
    CarrierManagedGroupSetTitleCallback *cb = ev->req->base.usr_cb;
    void *ctx = ev->req->base.usr_ctx;

    cb(w, ev->req->base.gid, ev->req->title, ev->status, ctx);
}

static title_rsp_ev_t *__create_title_rsp_ev(Carrier *w,
                                             title_req_t *req,
                                             int status)
{
    title_rsp_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), __title_rsp_ev_dtor);
    if (!ev)
        return NULL;

    ev->base.cb = __title_rsp_ev_cb;
    ev->base.le.data = ev;
    ev->req = ref(req);
    ev->status = status;

    return ev;
}

static void __title_req_on_rsp(Carrier *w, req_t *base, Packet *cp)
{
    title_req_t *req = (title_req_t *)base;
    sqlite3 *db = w->mgrp_client->db;
    server_t *svr = req->base.svr;
    title_rsp_ev_t *ev;
    group_t *grp;
    uint64_t ver;
    int rc;

    assert(svr->state == __SERVER_STATE_SYNCED && !svr->join_mode.is_on);

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_RESP) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    rc = packet_get_status(cp);
    if (rc < 0) {
        ev = __create_title_rsp_ev(w, req, rc);
        if (!ev) {
            base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
        deref(ev);

        return;
    }

    ver = packet_get_ver(cp);
    if (ver <= svr->ver) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    grp = __group_get(w->mgrp_client, req->base.gid);
    if (!grp) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    ev = __create_title_rsp_ev(w, req, 0);
    if (!ev) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(grp);
        return;
    }

    if (__db_begin(db) < 0||
        __db_upd_title(db, req->base.gid, req->title) < 0 ||
        __db_upd_svr_ver(db, svr->id, ver) < 0 ||
        __db_end(db) < 0) {
        __db_rollback(db);
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(grp);
        deref(ev);
        return;
    }

    strcpy(grp->title, req->title);
    deref(grp);
    svr->ver = ver;

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);
}

static void __title_req_abort(Carrier *w, req_t *base, int status)
{
    title_req_t *req = (title_req_t *)base;
    title_rsp_ev_t *ev;

    ev = __create_title_rsp_ev(w, req, status);
    if (!ev)
        abort();

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);

    __svr_set_out_of_sync(w->mgrp_client, base->svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
}

static title_req_t *__title_req_create(server_t *svr, const char *gid, const char *title, void *usr_cb, void *usr_ctx)
{
    title_req_t *req;
    Packet *cp;

    req = rc_zalloc(sizeof(*req), __req_dtor);
    if (!req)
        return NULL;

    req->base.type = PACKET_TYPE_MGRP_SET_TITLE_REQ;
    cp = packet_create(req->base.type, NULL);
    if (!cp) {
        deref(req);
        return NULL;
    }

    packet_set_group_id(cp, gid);
    packet_set_title(cp, title);

    req->base.bin = packet_encode(cp, &req->base.len);
    packet_free(cp);
    if (!req->base.bin) {
        deref(req);
        return NULL;
    }

    req->base.le.data = req;
    strcpy(req->base.gid, gid);
    req->base.svr = ref(svr);
    req->base.on_rsp = __title_req_on_rsp;
    req->base.abort = __title_req_abort;
    req->base.usr_cb = usr_cb;
    req->base.usr_ctx = usr_ctx;

    strcpy(req->title, title);

    return req;
}

int carrier_managed_group_set_title(Carrier *w, const char *group_id, const char *title,
                                    CarrierManagedGroupSetTitleCallback *callback, void *context)
{
    title_req_t *req;
    server_t *svr;
    group_t *grp;

    if (!w || !group_id || !*group_id || !title ||
        strlen(title) > CARRIER_MAX_GROUP_TITLE_LEN || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    grp = __group_get(w->mgrp_client, group_id);
    if (!grp) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    if (strcmp(w->me.userid, grp->admin) || !strcmp(title, grp->title)) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        deref(grp);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }
    deref(grp);

    req = __title_req_create(svr, group_id, title, callback, context);
    if (!req) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    linked_list_push_tail(svr->pending_reqs, &req->base.le);
    deref(req);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static int __db_upd_name(sqlite3 *db, const char *gid, const char *pid, const char *name)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "UPDATE peers"
          "  SET peer_name = :name"
          "  WHERE group_id = :group_id AND peer_id = :peer_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":name"),
                           name, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           gid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           pid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    return 0;
}

static void __name_rsp_ev_dtor(void *obj)
{
    title_rsp_ev_t *ev = obj;

    deref(ev->req);
}

static void __name_rsp_ev_cb(Carrier *w, event_t *base)
{
    name_rsp_ev_t *ev = (name_rsp_ev_t *)base;
    CarrierManagedGroupSetNameCallback *cb = ev->req->base.usr_cb;
    void *ctx = ev->req->base.usr_ctx;

    cb(w, ev->req->base.gid, ev->req->name, ev->status, ctx);
}

static name_rsp_ev_t *__create_name_rsp_ev(Carrier *w, name_req_t *req, int status)
{
    name_rsp_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), __name_rsp_ev_dtor);
    if (!ev)
        return NULL;

    ev->base.cb = __name_rsp_ev_cb;
    ev->base.le.data = ev;
    ev->req = ref(req);
    ev->status = status;

    return ev;
}

static void __name_req_on_rsp(Carrier *w, req_t *base, Packet *cp)
{
    name_req_t *req = (name_req_t *)base;
    sqlite3 *db = w->mgrp_client->db;
    server_t *svr = req->base.svr;
    name_rsp_ev_t *ev;
    uint64_t ver;
    int rc;

    assert(svr->state == __SERVER_STATE_SYNCED && !svr->join_mode.is_on);

    if (packet_get_type(cp) != PACKET_TYPE_MGRP_RESP) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    rc = packet_get_status(cp);
    if (rc < 0) {
        ev = __create_name_rsp_ev(w, req, rc);
        if (!ev) {
            base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
        deref(ev);
        return;
    }

    ver = packet_get_ver(cp);
    if (ver <= svr->ver) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (!__group_exist(w->mgrp_client, req->base.gid)) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    ev = __create_name_rsp_ev(w, req, 0);
    if (!ev) {
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (__db_begin(db) < 0||
        __db_upd_name(db, req->base.gid, w->me.userid, req->name) < 0 ||
        __db_upd_svr_ver(db, svr->id, ver) < 0 ||
        __db_end(db) < 0) {
        __db_rollback(db);
        base->abort(w, base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(ev);
        return;
    }

    svr->ver = ver;

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);
}

static void __name_req_abort(Carrier *w, req_t *base, int status)
{
    name_req_t *req = (name_req_t *)base;
    name_rsp_ev_t *ev;

    ev = __create_name_rsp_ev(w, req, status);
    if (!ev)
        abort();

    linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
    deref(ev);

    __svr_set_out_of_sync(w->mgrp_client, base->svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
}

static name_req_t *__name_req_create(server_t *svr, const char *gid, const char *name, void *usr_cb, void *usr_ctx)
{
    name_req_t *req;
    Packet *cp;

    req = rc_zalloc(sizeof(*req), __req_dtor);
    if (!req)
        return NULL;

    req->base.type = PACKET_TYPE_MGRP_SET_NAME_REQ;
    cp = packet_create(req->base.type, NULL);
    if (!cp) {
        deref(req);
        return NULL;
    }

    packet_set_group_id(cp, gid);
    packet_set_name(cp, name);

    req->base.bin = packet_encode(cp, &req->base.len);
    packet_free(cp);
    if (!req->base.bin) {
        deref(req);
        return NULL;
    }

    req->base.le.data = req;
    strcpy(req->base.gid, gid);
    req->base.svr = ref(svr);
    req->base.on_rsp = __name_req_on_rsp;
    req->base.abort = __name_req_abort;
    req->base.usr_cb = usr_cb;
    req->base.usr_ctx = usr_ctx;

    strcpy(req->name, name);

    return req;
}

int carrier_managed_group_set_name(Carrier *w, const char *group_id, const char *name,
                                   CarrierManagedGroupSetNameCallback *callback, void *context)
{
    name_req_t *req;
    server_t *svr;

    if (!w || !group_id || !*group_id || !name ||
        strlen(name) > CARRIER_MAX_USER_NAME_LEN || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    if (!__group_exist(w->mgrp_client, group_id)) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    req = __name_req_create(svr, group_id, name, callback, context);
    if (!req) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    linked_list_push_tail(svr->pending_reqs, &req->base.le);
    deref(req);

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static int __db_get_peers(sqlite3 *db, const char *group_id,
                          CarrierManagedGroupPeersIterateCallback *callback,
                          void *ctx)
{
    sqlite3_stmt *stmt;
    char *sql;
    int rc;

    sql = "SELECT peer_id, peer_name FROM peers WHERE group_id = :group_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":group_id"),
                           group_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        CarrierGroupPeer peer;
        bool resume;

        strcpy(peer.userid, (const char *)sqlite3_column_text(stmt, 0));
        strcpy(peer.name, (const char *)sqlite3_column_text(stmt, 1));
        resume = callback(&peer, ctx);
        if (!resume) {
            sqlite3_finalize(stmt);
            return 0;
        }
    }

    if (rc == SQLITE_DONE)
        (void)callback(NULL, ctx);

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
}

int carrier_managed_group_get_peers(Carrier *w, const char *group_id,
                                    CarrierManagedGroupPeersIterateCallback *callback,
                                    void *context)
{
    server_t *svr;
    int rc;

    if (!w || !group_id || !*group_id || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    if (!__group_exist(w->mgrp_client, group_id)) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    rc = __db_get_peers(w->mgrp_client->db, group_id, callback, context);
    if (rc < 0) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(rc);
        return -1;
    }

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

static int __db_get_peer(sqlite3 *db, const char *group_id,
                         const char *peer_id, CarrierGroupPeer *peer)
{
    sqlite3_stmt *stmt;
    char *sql;
    int rc;

    sql = "SELECT peer_name FROM peers WHERE group_id = :group_id AND peer_id = :peer_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":group_id"),
                           group_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           peer_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST);
    }

    strcpy(peer->userid, peer_id);
    strcpy(peer->name, (const char *)sqlite3_column_text(stmt, 0));

    sqlite3_finalize(stmt);
    return 0;
}

int carrier_managed_group_get_peer(Carrier *w, const char *group_id,
                                   const char *peer_id, CarrierGroupPeer *peer)
{
    server_t *svr;
    int rc;

    if (!w || !group_id || !*group_id || !peer_id || !*peer_id || !peer) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    svr = __get_svr_by_gid(w, group_id);
    if (!svr) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCED ||
        (svr->join_mode.is_on && !strcmp(svr->join_mode.gid, group_id))) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    if (!__group_exist(w->mgrp_client, group_id)) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return -1;
    }

    rc = __db_get_peer(w->mgrp_client->db, group_id, peer_id, peer);
    if (rc < 0) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        carrier_set_error(rc);
        return -1;
    }

    pthread_mutex_unlock(&svr->lock);
    deref(svr);

    return 0;
}

int carrier_get_managed_groups(Carrier *w, CarrierIterateManagedGroupCallback *callback,
                               void *context)
{
    group_t *grp;

    if (!w || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    hashtable_foreach(w->mgrp_client->grps, grp, {
        if (grp->is_joining)
            continue;

        bool resume = callback(grp->id, context);
        if (!resume)
            hashtable_foreach_return_val(0);
    });

    callback(NULL, context);
    return 0;
}

static void __hdl_invite_req(Carrier *w, FriendInfo *fi, Packet *cp)
{
    const char *grp_id;
    const char *svr_id;
    const char *title;

    grp_id = packet_get_group_id(cp);
    svr_id = packet_get_server_id(cp);
    title = packet_get_title(cp);

    if (!grp_id || !*grp_id || !is_valid_key(grp_id) || !svr_id ||
        !*svr_id || !is_valid_key(svr_id) || !title || !*title ||
        strlen(title) > CARRIER_MAX_GROUP_TITLE_LEN)
        return;

    w->callbacks.managed_group_invite(w, grp_id, fi->info.user_info.userid,
                                      svr_id, title, w->context);
}

static void __hdl_rsp(ManagedGroupClient *client, server_t *svr, Packet *cp)
{
    req_t *req;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    req = __list_pop_head(svr->ongoing_reqs);
    if (!req) {
        __svr_set_out_of_sync(client, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    req->on_rsp(client->w, req, cp);
    deref(req);
}

static void __new_grp_ev_cb(Carrier *w, event_t *base)
{
    new_grp_ev_t *ev = (new_grp_ev_t *)base;

    if (w->callbacks.managed_group_callbacks.new_group)
        w->callbacks.managed_group_callbacks.new_group(w, ev->id, w->context);
}

static new_grp_ev_t *__create_new_grp_ev(Carrier *w, const char *gid)
{
    new_grp_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), NULL);
    if (!ev)
        return NULL;

    ev->base.cb = __new_grp_ev_cb;
    ev->base.le.data = ev;
    strcpy(ev->id, gid);

    return ev;
}

static void __hdl_new_grp(ManagedGroupClient *c, server_t *svr, Packet *cp)
{
    Carrier *w = c->w;
    sqlite3 *db = c->db;
    const char *title;
    const char *admin;
    const char *name;
    new_grp_ev_t *ev;
    const char *gid;
    group_t *grp;
    uint64_t ver;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    gid = packet_get_group_id(cp);
    title = packet_get_title(cp);
    admin = packet_get_admin(cp);
    name = packet_get_name(cp);
    ver = packet_get_ver(cp);
    if (!gid || !*gid || !is_valid_key(gid) ||
        !title || !*title || strlen(title) > CARRIER_MAX_GROUP_TITLE_LEN ||
        !admin || !*admin || !is_valid_key(admin) || !name ||
        strlen(name) > CARRIER_MAX_USER_NAME_LEN) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if ((svr->join_mode.is_on && (strcmp(svr->join_mode.gid, gid) ||
                                  ver >= svr->join_mode.join_at_ver)) ||
        (!svr->join_mode.is_on && ver <= svr->ver)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (strcmp(admin, w->me.userid)) {
        if (!svr->join_mode.is_on) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        if (__group_exist(c, gid)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        grp = __group_create(svr, gid, admin, title, true);
        if (!grp) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        if (__db_begin(db) < 0 ||
            __db_store_grp(db, grp) < 0 ||
            __db_store_peer(db, gid, admin, name) < 0 ||
            __db_end(db) < 0) {
            __db_rollback(db);
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(grp);
            return;
        }

        linked_hashtable_put(w->mgrp_client->grps, &grp->he);
        deref(grp);
    } else {
        if (svr->state == __SERVER_STATE_SYNCED || svr->join_mode.is_on) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        if (__group_exist(c, gid)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        ev = __create_new_grp_ev(w, gid);
        if (!ev) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        grp = __group_create(svr, gid, admin, title, false);
        if (!grp) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(ev);
            return;
        }

        if (__db_begin(db) < 0 ||
            __db_store_grp(db, grp) < 0 ||
            __db_store_peer(db, gid, admin, name) < 0 ||
            __db_upd_svr_ver(db, svr->id, ver) < 0 ||
            __db_end(db) < 0) {
            __db_rollback(db);
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(ev);
            deref(grp);
            return;
        }

        linked_hashtable_put(w->mgrp_client->grps, &grp->he);
        deref(grp);
        svr->ver = ver;

        linked_list_push_tail(w->mgrp_client->evs, &ev->base.le);
        deref(ev);
    }
}

static void __dismiss_ev_cb(Carrier *w, event_t *base)
{
    dismiss_ev_t *ev = (dismiss_ev_t *)base;

    if (w->callbacks.managed_group_callbacks.dismissed)
        w->callbacks.managed_group_callbacks.dismissed(w, ev->id, w->context);
}

static dismiss_ev_t *__create_dismiss_ev(Carrier *w, const char *gid)
{
    dismiss_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), NULL);
    if (!ev)
        return NULL;

    ev->base.cb = __dismiss_ev_cb;
    ev->base.le.data = ev;
    strcpy(ev->id, gid);

    return ev;
}

static void __hdl_dismiss_grp(ManagedGroupClient *c, server_t *svr, Packet *cp)
{
    stat_ev_t *grp_stat_ev;
    Carrier *w = c->w;
    sqlite3 *db = c->db;
    dismiss_ev_t *ev;
    const char *gid;
    uint64_t ver;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    if (svr->join_mode.is_on) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    gid = packet_get_group_id(cp);
    ver = packet_get_ver(cp);
    if (!gid || !*gid || !is_valid_key(gid) || ver <= svr->ver) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (!__group_exist(c, gid)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    ev = __create_dismiss_ev(w, gid);
    if (!ev) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    grp_stat_ev = __create_grp_stat_ev(w, gid, CarrierManagedGroupStatus_OutOfSync);
    if (!ev) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(ev);
        return;
    }

    if (__db_begin(db) < 0 ||
        __db_del_grp(db, gid) < 0 ||
        __db_upd_svr_ver(db, svr->id, ver) < 0 ||
        __db_end(db) < 0) {
        __db_rollback(db);
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(ev);
        deref(grp_stat_ev);
        return;
    }

    deref(linked_hashtable_remove(c->grps, gid, strlen(gid)));
    svr->ver = ver;

    linked_list_push_tail(c->evs, &ev->base.le);
    deref(ev);

    linked_list_push_tail(c->evs, &grp_stat_ev->base.le);
    deref(grp_stat_ev);
}

static void __title_ev_cb(Carrier *w, event_t *base)
{
    title_ev_t *ev = (title_ev_t *)base;

    if (w->callbacks.managed_group_callbacks.title)
        w->callbacks.managed_group_callbacks.title(w, ev->id, ev->title, w->context);
}

static title_ev_t *__create_title_ev(Carrier *w, const char *gid, const char *title)
{
    title_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), NULL);
    if (!ev)
        return NULL;

    ev->base.cb = __title_ev_cb;
    ev->base.le.data = ev;
    strcpy(ev->id, gid);
    strcpy(ev->title, title);

    return ev;
}

static void __hdl_title_change(ManagedGroupClient *c, server_t *svr, Packet *cp)
{
    Carrier *w = c->w;
    sqlite3 *db = c->db;
    const char *title;
    const char *gid;
    title_ev_t *ev;
    group_t *grp;
    uint64_t ver;
    int rc;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    gid = packet_get_group_id(cp);
    ver = packet_get_ver(cp);
    title = packet_get_title(cp);
    if (!gid || !*gid || !is_valid_key(gid) ||
        !title || !*title || strlen(title) > CARRIER_MAX_GROUP_TITLE_LEN) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (svr->join_mode.is_on) {
        if (ver >= svr->join_mode.join_at_ver || strcmp(gid, svr->join_mode.gid)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        grp = __group_get(c, gid);
        if (!grp) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        if (!strcmp(grp->title, title)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(grp);
            return;
        }

        rc = __db_upd_title(db, gid, title);
        if (rc < 0) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(grp);
            return;
        }

        strcpy(grp->title, title);
        deref(grp);
    } else {
        if (ver <= svr->ver) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        grp = __group_get(c, gid);
        if (!grp) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        if (!strcmp(grp->title, title)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(grp);
            return;
        }

        ev = __create_title_ev(w, gid, title);
        if (!ev) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(grp);
            return;
        }

        if (__db_begin(db) < 0 ||
            __db_upd_title(db, gid, title) < 0 ||
            __db_upd_svr_ver(db, svr->id, ver) < 0 ||
            __db_end(db) < 0) {
            __db_rollback(db);
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(grp);
            deref(ev);
            return;
        }

        strcpy(grp->title, title);
        deref(grp);
        svr->ver = ver;

        linked_list_push_tail(c->evs, &ev->base.le);
        deref(ev);
    }
}

static void __join_ev_cb(Carrier *w, event_t *base)
{
    join_ev_t *ev = (join_ev_t *)base;

    if (w->callbacks.managed_group_callbacks.peer_status)
        w->callbacks.managed_group_callbacks.peer_status(w, ev->id, ev->peer_id,
                                                         CarrierManagedGroupPeerStatus_Joined,
                                                         w->context);
}

static join_ev_t *__create_join_ev(Carrier *w,
                                   const char *grp_id,
                                   const char *peer_id)
{
    join_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), NULL);
    if (!ev)
        return NULL;

    ev->base.cb = __join_ev_cb;
    ev->base.le.data = ev;
    strcpy(ev->id, grp_id);
    strcpy(ev->peer_id, peer_id);

    return ev;
}

static int __db_set_grp_joined(sqlite3 *db, const char *gid)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "UPDATE groups SET joining = 0 WHERE group_id = :group_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           gid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    return 0;
}

static void __hdl_join(ManagedGroupClient *c, server_t *svr, Packet *cp)
{
    const char *peer_name;
    Carrier *w = c->w;
    sqlite3 *db = c->db;
    const char *peer_id;
    const char *gid;
    group_t *grp;
    uint64_t ver;
    event_t *ev;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    gid = packet_get_group_id(cp);
    ver = packet_get_ver(cp);
    peer_id = packet_get_peer_id(cp);
    peer_name = packet_get_name(cp);
    if (!gid || !*gid || !is_valid_key(gid) || !peer_id || !*peer_id || !is_valid_key(peer_id) ||
        !peer_name || strlen(peer_name) > CARRIER_MAX_USER_NAME_LEN) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if ((svr->join_mode.is_on && (strcmp(svr->join_mode.gid, gid) ||
                                  ver > svr->join_mode.join_at_ver)) ||
        (!svr->join_mode.is_on && ver <= svr->ver)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (strcmp(peer_id, w->me.userid)) {
        if (!__group_exist(c, gid)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        if (svr->join_mode.is_on) {
            if (ver == svr->join_mode.join_at_ver) {
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                return;
            }

            if (__db_store_peer(db, gid, peer_id, peer_name) < 0)
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        } else {
            ev = (event_t *)__create_join_ev(w, gid, peer_id);
            if (!ev) {
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                return;
            }

            if (__db_begin(db) < 0 ||
                __db_store_peer(db, gid, peer_id, peer_name) < 0 ||
                __db_upd_svr_ver(db, svr->id, ver) < 0 ||
                __db_end(db) < 0) {
                __db_rollback(db);
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                deref(ev);
                return;
            }

            svr->ver = ver;

            linked_list_push_tail(c->evs, &ev->le);
            deref(ev);
        }
    } else {
        if (!svr->join_mode.is_on) {
            if (svr->state == __SERVER_STATE_SYNCED) {
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                return;
            }

            if (__group_exist(c, gid)) {
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                return;
            }

            svr->join_mode.is_on = true;
            svr->join_mode.join_at_ver = ver;
            strcpy(svr->join_mode.gid, gid);
        } else {
            if (ver < svr->join_mode.join_at_ver) {
                if (!__group_exist(c, gid))
                    __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            } else {
                join_req_t *req = NULL;

                grp = __group_get(c, gid);
                if (!grp) {
                    __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                    return;
                }

                if (svr->state == __SERVER_STATE_SYNCED) {
                    req = linked_list_pop_head(svr->ongoing_reqs);
                    assert(req && req->base.type == PACKET_TYPE_MGRP_JOIN_REQ);
                }

                ev = req ? (event_t *)__create_join_rsp_ev(w, req, 0) :
                           (event_t *)__create_join_ev(w, gid, peer_id);
                if (!ev) {
                    req ? req->base.abort(w, &req->base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE)) :
                          __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                    deref(grp);
                    deref(req);
                    return;
                }

                if (__db_begin(db) < 0 ||
                    __db_store_peer(db, gid, peer_id, peer_name) < 0 ||
                    __db_set_grp_joined(db, gid) < 0 ||
                    __db_upd_svr_ver(db, svr->id, ver) < 0 ||
                    __db_end(db) < 0) {
                    __db_rollback(db);
                    req ? req->base.abort(w, &req->base, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE)) :
                          __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                    deref(grp);
                    deref(req);
                    deref(ev);
                    return;
                }
                deref(req);

                grp->is_joining = false;
                deref(grp);

                svr->join_mode.is_on = false;

                svr->ver = ver;

                linked_list_push_tail(c->evs, &ev->le);
                deref(ev);
            }
        }
    }
}

static void __leave_ev_cb(Carrier *w, event_t *base)
{
    leave_ev_t *ev = (leave_ev_t *)base;

    if (w->callbacks.managed_group_callbacks.peer_status)
        w->callbacks.managed_group_callbacks.peer_status(w, ev->id, ev->peer_id,
                                                         CarrierManagedGroupPeerStatus_Left,
                                                         w->context);
}

static leave_ev_t *__create_leave_ev(Carrier *w, const char *gid, const char *peer_id)
{
    leave_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), NULL);
    if (!ev)
        return NULL;

    ev->base.cb = __leave_ev_cb;
    ev->base.le.data = ev;
    strcpy(ev->id, gid);
    strcpy(ev->peer_id, peer_id);

    return ev;
}

static void __hdl_leave(ManagedGroupClient *c, server_t *svr, Packet *cp)
{
    stat_ev_t *grp_stat_ev;
    Carrier *w = c->w;
    sqlite3 *db = c->db;
    const char *peer_id;
    const char *gid;
    leave_ev_t *ev;
    uint64_t ver;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    gid = packet_get_group_id(cp);
    ver = packet_get_ver(cp);
    peer_id = packet_get_peer_id(cp);
    if (!gid || !*gid || !is_valid_key(gid) ||
        !peer_id || !*peer_id || !is_valid_key(peer_id)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if ((svr->join_mode.is_on && (strcmp(svr->join_mode.gid, gid) ||
                                  ver >= svr->join_mode.join_at_ver)) ||
        (!svr->join_mode.is_on && ver <= svr->ver)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (strcmp(peer_id, w->me.userid)) {
        if (!__group_exist(c, gid)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        if (svr->join_mode.is_on) {
            if (__db_del_peer(db, gid, peer_id) < 0)
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        } else {
            ev = __create_leave_ev(w, gid, peer_id);
            if (!ev) {
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                return;
            }

            if (__db_begin(db) < 0 ||
                __db_del_peer(db, gid, peer_id) < 0 ||
                __db_upd_svr_ver(db, svr->id, ver) < 0 ||
                __db_end(db) < 0) {
                __db_rollback(db);
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                deref(ev);
                return;
            }

            svr->ver = ver;

            linked_list_push_tail(c->evs, &ev->base.le);
            deref(ev);
        }
    } else if (!svr->join_mode.is_on) {
        if (svr->state != __SERVER_STATE_SYNCING) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        if (!__group_exist(c, gid)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        ev = __create_leave_ev(w, gid, peer_id);
        if (!ev) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        grp_stat_ev = __create_grp_stat_ev(w, gid, CarrierManagedGroupStatus_OutOfSync);
        if (!ev) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(ev);
            return;
        }

        if (__db_begin(db) < 0 ||
            __db_del_grp(db, gid) < 0 ||
            __db_upd_svr_ver(db, svr->id, ver) < 0 ||
            __db_end(db) < 0) {
            __db_rollback(db);
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(ev);
            deref(grp_stat_ev);
            return;
        }

        deref(linked_hashtable_remove(c->grps, gid, strlen(gid)));
        svr->ver = ver;

        linked_list_push_tail(c->evs, &ev->base.le);
        deref(ev);

        linked_list_push_tail(c->evs, &grp_stat_ev->base.le);
        deref(grp_stat_ev);
    }
}

static void __kick_ev_cb(Carrier *w, event_t *base)
{
    kick_ev_t *ev = (kick_ev_t *)base;

    if (w->callbacks.managed_group_callbacks.peer_status)
        w->callbacks.managed_group_callbacks.peer_status(w, ev->id, ev->peer_id,
                                                         CarrierManagedGroupPeerStatus_Kicked,
                                                         w->context);
}

static kick_ev_t *__create_kick_ev(Carrier *w, const char *grp_id, const char *peer_id)
{
    kick_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), NULL);
    if (!ev)
        return NULL;

    ev->base.cb = __kick_ev_cb;
    ev->base.le.data = ev;
    strcpy(ev->id, grp_id);
    strcpy(ev->peer_id, peer_id);

    return ev;
}

static void __hdl_kick(ManagedGroupClient *c, server_t *svr, Packet *cp)
{
    stat_ev_t *grp_stat_ev;
    Carrier *w = c->w;
    sqlite3 *db = c->db;
    const char *peer_id;
    const char *gid;
    kick_ev_t *ev;
    uint64_t ver;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    gid = packet_get_group_id(cp);
    ver = packet_get_ver(cp);
    peer_id = packet_get_peer_id(cp);
    if (!gid || !*gid || !is_valid_key(gid) ||
        !peer_id || !*peer_id || !is_valid_key(peer_id)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if ((svr->join_mode.is_on && (strcmp(svr->join_mode.gid, gid) ||
                                  ver >= svr->join_mode.join_at_ver)) ||
        (!svr->join_mode.is_on && ver <= svr->ver)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (strcmp(peer_id, w->me.userid)) {
        if (!__group_exist(c, gid)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        if (svr->join_mode.is_on) {
            if (__db_del_peer(db, gid, peer_id) < 0)
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        } else {
            ev = __create_kick_ev(w, gid, peer_id);
            if (!ev) {
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                return;
            }

            if (__db_begin(db) < 0 ||
                __db_del_peer(db, gid, peer_id) < 0 ||
                __db_upd_svr_ver(db, svr->id, ver) < 0 ||
                __db_end(db) < 0) {
                __db_rollback(db);
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
                deref(ev);
                return;
            }

            svr->ver = ver;

            linked_list_push_tail(c->evs, &ev->base.le);
            deref(ev);
        }
    } else if (!svr->join_mode.is_on) {
        if (!__group_exist(c, gid)) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        ev = __create_kick_ev(w, gid, peer_id);
        if (!ev) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        grp_stat_ev = __create_grp_stat_ev(w, gid, CarrierManagedGroupStatus_OutOfSync);
        if (!ev) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(ev);
            return;
        }

        if (__db_begin(db) < 0 ||
            __db_del_grp(db, gid) < 0 ||
            __db_upd_svr_ver(db, svr->id, ver) < 0 ||
            __db_end(db) < 0) {
            __db_rollback(db);
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            deref(ev);
            deref(grp_stat_ev);
            return;
        }

        deref(linked_hashtable_remove(c->grps, gid, strlen(gid)));
        svr->ver = ver;

        linked_list_push_tail(c->evs, &ev->base.le);
        deref(ev);

        linked_list_push_tail(c->evs, &grp_stat_ev->base.le);
        deref(grp_stat_ev);
    }
}

static void __name_ev_cb(Carrier *w, event_t *base)
{
    name_ev_t *ev = (name_ev_t *)base;

    if (w->callbacks.managed_group_callbacks.peer_name)
        w->callbacks.managed_group_callbacks.peer_name(w, ev->id, ev->peer_id,
                                                       ev->name, w->context);
}

static name_ev_t *__create_name_ev(Carrier *w,
                                   const char *grp_id,
                                   const char *peer_id,
                                   const char *peer_name)
{
    name_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev), NULL);
    if (!ev)
        return NULL;

    ev->base.cb = __name_ev_cb;
    ev->base.le.data = ev;
    strcpy(ev->id, grp_id);
    strcpy(ev->peer_id, peer_id);
    strcpy(ev->name, peer_name);

    return ev;
}

static void __hdl_name_change(ManagedGroupClient *c, server_t *svr, Packet *cp)
{
    Carrier *w = c->w;
    sqlite3 *db = c->db;
    const char *peer_id;
    const char *name;
    const char *gid;
    name_ev_t *ev;
    uint64_t ver;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    gid = packet_get_group_id(cp);
    ver = packet_get_ver(cp);
    name = packet_get_name(cp);
    peer_id = packet_get_peer_id(cp);
    if (!gid || !*gid || !is_valid_key(gid) ||
        !peer_id || !*peer_id || !is_valid_key(peer_id) ||
        !name || strlen(name) > CARRIER_MAX_USER_NAME_LEN) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if ((svr->join_mode.is_on && (strcmp(svr->join_mode.gid, gid) ||
                                  ver >= svr->join_mode.join_at_ver)) ||
        (!svr->join_mode.is_on && ver <= svr->ver)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (!__group_exist(c, gid)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (strcmp(peer_id, w->me.userid)) {
        if (svr->join_mode.is_on) {
            if (__db_upd_name(db, gid, peer_id, name))
                __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        goto do_upd_name;
    } else {
        if (svr->join_mode.is_on)
            return;

        if (svr->state != __SERVER_STATE_SYNCING) {
            __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
            return;
        }

        goto do_upd_name;
    }

do_upd_name:
    ev = __create_name_ev(w, gid, peer_id, name);
    if (!ev) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (__db_begin(db) < 0 ||
        __db_upd_name(db, gid, peer_id, name) < 0 ||
        __db_upd_svr_ver(db, svr->id, ver) < 0 ||
        __db_end(db) < 0) {
        __db_rollback(db);
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        deref(ev);
        return;
    }

    svr->ver = ver;

    linked_list_push_tail(c->evs, &ev->base.le);
    deref(ev);
}

static void __msg_ev_cb(Carrier *w, event_t *base)
{
    msg_ev_t *ev = (msg_ev_t  *)base;

    if (w->callbacks.managed_group_callbacks.message)
        w->callbacks.managed_group_callbacks.message(w, ev->id, ev->peer_id,
                                                     ev->msg, ev->len, w->context);
}

static msg_ev_t *__create_msg_ev(Carrier *w, const char *grp_id, const char *peer_id,
                                 const void *msg, size_t len)
{
    msg_ev_t *ev;

    ev = rc_zalloc(sizeof(*ev) + len, NULL);
    if (!ev)
        return NULL;

    ev->base.cb = __msg_ev_cb;
    ev->base.le.data = ev;
    strcpy(ev->id, grp_id);
    strcpy(ev->peer_id, peer_id);
    ev->len = len;
    memcpy(ev->msg, msg, len);

    return ev;
}

static void __hdl_msg(ManagedGroupClient *c, server_t *svr, Packet *cp)
{
    Carrier *w = c->w;
    const char *peer_id;
    const char *gid;
    const void *msg;
    msg_ev_t *ev;
    size_t len;

    assert(svr->state == __SERVER_STATE_SYNCING || svr->state == __SERVER_STATE_SYNCED);

    if (svr->state == __SERVER_STATE_SYNCING || svr->join_mode.is_on) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    gid = packet_get_group_id(cp);
    peer_id = packet_get_peer_id(cp);
    msg = packet_get_raw_data(cp);
    len = packet_get_raw_data_length(cp);
    if (!gid || !*gid || !is_valid_key(gid) ||
        !peer_id || !*peer_id || !is_valid_key(peer_id) || !msg || !len) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    if (!__group_exist(c, gid) || !strcmp(peer_id, w->me.userid)) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    ev = __create_msg_ev(w, gid, peer_id, msg, len);
    if (!ev) {
        __svr_set_out_of_sync(c, svr, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        return;
    }

    linked_list_push_tail(c->evs, &ev->base.le);
    deref(ev);
}

void managed_group_client_handle_packet(ManagedGroupClient *client, uint32_t friend_number, Packet *cp)
{
    FriendInfo *fi;
    server_t *svr;

    fi = friends_get(client->w->friends, friend_number);
    if (!fi)
        return;

    if (packet_get_type(cp) == PACKET_TYPE_MGRP_INVITE_REQ) {
        __hdl_invite_req(client->w, fi, cp);
        deref(fi);
        return;
    }

    svr = __server_get(client, fi->info.user_info.userid);
    deref(fi);
    if (!svr)
        return;

    pthread_mutex_lock(&svr->lock);

    if (svr->state != __SERVER_STATE_SYNCING && svr->state != __SERVER_STATE_SYNCED) {
        pthread_mutex_unlock(&svr->lock);
        deref(svr);
        return;
    }

    switch(packet_get_type(cp)) {
    case PACKET_TYPE_MGRP_RESP:
    case PACKET_TYPE_MGRP_NEW_RESP:
        __hdl_rsp(client, svr, cp);
        break;
    case PACKET_TYPE_MGRP_NEW_GRP:
        __hdl_new_grp(client, svr, cp);
        break;
    case PACKET_TYPE_MGRP_DISMISSED:
        __hdl_dismiss_grp(client, svr, cp);
        break;
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        __hdl_title_change(client, svr, cp);
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        __hdl_join(client, svr, cp);
        break;
    case PACKET_TYPE_MGRP_PEER_LEFT:
        __hdl_leave(client, svr, cp);
        break;
    case PACKET_TYPE_MGRP_PEER_KICKED:
        __hdl_kick(client, svr, cp);
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        __hdl_name_change(client, svr, cp);
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        __hdl_msg(client, svr, cp);
        break;
    }

    pthread_mutex_unlock(&svr->lock);
    deref(svr);
}