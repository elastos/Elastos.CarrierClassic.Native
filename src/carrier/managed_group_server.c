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

#include <crystal.h>
#include <sqlite3.h>
#include <inttypes.h>

#include "managed_group_server.h"
#include "carrier.h"
#include "carrier_impl.h"
#include "hashtable_friends.h"

struct ManagedGroupServer {
    pthread_mutex_t lock;
    Carrier *w;
    linked_hashtable_t *grps;
    linked_hashtable_t *scs;
    uint64_t ver;
    sqlite3 *db;
};

typedef struct {
    linked_hash_entry_t he;
    char id[CARRIER_MAX_ID_LEN + 1];
    char title[CARRIER_MAX_GROUP_TITLE_LEN + 1];
    char admin[CARRIER_MAX_ID_LEN + 1];
    linked_hashtable_t *scs;
} group_t;

typedef struct {
    linked_hash_entry_t he;
    char id[CARRIER_MAX_ID_LEN + 1];
    uint32_t fnum;
    linked_hashtable_t *grps;
} synced_client_t;

typedef struct {
    linked_hash_entry_t ghe;
    linked_hash_entry_t sche;
    linked_list_entry_t le;
    group_t *grp;
    synced_client_t *sc;
} sync_entry_t;

typedef struct {
    linked_list_entry_t le;
    int type;
    char gid[CARRIER_MAX_ID_LEN + 1];
    uint64_t ver;
    size_t len;
    uint8_t content[0];
} event_t;

typedef struct {
    linked_list_entry_t le;
    char gid[CARRIER_MAX_ID_LEN + 1];
    uint64_t lower;
    uint64_t upper;
} event_range_t;

typedef struct {
    size_t buf_sz;
    size_t str_len;
    void *buf;
} string_t;

#define NOT_A_VER (0)
#define VER_START (1)

static void __db_dtor(sqlite3 *db)
{
    sqlite3_close(db);
    sqlite3_shutdown();
}

static void __svr_dtor(void *obj)
{
    ManagedGroupServer *svr = obj;

    pthread_mutex_destroy(&svr->lock);

    deref(svr->grps);
    deref(svr->scs);
    __db_dtor(svr->db);
}

static sqlite3 *__db_create(Carrier *w)
{
    char db_path[PATH_MAX];
    sqlite3_stmt *stmt;
    const char *sql;
    sqlite3 *db;
    int rc;

    rc = mkdirs(w->pref.data_location, S_IRWXU);
    if (rc < 0)
        return NULL;

    sqlite3_initialize();

    snprintf(db_path, sizeof(db_path), "%s/mgrp_server.sqlite3", w->pref.data_location);
    rc = sqlite3_open_v2(db_path, &db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                         NULL);
    if (rc) {
        __db_dtor(db);
        return NULL;
    }

    /* ================================= stmt-sep ================================= */
    sql = "PRAGMA foreign_keys = ON";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_dtor(db);
        return NULL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_dtor(db);
        return NULL;
    }

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS groups ("
          "  group_id TEXT PRIMARY KEY,"
          "  admin_id TEXT NOT NULL,"
          "  title    TEXT NOT NULL"
          ")";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_dtor(db);
        return NULL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_dtor(db);
        return NULL;
    }

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS peers ("
          "  group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,"
          "  peer_id  TEXT NOT NULL,"
          "  name     TEXT NOT NULL,"
          "  PRIMARY KEY(group_id, peer_id)"
          ")";

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_dtor(db);
        return NULL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_dtor(db);
        return NULL;
    }

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS in_group_periods ("
          "  join_at  INTEGER NOT NULL REFERENCES events(version),"
          "  leave_at INTEGER REFERENCES events(version) DEFAULT NULL,"
          "  group_id TEXT NOT NULL,"
          "  peer_id  TEXT NOT NULL"
          ")";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_dtor(db);
        return NULL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_dtor(db);
        return NULL;
    }

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS events ("
          "  version  INTEGER PRIMARY KEY AUTOINCREMENT,"
          "  type     INTEGER NOT NULL,"
          "  group_id TEXT NOT NULL,"
          "  content  BLOB NOT NULL"
          ")";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc) {
        __db_dtor(db);
        return NULL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        __db_dtor(db);
        return NULL;
    }

    return db;
}

static void __grp_dtor(void *obj)
{
    group_t *grp = obj;

    deref(grp->scs);
}

static group_t *__grp_create(const char *gid, const char *title, const char *admin)
{
    group_t *grp;

    grp = rc_zalloc(sizeof(*grp), __grp_dtor);
    if (!grp)
        return NULL;

    grp->scs = linked_hashtable_create(16, 0, NULL, NULL);
    if (!grp->scs) {
        deref(grp);
        return NULL;
    }

    strcpy(grp->id, gid);
    strcpy(grp->title, title);
    strcpy(grp->admin, admin);

    grp->he.data = grp;
    grp->he.key = grp->id;
    grp->he.keylen = strlen(grp->id);

    return grp;
}

static int __load_state_from_db(ManagedGroupServer *svr)
{
    sqlite3 *db = svr->db;
    sqlite3_stmt *stmt;
    char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "SELECT group_id, admin_id, title FROM groups";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        group_t *grp;

        grp = __grp_create((const char *)sqlite3_column_text(stmt, 0),
                           (const char *)sqlite3_column_text(stmt, 2),
                           (const char *)sqlite3_column_text(stmt, 1));
        if (!grp) {
            sqlite3_finalize(stmt);
            return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
        }

        linked_hashtable_put(svr->grps, &grp->he);
        deref(grp);
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    /* ================================= stmt-sep ================================= */
    sql = "SELECT CASE WHEN max(version) IS NOT NULL THEN max(version) ELSE 0 END"
          "  FROM events";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
    }

    svr->ver = sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return 0;
}

ManagedGroupServer *managed_group_server_create(Carrier *w)
{
    ManagedGroupServer *svr;
    int rc;

    svr = rc_zalloc(sizeof(*svr), __svr_dtor);
    if (!svr)
        return NULL;

    pthread_mutex_init(&svr->lock, NULL);

    svr->db = __db_create(w);
    if (!svr->db) {
        deref(svr);
        return NULL;
    }

    svr->grps = linked_hashtable_create(16, 0, NULL, NULL);
    if (!svr->grps) {
        deref(svr);
        return NULL;
    }

    svr->scs = linked_hashtable_create(16, 0, NULL, NULL);
    if (!svr->scs) {
        deref(svr);
        return NULL;
    }

    svr->w = w;

    rc = __load_state_from_db(svr);
    if (rc < 0) {
        deref(svr);
        return NULL;
    }

    return svr;
}

static sync_entry_t *__sync_ent_create(group_t *grp, synced_client_t *sc)
{
    sync_entry_t *ent;

    ent = rc_zalloc(sizeof(*ent), NULL);
    if (!ent)
        return NULL;

    ent->grp = grp;
    ent->sc = sc;

    ent->ghe.data = ent;
    ent->ghe.key = sc->id;
    ent->ghe.keylen = strlen(sc->id);

    ent->sche.data = ent;
    ent->sche.key = grp->id;
    ent->sche.keylen = strlen(grp->id);

    ent->le.data = ent;

    return ent;
}

static void __synced_client_dtor(void *obj)
{
    synced_client_t *sc = obj;

    deref(sc->grps);
}

static synced_client_t *__synced_client_create(FriendInfo *fi)
{
    synced_client_t *sc;

    sc = rc_zalloc(sizeof(*sc), __synced_client_dtor);
    if (!sc)
        return NULL;

    sc->grps = linked_hashtable_create(16, 0, NULL, NULL);
    if (!sc->grps) {
        deref(sc);
        return NULL;
    }

    strcpy(sc->id, fi->info.user_info.userid);
    sc->fnum = fi->friend_number;

    sc->he.data = sc;
    sc->he.key = sc->id;
    sc->he.keylen = strlen(sc->id);

    return sc;
}

static event_range_t *__ev_range_create(const char *gid, uint64_t lower, uint64_t upper)
{
    event_range_t *rng;

    rng = rc_zalloc(sizeof(*rng), NULL);
    if (!rng)
        return NULL;

    strcpy(rng->gid, gid);
    rng->lower = lower;
    rng->upper = upper;
    rng->le.data = rng;

    return rng;
}

static void __str_dtor(void *obj)
{
    string_t *str = obj;

    if (str->buf)
        free(str->buf);
}

static string_t *__str_create()
{
    string_t *str;

    str = rc_zalloc(sizeof(string_t), __str_dtor);
    if (!str)
        return NULL;

    str->buf = calloc(1, 2048);
    if (!str->buf) {
        deref(str);
        return NULL;
    }

    str->buf_sz = 2048;

    return str;
}

static event_t *__ev_create(uint64_t ver, const char *gid, int type, const void *content, size_t len)
{
    event_t *ev;

    ev = rc_zalloc(sizeof(*ev) + len, NULL);
    if (!ev)
        return NULL;

    strcpy(ev->gid, gid);
    ev->ver = ver;
    ev->type = type;
    ev->len = len;
    memcpy(ev->content, content, len);

    ev->le.data = ev;

    return ev;
}

static synced_client_t *__synced_client_get(ManagedGroupServer *svr, const char *scid)
{
    return linked_hashtable_get(svr->scs, scid, strlen(scid));
}

static void __synced_client_rm(ManagedGroupServer *svr, const char *scid)
{
    synced_client_t *sc;
    sync_entry_t *ent;

    sc = linked_hashtable_remove(svr->scs, scid, strlen(scid));
    if (!sc)
        return;

    hashtable_foreach(sc->grps, ent, {
        deref(linked_hashtable_remove(ent->grp->scs, scid, strlen(scid)));
        hashtable_foreach_remove_cur_entry();
    });

    deref(sc);
}

static int __grp_exist(ManagedGroupServer *svr, const char *gid)
{
    return linked_hashtable_exist(svr->grps, gid, strlen(gid));
}

static group_t *__grp_get(ManagedGroupServer *svr, const char *gid)
{
    return linked_hashtable_get(svr->grps, gid, strlen(gid));
}

static int __sync_ent_exist(ManagedGroupServer *svr, const char *scid, const char *gid)
{
    synced_client_t *sc;
    int rc;

    sc = __synced_client_get(svr, scid);
    if (!sc)
        return 0;

    rc = linked_hashtable_exist(sc->grps, gid, strlen(gid));
    deref(sc);

    return rc;
}

static sync_entry_t *__sync_ent_get(ManagedGroupServer *svr, const char *scid, const char *gid)
{
    synced_client_t *sc;
    sync_entry_t *ent;

    sc = __synced_client_get(svr, scid);
    if (!sc)
        return NULL;

    ent = linked_hashtable_get(sc->grps, gid, strlen(gid));
    deref(sc);

    return ent;
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

static void *__enc_new_grp_rsp(int rc, uint64_t ver, const char *name, size_t *len)
{
    Packet *cp;
    void *rsp;

    cp = packet_create(PACKET_TYPE_MGRP_NEW_RESP, NULL);
    if (!cp)
        return NULL;

    packet_set_status(cp, rc);
    packet_set_ver(cp, ver);
    packet_set_name(cp, name);

    rsp = packet_encode(cp, len);
    packet_free(cp);

    return rsp;
}

static void *__enc_new_grp_ev(const char *grp_id, const char *title,
                              const char *admin, const char *name, uint64_t ver, size_t *len)
{
    Packet *cp;
    void *ev;

    cp = packet_create(PACKET_TYPE_MGRP_NEW_GRP, NULL);
    if (!cp)
        return NULL;

    packet_set_group_id(cp, grp_id);
    packet_set_title(cp, title);
    packet_set_admin(cp, admin);
    packet_set_name(cp, name);
    packet_set_ver(cp, ver);

    ev = packet_encode(cp, len);
    packet_free(cp);

    return ev;
}

static void *__enc_grp_dismiss_ev(const char *gid, uint64_t ver, size_t *len)
{
    Packet *cp;
    void *ev;

    cp = packet_create(PACKET_TYPE_MGRP_DISMISSED, NULL);
    if (!cp)
        return NULL;

    packet_set_group_id(cp, gid);
    packet_set_ver(cp, ver);

    ev = packet_encode(cp, len);
    packet_free(cp);

    return ev;
}

static void *__enc_peer_leave_ev(const char *gid, const char *peer_id, uint64_t ver, size_t *len)
{
    Packet *cp;
    void *ev;

    cp = packet_create(PACKET_TYPE_MGRP_PEER_LEFT, NULL);
    if (!cp)
        return NULL;

    packet_set_group_id(cp, gid);
    packet_set_peer_id(cp, peer_id);
    packet_set_ver(cp, ver);

    ev = packet_encode(cp, len);
    packet_free(cp);

    return ev;

}

static void *__enc_join_ev(const char *gid, const char *peer_id,
                           const char *name, uint64_t ver, size_t *len)
{
    Packet *cp;
    void *ev;

    cp = packet_create(PACKET_TYPE_MGRP_PEER_JOINED, NULL);
    if (!cp)
        return NULL;

    packet_set_group_id(cp, gid);
    packet_set_peer_id(cp, peer_id);
    packet_set_name(cp, name);
    packet_set_ver(cp, ver);

    ev = packet_encode(cp, len);
    packet_free(cp);

    return ev;
}

static void *__enc_kick_ev(const char *gid, const char *peer_id, uint64_t ver, size_t *len)
{
    Packet *cp;
    void *ev;

    cp = packet_create(PACKET_TYPE_MGRP_PEER_KICKED, NULL);
    if (!cp)
        return NULL;

    packet_set_group_id(cp, gid);
    packet_set_peer_id(cp, peer_id);
    packet_set_ver(cp, ver);

    ev = packet_encode(cp, len);
    packet_free(cp);

    return ev;
}

static void *__enc_grp_msg_ev(const char *gid, const char *peer_id, const void *msg,
                              size_t msg_len, size_t *len)
{
    Packet *cp;
    void *ev;

    cp = packet_create(PACKET_TYPE_MGRP_PEER_MSG, NULL);
    if (!cp)
        return NULL;

    packet_set_group_id(cp, gid);
    packet_set_peer_id(cp, peer_id);
    packet_set_raw_data(cp, msg, msg_len);

    ev = packet_encode(cp, len);
    packet_free(cp);

    return ev;
}

static void *__enc_title_change_ev(const char *gid, const char *title, uint64_t ver, size_t *len)
{
    Packet *cp;
    void *ev;

    cp = packet_create(PACKET_TYPE_MGRP_TITLE_CHANGED, NULL);
    if (!cp)
        return NULL;

    packet_set_group_id(cp, gid);
    packet_set_title(cp, title);
    packet_set_ver(cp, ver);

    ev = packet_encode(cp, len);
    packet_free(cp);

    return ev;
}

static void *__enc_name_change_ev(const char *gid, const char *peer_id,
                                  const char *title, uint64_t ver, size_t *len)
{
    Packet *cp;
    void *ev;

    cp = packet_create(PACKET_TYPE_MGRP_PEER_NAME_CHANGED, NULL);
    if (!cp)
        return NULL;

    packet_set_group_id(cp, gid);
    packet_set_peer_id(cp, peer_id);
    packet_set_name(cp, title);
    packet_set_ver(cp, ver);

    ev = packet_encode(cp, len);
    packet_free(cp);

    return ev;
}

static int __db_get_synced_ents(sqlite3 *db, ManagedGroupServer *svr,
                                synced_client_t *sc, linked_list_t **ents)
{
    sqlite3_stmt *stmt;
    linked_list_t *__ents;
    char *sql;
    int rc;

    __ents = linked_list_create(0, NULL);
    if (!__ents)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    /* ================================= stmt-sep ================================= */
    sql = "SELECT group_id FROM peers WHERE peer_id = :peer_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc) {
        deref(__ents);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           sc->id, -1, NULL);
    if (rc) {
        deref(__ents);
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sync_entry_t *ent;
        group_t *grp;

        grp = __grp_get(svr, (const char *)sqlite3_column_text(stmt, 0));
        assert(grp);

        ent = __sync_ent_create(grp, sc);
        if (!ent) {
            deref(__ents);
            deref(grp);
            sqlite3_finalize(stmt);
            return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
        }

        linked_list_push_tail(__ents, &ent->le);
        deref(grp);
        deref(ent);
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        deref(__ents);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    *ents = __ents;
    return 0;
}

static int __db_get_ev_ranges(sqlite3 *db, const char *cid, uint64_t ver, linked_list_t **rngs)
{
    sqlite3_stmt *stmt;
    linked_list_t *__rngs;
    char *sql;
    int rc;

    __rngs = linked_list_create(0, NULL);
    if (!__rngs)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    /* ================================= stmt-sep ================================= */
    sql = "SELECT group_id,"
          "       CASE WHEN join_at > :version THEN join_at ELSE :version + 1 END AS lower_bound,"
          "       CASE WHEN leave_at IS NULL THEN 0 ELSE leave_at END AS upper_bound"
          "  FROM in_group_periods"
          "  WHERE peer_id = :peer_id AND (leave_at > :version OR leave_at IS NULL)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc) {
        deref(__rngs);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":version"),
                            ver);
    if (rc) {
        deref(__rngs);
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           cid, -1, NULL);
    if (rc) {
        deref(__rngs);
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        event_range_t *rng;

        rng = __ev_range_create((const char *)sqlite3_column_text(stmt, 0),
                                sqlite3_column_int64(stmt, 1),
                                sqlite3_column_int64(stmt, 2));
        if (!rng) {
            deref(__rngs);
            sqlite3_finalize(stmt);
            return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
        }

        linked_list_push_tail(__rngs, &rng->le);
        deref(rng);
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        deref(__rngs);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    *rngs = __rngs;
    return 0;
}

static int __str_appendf(string_t *str, const char *fmt, ...)
{
    va_list args;
    va_list prerun_args;
    int rc;

    va_start(args, fmt);

    va_copy(prerun_args, args);
    rc = vsnprintf(NULL, 0, fmt, prerun_args);
    va_end(prerun_args);
    if (rc <= 0) {
        va_end(args);
        return rc;
    }

    if (str->str_len + rc >= str->buf_sz) {
        void *buf_tmp;

        buf_tmp = realloc(str->buf, str->str_len + rc + 1);
        if (!buf_tmp) {
            va_end(args);
            return -1;
        }

        str->buf = buf_tmp;
        str->buf_sz += (rc + 1);
    }

    vsprintf((char *)str->buf + str->str_len,  fmt, args);
    va_end(args);

    str->str_len += rc;
    return 0;
}

static int __db_get_evs_by_ranges(sqlite3 *db, linked_list_t *rngs, linked_list_t **evs)
{
    sqlite3_stmt *stmt;
    event_range_t *rng;
    linked_list_t *__evs;
    string_t *sql;
    int rc;
    int i;

    __evs = linked_list_create(0, NULL);
    if (!__evs)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    sql = __str_create();
    if (!sql) {
        deref(__evs);
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
    }

    /* ================================= stmt-sep ================================= */
    rc = __str_appendf(sql,
                       "SELECT version, group_id, type, content, length(content)"
                       "  FROM events");
    if (rc < 0) {
        deref(__evs);
        deref(sql);
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
    }

    i = 0;
    list_foreach(rngs, rng, {
        if (__str_appendf(sql, " %s (group_id = '%s'", !i ? "WHERE" : "OR", rng->gid) ||
            (rng->lower && __str_appendf(sql, " AND version >= %" PRIu64, rng->lower)) ||
            (rng->upper && __str_appendf(sql, " AND version <= %" PRIu64, rng->upper)) ||
            __str_appendf(sql, ") ")) {
            deref(__evs);
            deref(sql);
            list_foreach_return_val(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        }

        ++i;
    });

    rc = __str_appendf(sql, " ORDER BY version ASC");
    if (rc < 0) {
        deref(__evs);
        deref(sql);
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
    }

    rc = sqlite3_prepare_v2(db, sql->buf, -1, &stmt, NULL);
    deref(sql);
    if (rc) {
        deref(__evs);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        event_t *ev;

        ev = __ev_create(sqlite3_column_int64(stmt, 0),
                         (const char *)sqlite3_column_text(stmt, 1),
                         sqlite3_column_int(stmt, 2),
                         sqlite3_column_blob(stmt, 3),
                         sqlite3_column_int64(stmt, 4));
        if (!ev) {
            deref(__evs);
            sqlite3_finalize(stmt);
            return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
        }

        linked_list_push_tail(__evs, &ev->le);
        deref(ev);
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        deref(__evs);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    *evs = __evs;
    return 0;
}

static int __db_get_grp_history(sqlite3 *db, const char *gid, uint64_t lower, uint64_t upper, linked_list_t **evs)
{
    sqlite3_stmt *stmt;
    linked_list_t *__evs;
    char *sql;
    int rc;

    __evs = linked_list_create(0, NULL);
    if (!__evs)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    /* ================================= stmt-sep ================================= */
    sql = "SELECT version, group_id, type, content, length(content)"
          "  FROM events"
          "  WHERE group_id = :group_id AND version >= :lower AND version <= :upper"
          "  ORDER BY version ASC";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc) {
        deref(__evs);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":group_id"),
                           gid, -1, NULL);
    if (rc) {
        deref(__evs);
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":lower"),
                            lower);
    if (rc) {
        deref(__evs);
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":upper"),
                            upper);
    if (rc) {
        deref(__evs);
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        event_t *ev;

        ev = __ev_create(sqlite3_column_int64(stmt, 0),
                         (const char *)sqlite3_column_text(stmt, 1),
                         sqlite3_column_int(stmt, 2),
                         sqlite3_column_blob(stmt, 3),
                         sqlite3_column_int64(stmt, 4));
        if (!ev) {
            deref(__evs);
            sqlite3_finalize(stmt);
            return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
        }

        linked_list_push_tail(__evs, &ev->le);
        deref(ev);
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        deref(__evs);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    *evs = __evs;
    return 0;
}

static void *__list_pop_head(linked_list_t *list)
{
    return linked_list_is_empty(list) ? NULL : linked_list_pop_head(list);
}

static int __db_get_sync_evs(sqlite3 *db, const char *cid, uint64_t ver, linked_list_t **evs)
{
    linked_list_t *__evs;
    size_t evs_sz;
    linked_list_t *rngs;
    int rc;
    int i;

    rc = __db_get_ev_ranges(db, cid, ver, &rngs);
    if (rc < 0)
        return rc;
    else if (linked_list_is_empty(rngs)) {
        deref(rngs);
        *evs = NULL;
        return 0;
    }

    rc = __db_get_evs_by_ranges(db, rngs, &__evs);
    deref(rngs);
    if (rc < 0)
        return rc;

    evs_sz = linked_list_size(__evs);

    for (i = 0; i < evs_sz; ++i) {
        linked_list_t *history;
        event_t *ev;
        Packet *cp;

        ev = __list_pop_head(__evs);
        assert(ev);

        linked_list_push_tail(__evs, &ev->le);

        if (ev->type != PACKET_TYPE_MGRP_PEER_JOINED) {
            deref(ev);
            continue;
        }

        cp = packet_decode(ev->content, ev->len);
        if (!cp) {
            deref(__evs);
            deref(ev);
            return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
        }

        assert(packet_get_type(cp) == PACKET_TYPE_MGRP_PEER_JOINED);
        if (strcmp(packet_get_peer_id(cp), cid)) {
            deref(ev);
            free(cp);
            continue;
        }
        free(cp);

        rc = __db_get_grp_history(db, ev->gid, VER_START, ev->ver, &history);
        deref(ev);
        if (rc < 0) {
            deref(__evs);
            return rc;
        }

        assert(!linked_list_is_empty(history));

        while ((ev = __list_pop_head(history))) {
            linked_list_push_tail(__evs, &ev->le);
            deref(ev);
        }

        deref(history);
    }

    *evs = __evs;
    return 0;
}

static int __db_store_grp(sqlite3 *db, group_t *grp, const char *admin_name,
                          const void *ev, size_t len, uint64_t ver)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "BEGIN";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO groups(group_id, admin_id, title)"
          "  VALUES (:group_id, :admin_id, :title)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":admin_id"),
                           grp->admin, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":title"),
                           grp->title, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO peers(group_id, peer_id, name)"
          "  VALUES (:group_id, :admin_id, :name)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":admin_id"),
                           grp->admin, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":name"),
                           admin_name, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO events(type, group_id, content)"
          "  VALUES (:new_grp, :group_id, :ev)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":new_grp"),
                          PACKET_TYPE_MGRP_NEW_GRP);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_blob(stmt,
                           sqlite3_bind_parameter_index(stmt, ":ev"),
                           ev, len, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO in_group_periods(join_at, group_id, peer_id)"
          "  VALUES (:version, :group_id, :admin_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":version"),
                            ver);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":admin_id"),
                           grp->admin, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "END";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    return 0;

rollback:
    sql = "ROLLBACK";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
}

static int __db_del_grp(sqlite3 *db, group_t *grp, void *ev, size_t len, uint64_t ver)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "BEGIN";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO events(type, group_id, content)"
          "  VALUES (:dismiss, :group_id, :ev)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":dismiss"),
                          PACKET_TYPE_MGRP_DISMISSED);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_blob(stmt,
                           sqlite3_bind_parameter_index(stmt, ":ev"),
                           ev, len, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "UPDATE in_group_periods"
          "  SET leave_at = :version"
          "  WHERE group_id = :group_id AND leave_at IS NULL";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":version"),
                            ver);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "DELETE FROM groups WHERE group_id = :group_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "END";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    return 0;

rollback:
    sql = "ROLLBACK";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
}

static int __db_del_peer(sqlite3 *db, int type, group_t *grp,
                         const char *peer_id, void *ev, size_t len, uint64_t ver)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "BEGIN";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    /* ================================= stmt-sep ================================= */
    sql = "DELETE FROM peers"
          "  WHERE group_id = :group_id AND peer_id = :peer_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           peer_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO events(type, group_id, content)"
          "  VALUES (:type, :group_id, :ev)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":type"),
                          type);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_blob(stmt,
                           sqlite3_bind_parameter_index(stmt, ":ev"),
                           ev, len, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "UPDATE in_group_periods"
          "  SET leave_at = :version"
          "  WHERE group_id = :group_id AND peer_id = :peer_id AND leave_at IS NULL";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":version"),
                            ver);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           peer_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "END";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    return 0;

rollback:
    sql = "ROLLBACK";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
}

static int __db_join_grp(sqlite3 *db, const char *cid, const char *name,
                         group_t *grp, void *ev, size_t len, uint64_t ver)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "BEGIN";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO peers(group_id, peer_id, name)"
          "  VALUES (:group_id, :peer_id, :name)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           cid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":name"),
                           name, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO events(type, group_id, content)"
          "  VALUES (:join, :group_id, :ev)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":join"),
                          PACKET_TYPE_MGRP_PEER_JOINED);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_blob(stmt,
                           sqlite3_bind_parameter_index(stmt, ":ev"),
                           ev, len, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO in_group_periods(join_at, group_id, peer_id)"
          "  VALUES (:version, :group_id, :peer_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":version"),
                            ver);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           cid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "END";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    return 0;

rollback:
    sql = "ROLLBACK";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
}

static int __db_is_peer(sqlite3 *db, const char *friend_id, group_t *grp, bool *res)
{
    sqlite3_stmt *stmt;
    char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "SELECT EXISTS(SELECT * FROM peers "
          "                WHERE group_id = :group_id AND peer_id = :peer_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           friend_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);
    }

    *res = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return 0;
}

static int __db_upd_grp_title(sqlite3 *db, group_t *grp, const char *title, void *ev, size_t len)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "BEGIN";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    /* ================================= stmt-sep ================================= */
    sql = "UPDATE groups"
          "  SET title = :title"
          "  WHERE group_id = :group_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":title"),
                           title, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO events(type, group_id, content)"
          "  VALUES (:title_change, :group_id, :ev)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":title_change"),
                          PACKET_TYPE_MGRP_TITLE_CHANGED);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_blob(stmt,
                           sqlite3_bind_parameter_index(stmt, ":ev"),
                           ev, len, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "END";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    return 0;

rollback:
    sql = "ROLLBACK";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
}

static int __db_upd_name(sqlite3 *db, group_t *grp, const char *scid,
                         const char *name, void *ev, size_t len)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "BEGIN";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    /* ================================= stmt-sep ================================= */
    sql = "UPDATE peers"
          "  SET name = :name"
          "  WHERE group_id = :group_id AND peer_id = :peer_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":name"),
                           name, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":peer_id"),
                           scid, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE);

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO events(type, group_id, content)"
          "  VALUES (:name_change, :group_id, :ev)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":name_change"),
                          PACKET_TYPE_MGRP_PEER_NAME_CHANGED);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":group_id"),
                           grp->id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_bind_blob(stmt,
                           sqlite3_bind_parameter_index(stmt, ":ev"),
                           ev, len, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    /* ================================= stmt-sep ================================= */
    sql = "END";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto rollback;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto rollback;

    return 0;

rollback:
    sql = "ROLLBACK";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return CARRIER_GENERAL_ERROR(ERROR_UNKNOWN);
}

static int __send_err_rsp(ManagedGroupServer *svr, FriendInfo *fi, int rc)
{
    size_t len;
    void *rsp;

    rsp = __enc_rsp(rc, NOT_A_VER, &len);
    if (!rsp)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    rc = dht_friend_message(&svr->w->dht, fi->friend_number, rsp, len, 0);
    free(rsp);

    return rc;
}

static int __send_err_rsp_and_rm_sc_if_fail(ManagedGroupServer *svr, FriendInfo *fi, int rc)
{
    rc = __send_err_rsp(svr, fi, rc);
    if (!rc)
        return 0;

    __synced_client_rm(svr, fi->info.user_info.userid);

    return rc;
}

static int __send_new_grp_err_rsp_and_rm_sc_if_fail(ManagedGroupServer *svr, FriendInfo *fi, int rc)
{
    size_t len;
    void *rsp;

    rsp = __enc_new_grp_rsp(rc, NOT_A_VER, NULL, &len);
    if (!rsp) {
        __synced_client_rm(svr, fi->info.user_info.userid);
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
    }

    rc = dht_friend_message(&svr->w->dht, fi->friend_number, rsp, len, 0);
    free(rsp);
    if (rc < 0) {
        __synced_client_rm(svr, fi->info.user_info.userid);
        return rc;
    }

    return 0;
}

static int __send_new_grp_rsp_and_rm_sc_if_fail(ManagedGroupServer *svr, FriendInfo *fi,
                                                uint64_t ver, const char *name)
{
    size_t len;
    void *rsp;
    int rc;

    rsp = __enc_new_grp_rsp(0, ver, name, &len);
    if (!rsp) {
        __synced_client_rm(svr, fi->info.user_info.userid);
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);
    }

    rc = dht_friend_message(&svr->w->dht, fi->friend_number, rsp, len, 0);
    free(rsp);
    if (rc < 0) {
        __synced_client_rm(svr, fi->info.user_info.userid);
        return rc;
    }

    return 0;
}

static int __send_ev(ManagedGroupServer *svr, uint32_t fnum, const void *ev, size_t len)
{
    return dht_friend_message(&svr->w->dht, fnum, ev, len, 0);
}

static int __send_rsp(ManagedGroupServer *svr, FriendInfo *fi, uint64_t ver)
{
    size_t len;
    void *rsp;
    int rc;

    rsp = __enc_rsp(0, ver, &len);
    if (!rsp)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    rc = dht_friend_message(&svr->w->dht, fi->friend_number, rsp, len, 0);
    free(rsp);

    return rc;
}

static void __notify_all_but_reqer_and_rm_sc_if_fail(ManagedGroupServer *svr, group_t *grp, FriendInfo *reqer,
                                                     void *ev, size_t len)
{
    sync_entry_t *ent;
    int rc;

    hashtable_foreach(grp->scs, ent, {
        synced_client_t *sc = ent->sc;

        if (!strcmp(reqer->info.user_info.userid, sc->id))
            continue;

        rc = __send_ev(svr, sc->fnum, ev, len);
        if (rc < 0) {
            hashtable_foreach_remove_cur_entry();
            __synced_client_rm(svr, sc->id);
        }
    });
}

static void __send_rsp_and_notify_rest_and_rm_sc_if_fail(ManagedGroupServer *svr, group_t *grp, FriendInfo *fi,
                                                         uint64_t ver, void *ev, size_t len)
{
    if (__send_rsp(svr, fi, ver) < 0)
        __synced_client_rm(svr, fi->info.user_info.userid);

    __notify_all_but_reqer_and_rm_sc_if_fail(svr, grp, fi, ev, len);
}

static int __send_grp_history(ManagedGroupServer *svr, group_t *grp, FriendInfo *fi,
                              uint64_t lower, uint64_t upper)
{
    linked_list_t *history;
    event_t *ev;
    int rc;

    rc = __db_get_grp_history(svr->db, grp->id, lower, upper, &history);
    if (rc < 0)
        return rc;

    list_foreach(history, ev, {
        rc = dht_friend_message(&svr->w->dht, fi->friend_number, ev->content, ev->len, 0);
        if (rc < 0)
            list_foreach_break;
    });

    deref(history);
    return rc;
}

static void __send_join_rsp_and_notify_rest_and_rm_sc_if_fail(ManagedGroupServer *svr, group_t *grp, FriendInfo *fi,
                                                              uint64_t ver, void *ev, size_t len)
{
    if (__send_rsp(svr, fi, ver) < 0 ||
        __send_grp_history(svr, grp, fi, VER_START, ver - 1) < 0 ||
        __send_ev(svr, fi->friend_number, ev, len) < 0)
        __synced_client_rm(svr, fi->info.user_info.userid);

    __notify_all_but_reqer_and_rm_sc_if_fail(svr, grp, fi, ev, len);
}

static void __hdl_sync_req(ManagedGroupServer *svr, FriendInfo *fi, Packet *cp)
{
    synced_client_t *sc = NULL;
    linked_list_t *ents = NULL;
    linked_list_t *evs = NULL;
    sync_entry_t *ent;
    uint64_t ver;
    event_t *ev;
    int rc;

    sc = __synced_client_get(svr, fi->info.user_info.userid);
    if (sc)
        return;

    ver = packet_get_ver(cp);
    if (ver > svr->ver) {
        __send_err_rsp(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    sc = __synced_client_create(fi);
    if (!sc) {
        __send_err_rsp(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    rc = __db_get_synced_ents(svr->db, svr, sc, &ents);
    if (rc < 0) {
        __send_err_rsp(svr, fi, rc);
        goto cleanup;
    }

    rc = __db_get_sync_evs(svr->db, sc->id, ver, &evs);
    if (rc < 0) {
        __send_err_rsp(svr, fi, rc);
        goto cleanup;
    }

    list_foreach(evs, ev, {
        rc = __send_ev(svr, fi->friend_number, ev->content, ev->len);
        if (rc < 0)
            list_foreach_goto(cleanup);
    });

    rc = __send_rsp(svr, fi, 0);
    if (rc < 0)
        goto cleanup;

    list_foreach(ents, ent, {
        linked_hashtable_put(ent->grp->scs, &ent->ghe);
        linked_hashtable_put(ent->sc->grps, &ent->sche);
    });

    linked_hashtable_put(svr->scs, &sc->he);

cleanup:
    deref(sc);
    deref(ents);
    deref(evs);
}

static void __hdl_new_grp_req(ManagedGroupServer *svr, FriendInfo *fi, Packet *cp)
{
    synced_client_t *sc = NULL;
    sync_entry_t *ent = NULL;
    group_t *grp = NULL;
    void *ev = NULL;
    char name[CARRIER_MAX_USER_NAME_LEN + 1];
    const char *title;
    const char *gid;
    size_t len;
    int rc;

    sc = __synced_client_get(svr, fi->info.user_info.userid);
    if (!sc)
        return;

    gid = packet_get_group_id(cp);
    title = packet_get_title(cp);
    if (!gid || !*gid || !is_valid_key(gid) ||
        !title || !*title || strlen(title) > CARRIER_MAX_GROUP_TITLE_LEN) {
        __send_new_grp_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    if (__grp_exist(svr, gid)) {
        __send_new_grp_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    grp = __grp_create(gid, title, sc->id);
    if (!grp) {
        __send_new_grp_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    ent = __sync_ent_create(grp, sc);
    if (!ent) {
        __send_new_grp_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    ev = __enc_new_grp_ev(gid, title, sc->id, strcpy(name, fi->info.user_info.name),
                          svr->ver + 1, &len);
    if (!ev) {
        __send_new_grp_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    rc = __db_store_grp(svr->db, grp, name, ev, len, svr->ver + 1);
    if (rc < 0) {
        __send_new_grp_err_rsp_and_rm_sc_if_fail(svr, fi, rc);
        goto cleanup;
    }

    linked_hashtable_put(ent->grp->scs, &ent->ghe);
    linked_hashtable_put(ent->sc->grps, &ent->sche);

    linked_hashtable_put(svr->grps, &grp->he);
    ++svr->ver;

    __send_new_grp_rsp_and_rm_sc_if_fail(svr, fi, svr->ver, name);

cleanup:
    deref(sc);
    deref(ent);
    deref(grp);
    if (ev)
        free(ev);
}

static void __hdl_leave_grp_req(ManagedGroupServer *svr, FriendInfo *fi, Packet *cp)
{
    synced_client_t *sc = NULL;
    group_t *grp = NULL;
    void *ev = NULL;
    sync_entry_t *ent;
    const char *gid;
    size_t len;
    int rc;

    sc = __synced_client_get(svr, fi->info.user_info.userid);
    if (!sc)
        return;

    gid = packet_get_group_id(cp);
    if (!gid || !*gid || !is_valid_key(gid)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    grp = __grp_get(svr, gid);
    if (!grp) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    if (!__sync_ent_exist(svr, sc->id, grp->id)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    if (!strcmp(grp->admin, sc->id)) {
        ev = __enc_grp_dismiss_ev(grp->id, svr->ver + 1, &len);
        if (!ev) {
            __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            goto cleanup;
        }

        rc = __db_del_grp(svr->db, grp, ev, len, svr->ver + 1);
        if (rc < 0) {
            __send_err_rsp_and_rm_sc_if_fail(svr, fi, rc);
            goto cleanup;
        }

        __send_rsp_and_notify_rest_and_rm_sc_if_fail(svr, grp, fi, svr->ver + 1, ev, len);

        deref(linked_hashtable_remove(svr->grps, gid, strlen(gid)));

        hashtable_foreach(grp->scs, ent, {
            deref(linked_hashtable_remove(ent->sc->grps, gid, strlen(gid)));
            hashtable_foreach_remove_cur_entry();
        });

        ++svr->ver;
    } else {
        ev = __enc_peer_leave_ev(grp->id, sc->id, svr->ver + 1, &len);
        if (!ev) {
            __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            goto cleanup;
        }

        rc = __db_del_peer(svr->db, PACKET_TYPE_MGRP_PEER_LEFT, grp, sc->id, ev, len, svr->ver + 1);
        if (rc < 0) {
            __send_err_rsp_and_rm_sc_if_fail(svr, fi, rc);
            goto cleanup;
        }

        __send_rsp_and_notify_rest_and_rm_sc_if_fail(svr, grp, fi, svr->ver + 1, ev, len);

        ent = __sync_ent_get(svr, sc->id, grp->id);
        if (ent) {
            deref(linked_hashtable_remove(ent->sc->grps, ent->grp->id, strlen(ent->grp->id)));
            deref(linked_hashtable_remove(ent->grp->scs, ent->sc->id, strlen(ent->sc->id)));
            deref(ent);
        }

        ++svr->ver;
    }

cleanup:
    deref(sc);
    deref(grp);
    if (ev)
        free(ev);
}

static void __hdl_join_grp_req(ManagedGroupServer *svr, FriendInfo *fi, Packet *cp)
{
    synced_client_t *sc = NULL;
    sync_entry_t *ent = NULL;
    group_t *grp = NULL;
    void *ev = NULL;
    char name[CARRIER_MAX_USER_NAME_LEN + 1];
    const char *gid;
    size_t len;
    int rc;

    sc = __synced_client_get(svr, fi->info.user_info.userid);
    if (!sc)
        return;

    gid = packet_get_group_id(cp);
    if (!gid || !*gid || !is_valid_key(gid)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    grp = __grp_get(svr, gid);
    if (!grp) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    if (__sync_ent_exist(svr, sc->id, grp->id)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    ev = __enc_join_ev(grp->id, fi->info.user_info.userid, strcpy(name, fi->info.user_info.name),
                       svr->ver + 1, &len);
    if (!ev) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    ent = __sync_ent_create(grp, sc);
    if (!ent) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    rc = __db_join_grp(svr->db, sc->id, name, grp, ev, len, svr->ver + 1);
    if (rc < 0) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, rc);
        goto cleanup;
    }

    linked_hashtable_put(ent->grp->scs, &ent->ghe);
    linked_hashtable_put(ent->sc->grps, &ent->sche);

    ++svr->ver;

    __send_join_rsp_and_notify_rest_and_rm_sc_if_fail(svr, grp, fi, svr->ver, ev, len);

cleanup:
    deref(sc);
    deref(grp);
    deref(ent);
    if (ev)
        free(ev);
}

static void __hdl_kick_req(ManagedGroupServer *svr, FriendInfo *fi, Packet *cp)
{
    synced_client_t *sc = NULL;
    sync_entry_t *ent = NULL;
    group_t *grp = NULL;
    void *ev = NULL;
    const char *peer_id;
    const char *gid;
    bool is_peer;
    size_t len;
    int rc;

    sc = __synced_client_get(svr, fi->info.user_info.userid);
    if (!sc)
        return;

    gid = packet_get_group_id(cp);
    peer_id = packet_get_peer_id(cp);
    if (!gid || !*gid || !is_valid_key(gid) ||
        !peer_id || !*peer_id || !is_valid_key(peer_id)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    grp = __grp_get(svr, gid);
    if (!grp) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    if (strcmp(fi->info.user_info.userid, grp->admin)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        goto cleanup;
    }

    if (!strcmp(peer_id, grp->admin)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    rc = __db_is_peer(svr->db, peer_id, grp, &is_peer);
    if (rc < 0 || !is_peer) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    ev = __enc_kick_ev(grp->id, peer_id, svr->ver + 1, &len);
    if (!ev) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    rc = __db_del_peer(svr->db, PACKET_TYPE_MGRP_PEER_KICKED, grp, peer_id, ev, len, svr->ver + 1);
    if (rc < 0) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, rc);
        goto cleanup;
    }

    __send_rsp_and_notify_rest_and_rm_sc_if_fail(svr, grp, fi, svr->ver + 1, ev, len);

    ent = __sync_ent_get(svr, peer_id, grp->id);
    if (ent) {
        deref(linked_hashtable_remove(ent->sc->grps, ent->grp->id, strlen(ent->grp->id)));
        deref(linked_hashtable_remove(ent->grp->scs, ent->sc->id, strlen(ent->sc->id)));
    }

    ++svr->ver;

cleanup:
    deref(sc);
    deref(ent);
    deref(grp);
    if (ev)
        free(ev);
}

static void __hdl_msg_req(ManagedGroupServer *svr, FriendInfo *fi, Packet *cp)
{
    synced_client_t *sc = NULL;
    group_t *grp = NULL;
    void *ev = NULL;
    const void *msg;
    const char *gid;
    size_t ev_len;
    size_t len;

    sc = __synced_client_get(svr, fi->info.user_info.userid);
    if (!sc)
        return;

    gid = packet_get_group_id(cp);
    msg = packet_get_raw_data(cp);
    len = packet_get_raw_data_length(cp);
    if (!gid || !*gid || !is_valid_key(gid) || !msg || !len) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    grp = __grp_get(svr, gid);
    if (!grp) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    if (!__sync_ent_exist(svr, sc->id, grp->id)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        goto cleanup;
    }

    ev = __enc_grp_msg_ev(grp->id, sc->id, msg, len, &ev_len);
    if (!ev) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    __send_rsp_and_notify_rest_and_rm_sc_if_fail(svr, grp, fi, NOT_A_VER, ev, ev_len);

cleanup:
    deref(sc);
    deref(grp);
    if (ev)
        free(ev);
}

static void __hdl_set_title_req(ManagedGroupServer *svr, FriendInfo *fi, Packet *cp)
{
    synced_client_t *sc = NULL;
    group_t *grp = NULL;
    void *ev = NULL;
    const char *title;
    const char *gid;
    size_t len;
    int rc;

    sc = __synced_client_get(svr, fi->info.user_info.userid);
    if (!sc)
        return;

    gid = packet_get_group_id(cp);
    title = packet_get_title(cp);
    if (!gid || !*gid || !is_valid_key(gid) ||
        !title || !*title || strlen(title) > CARRIER_MAX_GROUP_TITLE_LEN) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    grp = __grp_get(svr, gid);
    if (!grp) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    if (strcmp(fi->info.user_info.userid, grp->admin)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_WRONG_STATE));
        goto cleanup;
    }

    if (!strcmp(grp->title, title)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    ev = __enc_title_change_ev(grp->id, title, svr->ver + 1, &len);
    if (!ev) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    rc = __db_upd_grp_title(svr->db, grp, title, ev, len);
    if (rc < 0) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, rc);
        goto cleanup;
    }

    strcpy(grp->title, title);
    ++svr->ver;

    __send_rsp_and_notify_rest_and_rm_sc_if_fail(svr, grp, fi, svr->ver, ev, len);

cleanup:
    deref(sc);
    deref(grp);
    if (ev)
        free(ev);
}

static void __hdl_set_name_req(ManagedGroupServer *svr, FriendInfo *fi, Packet *cp)
{
    synced_client_t *sc = NULL;
    group_t *grp = NULL;
    void *ev = NULL;
    const char *grp_id;
    const char *name;
    size_t len;
    int rc;

    sc = __synced_client_get(svr, fi->info.user_info.userid);
    if (!sc)
        return;

    grp_id = packet_get_group_id(cp);
    name = packet_get_name(cp);
    if (!grp_id || !*grp_id || !is_valid_key(grp_id) ||
        !name || !*name || strlen(name) > CARRIER_MAX_USER_NAME_LEN) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    grp = __grp_get(svr, grp_id);
    if (!grp) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    if (!__sync_ent_exist(svr, sc->id, grp->id)) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        goto cleanup;
    }

    ev = __enc_name_change_ev(grp->id, sc->id, name, svr->ver + 1, &len);
    if (!ev) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        goto cleanup;
    }

    rc = __db_upd_name(svr->db, grp, sc->id, name, ev, len);
    if (rc < 0) {
        __send_err_rsp_and_rm_sc_if_fail(svr, fi, rc);
        goto cleanup;
    }

    ++svr->ver;

    __send_rsp_and_notify_rest_and_rm_sc_if_fail(svr, grp, fi, svr->ver, ev, len);

cleanup:
    deref(sc);
    deref(grp);
    if (ev)
        free(ev);
}

void managed_group_server_handle_packet(ManagedGroupServer *svr, uint32_t fnum, Packet *cp)
{
    FriendInfo *fi;

    fi = friends_get(svr->w->friends, fnum);
    if (!fi)
        return;

    pthread_mutex_lock(&svr->lock);

    switch(packet_get_type(cp)) {
    case PACKET_TYPE_MGRP_SYNC_REQ:
        __hdl_sync_req(svr, fi, cp);
        break;
    case PACKET_TYPE_MGRP_NEW_REQ:
        __hdl_new_grp_req(svr, fi, cp);
        break;
    case PACKET_TYPE_MGRP_LEAVE_REQ:
        __hdl_leave_grp_req(svr, fi, cp);
        break;
    case PACKET_TYPE_MGRP_JOIN_REQ:
        __hdl_join_grp_req(svr, fi, cp);
        break;
    case PACKET_TYPE_MGRP_KICK_REQ:
        __hdl_kick_req(svr, fi, cp);
        break;
    case PACKET_TYPE_MGRP_MSG_REQ:
        __hdl_msg_req(svr, fi, cp);
        break;
    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
        __hdl_set_title_req(svr, fi, cp);
        break;
    case PACKET_TYPE_MGRP_SET_NAME_REQ:
        __hdl_set_name_req(svr, fi, cp);
        break;
    }

    pthread_mutex_unlock(&svr->lock);

    deref(fi);
}

void managed_group_server_handle_client_disconnected(ManagedGroupServer *svr, const char *cid)
{
    pthread_mutex_lock(&svr->lock);

    __synced_client_rm(svr, cid);

    pthread_mutex_unlock(&svr->lock);
}
