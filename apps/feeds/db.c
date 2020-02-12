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

#include <sqlite3.h>

#include "db.h"

static sqlite3 *db;

int db_initialize(const char *db_file)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sqlite3_initialize();

    rc = sqlite3_open_v2(db_file, &db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                         NULL);
    if (rc)
        goto failure;

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS users "
          "("
          "    user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
          "    node_id TEXT    NOT NULL UNIQUE CHECK(node_id != '')"
          ")";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto failure;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto failure;

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS topics "
          "("
          "    topic_id INTEGER PRIMARY KEY AUTOINCREMENT,"
          "    user_id  INTEGER NOT NULL REFERENCES users(user_id),"
          "    name     TEXT    NOT NULL UNIQUE CHECK(name != ''),"
          "    desc     TEXT    NOT NULL CHECK(desc != '')"
          ")";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto failure;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto failure;

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS topic_events "
          "("
          "    topic_id INTEGER NOT NULL REFERENCES topics(topic_id),"
          "    seqno    INTEGER NOT NULL,"
          "    content  BLOB    NOT NULL,"
          "    ts       INTEGER NOT NULL,"
          "    PRIMARY KEY(topic_id, seqno)"
          ")";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto failure;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto failure;

    /* ================================= stmt-sep ================================= */
    sql = "CREATE TABLE IF NOT EXISTS subscriptions "
          "("
          "    user_id  INTEGER NOT NULL REFERENCES users(user_id),"
          "    topic_id INTEGER NOT NULL REFERENCES topics(topic_id),"
          "    PRIMARY KEY(user_id, topic_id)"
          ")";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        goto failure;

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        goto failure;

    return 0;

failure:
    db_finalize();
    return -1;
}

int db_iterate_topics(int (*it)(uint64_t id, const char *name, const char *desc,
                                uint64_t next_seqno, const char *publisher))
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "SELECT topic_id, topics.name, topics.desc, "
          "       MAX(CASE WHEN seqno IS NULL THEN 0 ELSE seqno END) + 1, "
          "       node_id "
          "FROM topics JOIN users USING(user_id) "
          "     LEFT OUTER JOIN topic_events USING(topic_id) "
          "GROUP BY topic_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (it(sqlite3_column_int64(stmt, 0),
               (const char *)sqlite3_column_text(stmt, 1),
               (const char *)sqlite3_column_text(stmt, 2),
               sqlite3_column_int64(stmt, 3),
               (const char *)sqlite3_column_text(stmt, 4)))
            break;
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return -1;

    return 0;
}

int db_add_topic(const char *name, const char *node_id, const char *desc)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT OR IGNORE INTO users (node_id) VALUES (:node_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":node_id"),
                           node_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return -1;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO topics (user_id, name, desc) "
          "VALUES ((SELECT user_id FROM users WHERE node_id = :node_id), :name, :desc)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":node_id"),
                           node_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":name"),
                           name, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":desc"),
                           desc, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return -1;

    return 0;
}

int db_add_event(uint64_t topic_id, uint64_t seqno, const void *content,
                 size_t len, uint64_t ts)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT INTO topic_events (topic_id, seqno, content, ts) "
          "VALUES (:topic_id, :seqno, :content, :ts)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":topic_id"),
                            topic_id);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":seqno"),
                            seqno);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_bind_blob(stmt,
                           sqlite3_bind_parameter_index(stmt, ":content"),
                           content, len, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":ts"),
                            ts);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return -1;

    return 0;
}

int db_add_subscriber(uint64_t topic_id, const char *node_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT OR IGNORE INTO users (node_id) VALUES (:node_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":node_id"),
                           node_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return -1;

    /* ================================= stmt-sep ================================= */
    sql = "INSERT OR IGNORE INTO subscriptions (user_id, topic_id) "
          "VALUES ((SELECT user_id FROM users WHERE node_id = :node_id), :topic_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":node_id"),
                           node_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":topic_id"),
                            topic_id);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return -1;

    return 0;
}

int db_unsubscribe(uint64_t topic_id, const char *node_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "DELETE FROM subscriptions "
          "WHERE user_id = (SELECT user_id FROM users WHERE node_id = :node_id) AND "
          "      topic_id = :topic_id";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":node_id"),
                           node_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":topic_id"),
                            topic_id);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return -1;

    return 0;
}

int db_fetch_events(uint64_t topic_id, uint64_t since, cJSON **result)
{
    sqlite3_stmt *stmt;
    const char *sql;
    cJSON *events;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "SELECT seqno, content, ts "
          "FROM topic_events WHERE topic_id = :topic_id AND seqno >= :since "
          "ORDER BY seqno ASC";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":topic_id"),
                            topic_id);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":since"),
                            since);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    events = cJSON_CreateArray();
    if (!events) {
        sqlite3_finalize(stmt);
        return -1;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cJSON *ev = cJSON_CreateObject();
        if (!ev)
            break;

        cJSON_AddItemToArray(events, ev);

        if (!cJSON_AddNumberToObject(ev, "seqno",
                                     (double)sqlite3_column_int64(stmt, 0)))
            break;

        if (!cJSON_AddStringToObject(ev, "event",
                                     sqlite3_column_blob(stmt, 1)))
            break;

        if (!cJSON_AddNumberToObject(ev, "ts",
                                     sqlite3_column_int64(stmt, 2)))
            break;
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        cJSON_Delete(events);
        return -1;
    }

    *result = events;

    return 0;
}

int db_list_owned_topics(const char *node_id, cJSON **result)
{
    sqlite3_stmt *stmt;
    const char *sql;
    cJSON *topics;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "SELECT name, desc "
          "FROM topics WHERE user_id = (SELECT user_id FROM users WHERE node_id = :node_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":node_id"),
                           node_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    topics = cJSON_CreateArray();
    if (!topics) {
        sqlite3_finalize(stmt);
        return -1;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cJSON *topic = cJSON_CreateObject();
        if (!topic)
            break;

        cJSON_AddItemToArray(topics, topic);

        if (!cJSON_AddStringToObject(topic, "name",
                                     (const char *)sqlite3_column_text(stmt, 0)))
            break;

        if (!cJSON_AddStringToObject(topic, "desc",
                                     (const char *)sqlite3_column_text(stmt, 1)))
            break;
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        cJSON_Delete(topics);
        return -1;
    }

    *result = topics;

    return 0;
}

int db_list_subscribed_topics(const char *node_id, cJSON **result)
{
    sqlite3_stmt *stmt;
    const char *sql;
    cJSON *topics;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "SELECT topics.name, topics.desc "
          "FROM (SELECT topic_id "
          "      FROM subscriptions "
          "      WHERE user_id = (SELECT user_id FROM users WHERE node_id = :node_id)) "
          "      JOIN topics USING(topic_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":node_id"),
                           node_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    topics = cJSON_CreateArray();
    if (!topics) {
        sqlite3_finalize(stmt);
        return -1;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cJSON *topic = cJSON_CreateObject();
        if (!topic)
            break;

        cJSON_AddItemToArray(topics, topic);

        if (!cJSON_AddStringToObject(topic, "name",
                                     (const char *)sqlite3_column_text(stmt, 0)))
            break;

        if (!cJSON_AddStringToObject(topic, "desc",
                                     (const char *)sqlite3_column_text(stmt, 1)))
            break;
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        cJSON_Delete(topics);
        return -1;
    }

    *result = topics;

    return 0;
}

bool db_is_subscriber(uint64_t topic_id, const char *node_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    /* ================================= stmt-sep ================================= */
    sql = "SELECT "
          "EXISTS(SELECT * FROM subscriptions "
          "       WHERE user_id = (SELECT user_id FROM users WHERE node_id = :node_id) AND "
          "             topic_id = :topic_id)";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc)
        return -1;

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":node_id"),
                           node_id, -1, NULL);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":topic_id"),
                            topic_id);
    if (rc) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc =  sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return rc ? true : false;
}

void db_finalize()
{
    sqlite3_close(db);
    sqlite3_shutdown();
}
