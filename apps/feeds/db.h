#ifndef __DB_H__
#define __DB_H__

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

#include <stdbool.h>
#include <stdint.h>

#include <cjson/cJSON.h>

int db_initialize(const char *db_file);

int db_iterate_topics(int (*it)(uint64_t id, const char *name, const char *desc,
                                uint64_t next_seqno, const char *publisher));

int db_add_topic(const char *name, const char *node_id, const char *desc);

int db_add_event(uint64_t topic_id, uint64_t seqno, const void *content,
                 size_t len, uint64_t ts);

int db_add_subscriber(uint64_t topic_id, const char *node_id);

int db_unsubscribe(uint64_t topic_id, const char *node_id);

int db_fetch_events(uint64_t topic_id, uint64_t since, cJSON **result);

int db_list_owned_topics(const char *node_id, cJSON **result);

int db_list_subscribed_topics(const char *node_id, cJSON **result);

bool db_is_subscriber(uint64_t topic_id, const char *node_id);

void db_finalize();

#endif // __DB_H__
