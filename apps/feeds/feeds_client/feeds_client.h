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

#ifndef __FEEDS_CLIENT_H__
#define __FEEDS_CLIENT_H__

#include <ela_carrier.h>
#include <cjson/cJSON.h>

typedef struct FeedsClient FeedsClient;

FeedsClient *feeds_client_create(ElaOptions *opts);

void feeds_client_wait_until_online(FeedsClient *fc);

void feeds_client_delete(FeedsClient *fc);

ElaCarrier *feeds_client_get_carrier(FeedsClient *fc);

int feeds_client_friend_add(FeedsClient *fc, const char *address, const char *hello);

int feeds_client_wait_until_friend_connected(FeedsClient *fc, const char *friend_node_id);

int feeds_client_friend_remove(FeedsClient *fc, const char *user_id);

int feeds_client_create_topic(FeedsClient *fc, const char *svc_node_id, const char *name,
                              const char *desc, cJSON **resp);

int feeds_client_post_event(FeedsClient *fc, const char *svc_node_id, const char *topic,
                            const char *content, cJSON **resp);

int feeds_client_list_owned_topics(FeedsClient *fc, const char *svc_node_id, cJSON **resp);

int feeds_client_subscribe(FeedsClient *fc, const char *svc_node_id,
                           const char *topic, cJSON **resp);

int feeds_client_unsubscribe(FeedsClient *fc, const char *svc_node_id,
                             const char *topic, cJSON **resp);

int feeds_client_explore_topics(FeedsClient *fc, const char *svc_node_id, cJSON **resp);

int feeds_client_list_subscribed(FeedsClient *fc, const char *svc_node_id, cJSON **resp);

int feeds_client_fetch_unreceived(FeedsClient *fc, const char *svc_node_id,
                                  const char *topic, size_t since, cJSON **resp);

cJSON *feeds_client_get_new_events(FeedsClient *fc);

#endif // __FEEDS_CLIENT_H__
