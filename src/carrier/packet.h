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

#ifndef __CARRIER_PACKET_H__
#define __CARRIER_PACKET_H__

#include <stdint.h>
#include <stdbool.h>
#include "carrier.h"

typedef struct Packet Packet;

/* WMCP types */
#define PACKET_TYPE_MIN                        1

#define PACKET_TYPE_USERINFO                   3

#define PACKET_TYPE_FRIEND_REQUEST             6
#define PACKET_TYPE_FRIEND_REMOVE              7

#define PACKET_TYPE_MESSAGE                    33
#define PACKET_TYPE_INVITE_REQUEST             34
#define PACKET_TYPE_INVITE_RESPONSE            35
#define PACKET_TYPE_BULKMSG                    36

#define PACKET_TYPE_MAX                        95

Packet *packet_create(uint8_t type, const char *ext_name);

void packet_free(Packet *packet);

int packet_get_type(Packet *packet);

const char *packet_get_extension(Packet *packet);

const char *packet_get_name(Packet *packet);

const char *packet_get_descr(Packet *packet);

bool packet_get_has_avatar(Packet *packet);

const char *packet_get_gender(Packet *packet);

const char *packet_get_phone(Packet *packet);

const char *packet_get_email(Packet *packet);

const char *packet_get_region(Packet *packet);

const char *packet_get_hello(Packet *packet);

int64_t packet_get_tid(Packet *packet);

size_t packet_get_totalsz(Packet *packet);

int packet_get_status(Packet *packet);

const void *packet_get_raw_data(Packet *packet);

size_t packet_get_raw_data_length(Packet *packet);

const char *packet_get_bundle(Packet *packet);

const char *packet_get_reason(Packet *packet);

void packet_set_name(Packet *packet, const char *name);

void packet_set_descr(Packet *packet, const char *descr);

void packet_set_has_avatar(Packet *packet, int has_avatar);

void packet_set_gender(Packet *packet, const char *gender);

void packet_set_phone(Packet *packet, const char *phone);

void packet_set_email(Packet *packet, const char *email);

void packet_set_region(Packet *packet, const char *region);

void packet_set_hello(Packet *packet, const char *hello);

void packet_set_tid(Packet *packet, int64_t *tid);

void packet_set_totalsz(Packet *packet, size_t totalsz);

void packet_set_status(Packet *packet, int status);

void packet_set_raw_data(Packet *packet, const void *data, size_t len);

void packet_set_bundle(Packet *packet, const char *bundle);

void packet_set_reason(Packet *packet, const char *reason);

uint8_t *packet_encode(Packet *packet, size_t *len);

Packet *packet_decode(const uint8_t *buf, size_t len);


typedef struct PacketPullMsg {
  uint64_t id;
  const char *from;
  uint8_t type;
  uint64_t timestamp;
  const char *address;
  const uint8_t *payload;
  size_t payload_sz;
} PacketPullMsg;
int packet_decode_pullmsg(const uint8_t *buf, PacketPullMsg *pullmsg);

#endif /* __CARRIER_CONTROL_PACKET_H__ */
