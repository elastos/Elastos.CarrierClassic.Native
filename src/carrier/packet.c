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

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>

#include "packet.h"
#include "packet_generated.h"
#include "flatcc/support/hexdump.h"

#pragma pack(push, 1)

struct Packet {
    uint8_t type;
    const char *ext;
};

struct PacketUserInfo {
    Packet header;
    bool has_avatar;
    const char *name;
    const char *descr;
    const char *phone;
    const char *gender;
    const char *email;
    const char *region;
};

struct PacketFriendReq {
    Packet header;
    const char *name;
    const char *descr;
    const char *hello;
};

struct PacketFriendMsg {
    Packet headr;
    size_t len;
    const uint8_t *msg;
};

struct PacketInviteReq {
    Packet header;
    int64_t tid;
    const char *bundle;
    size_t totalsz;
    size_t len;
    const uint8_t *data;
};

struct PacketInviteRsp {
    Packet header;
    int64_t tid;
    const char *bundle;
    size_t totalsz;
    int status;
    const char *reason;
    size_t len;
    const uint8_t *data;
};

struct PacketBulkMsg {
    Packet headr;
    int64_t tid;
    size_t totalsz;
    size_t len;
    const uint8_t *data;
};

#pragma pack(pop)

#define pktinfo pkt.u.pkt_info
#define pktfreq pkt.u.pkt_freq
#define pktfmsg pkt.u.pkt_fmsg
#define pktireq pkt.u.pkt_ireq
#define pktirsp pkt.u.pkt_irsp
#define pktbmsg pkt.u.pkt_bmsg

#define tblinfo tbl.u.tbl_info
#define tblfreq tbl.u.tbl_freq
#define tblfmsg tbl.u.tbl_fmsg
#define tblireq tbl.u.tbl_ireq
#define tblirsp tbl.u.tbl_irsp
#define tblbmsg tbl.u.tbl_bmsg

struct elacp_packet_t {
    union {
        struct Packet         *cp;
        struct PacketUserInfo  *pkt_info;
        struct PacketFriendReq *pkt_freq;
        struct PacketFriendMsg *pkt_fmsg;
        struct PacketInviteReq *pkt_ireq;
        struct PacketInviteRsp *pkt_irsp;
        struct PacketBulkMsg   *pkt_bmsg;
    } u;
};

struct elacp_table_t {
    union {
        carrier_userinfo_table_t  tbl_info;
        carrier_friendreq_table_t tbl_freq;
        carrier_friendmsg_table_t tbl_fmsg;
        carrier_invitereq_table_t tbl_ireq;
        carrier_invitersp_table_t tbl_irsp;
        carrier_bulkmsg_table_t   tbl_bmsg;
    } u;
};

Packet *packet_create(uint8_t type, const char *ext_name)
{
    Packet *cp;
    size_t len;

    switch(type) {
    case PACKET_TYPE_USERINFO:
        len = sizeof(struct PacketUserInfo);
        break;
    case PACKET_TYPE_FRIEND_REQUEST:
        len = sizeof(struct PacketFriendReq);
        break;
    case PACKET_TYPE_MESSAGE:
        len = sizeof(struct PacketFriendMsg);
        break;
    case PACKET_TYPE_INVITE_REQUEST:
        len = sizeof(struct PacketInviteReq);
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        len = sizeof(struct PacketInviteRsp);
        break;
    case PACKET_TYPE_BULKMSG:
        len = sizeof(struct PacketBulkMsg);
        break;
    default:
        assert(0);
        return NULL;
    }

    cp = (Packet *)calloc(1, len);
    if (!cp)
        return NULL;

    cp->type = type;
    cp->ext  = ext_name;

    return cp;
}

void packet_free(Packet *cp)
{
    if (cp)
        free(cp);
}

int packet_get_type(Packet *cp)
{
    assert(cp);

    return cp->type;
}

const char *packet_get_extension(Packet *cp)
{
    assert(cp);

    return cp->ext;
}

const char *packet_get_name(Packet *cp)
{
    struct elacp_packet_t pkt;
    const char *name = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        name = pktinfo->name;
        break;
    case PACKET_TYPE_FRIEND_REQUEST:
        name = pktfreq->name;
        break;
    default:
        assert(0);
        break;
    }

    return name;
}

const char *packet_get_descr(Packet *cp)
{
    struct elacp_packet_t pkt;
    const char *descr = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        descr = pktinfo->descr;
        break;
    case PACKET_TYPE_FRIEND_REQUEST:
        descr = pktfreq->descr;
        break;
    default:
        assert(0);
        break;
    }

    return descr;
}

const char *packet_get_gender(Packet *cp)
{
    struct elacp_packet_t pkt;
    const char *gender = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        gender = pktinfo->gender;
        break;
    default:
        assert(0);
        break;
    }

    return gender;
}

const char *packet_get_phone(Packet *cp)
{
    struct elacp_packet_t pkt;
    const char *phone = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        phone = pktinfo->phone;
        break;
    default:
        assert(0);
        break;
    }

    return phone;
}

const char *packet_get_email(Packet *cp)
{
    struct elacp_packet_t pkt;
    const char *email = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        email = pktinfo->email;
        break;
    default:
        assert(0);
        break;
    }

    return email;
}

const char *packet_get_region(Packet *cp)
{
    struct elacp_packet_t pkt;
    const char *region = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        region = pktinfo->region;
        break;
    default:
        assert(0);
        break;
    }

    return region;
}

bool packet_get_has_avatar(Packet *cp)
{
    struct elacp_packet_t pkt;
    bool has_avatar = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        has_avatar = pktinfo->has_avatar;
        break;
    default:
        assert(0);
        break;
    }

    return has_avatar;
}

const char *packet_get_hello(Packet *cp)
{
    struct elacp_packet_t pkt;
    const char *hello = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_FRIEND_REQUEST:
        hello = pktfreq->hello;
        break;
    default:
        assert(0);
        break;
    }

    return hello;
}

int64_t packet_get_tid(Packet *cp)
{
    struct elacp_packet_t pkt;
    int64_t tid = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_REQUEST:
        tid = pktireq->tid;
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        tid = pktirsp->tid;
        break;
    case PACKET_TYPE_BULKMSG:
        tid = pktbmsg->tid;
        break;
    default:
        assert(0);
        break;
    }

    return tid;
}

size_t packet_get_totalsz(Packet *cp)
{
    struct elacp_packet_t pkt;
    size_t totalsz = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_REQUEST:
        totalsz = pktireq->totalsz;
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        totalsz = pktirsp->totalsz;
        break;
    case PACKET_TYPE_BULKMSG:
        totalsz = pktbmsg->totalsz;
        break;
    default:
        assert(0);
        break;
    }

    return totalsz;
}

int packet_get_status(Packet *cp)
{
    struct elacp_packet_t pkt;
    int status = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_RESPONSE:
        status = pktirsp->status;
        break;
    default:
        assert(0);
        break;
    }

    return status;
}

const void *packet_get_raw_data(Packet *cp)
{
    struct elacp_packet_t pkt;
    const void *data = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MESSAGE:
        data = pktfmsg->msg;
        break;
    case PACKET_TYPE_INVITE_REQUEST:
        data = pktireq->data;
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        data = pktirsp->data;
        break;
    case PACKET_TYPE_BULKMSG:
        data = pktbmsg->data;
        break;
    default:
        assert(0);
        break;
    }

    return data;
}

size_t packet_get_raw_data_length(Packet *cp)
{
    struct elacp_packet_t pkt;
    size_t len = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MESSAGE:
        len = pktfmsg->len;
        break;
    case PACKET_TYPE_INVITE_REQUEST:
        len = pktireq->len;
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        len = pktirsp->len;
        break;
    case PACKET_TYPE_BULKMSG:
        len = pktbmsg->len;
        break;
    default:
        assert(0);
        break;
    }

    return len;
}

const char *packet_get_bundle(Packet *cp)
{
     struct elacp_packet_t pkt;
     const char *bundle = NULL;

     assert(cp);
     pkt.u.cp = cp;

     switch(cp->type) {
     case PACKET_TYPE_INVITE_REQUEST:
         bundle = pktireq->bundle;
         break;
     case PACKET_TYPE_INVITE_RESPONSE:
         bundle = pktirsp->bundle;
         break;
     default:
         assert(0);
         break;
     }

     return bundle;
 }

const char *packet_get_reason(Packet *cp)
{
    struct elacp_packet_t pkt;
    const char *reason = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_RESPONSE:
        reason = pktirsp->reason;
        break;
    default:
        assert(0);
        break;
    }

    return reason;
}

void packet_set_name(Packet *cp, const char *name)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(name);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        pktinfo->name = name;
        break;
    case PACKET_TYPE_FRIEND_REQUEST:
        pktfreq->name = name;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_descr(Packet *cp, const char *descr)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(descr);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        pktinfo->descr = descr;
        break;
    case PACKET_TYPE_FRIEND_REQUEST:
        pktfreq->descr = descr;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_gender(Packet *cp, const char *gender)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(gender);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        pktinfo->gender = gender;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_phone(Packet *cp, const char *phone)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(phone);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        pktinfo->phone = phone;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_email(Packet *cp, const char *email)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(email);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        pktinfo->email = email;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_region(Packet *cp, const char *region)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(region);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        pktinfo->region = region;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_has_avatar(Packet *cp, int has_avatar)
{
    struct elacp_packet_t pkt;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        pktinfo->has_avatar = !!has_avatar;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_hello(Packet *cp, const char *hello)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(hello);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_FRIEND_REQUEST:
        pktfreq->hello = hello;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_tid(Packet *cp, int64_t *tid)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(tid);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_REQUEST:
        pktireq->tid = *tid;
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        pktirsp->tid = *tid;
        break;
    case PACKET_TYPE_BULKMSG:
        pktbmsg->tid = *tid;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_totalsz(Packet *cp, size_t totalsz)
{
    struct elacp_packet_t pkt;

    assert(cp);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_REQUEST:
        pktireq->totalsz = totalsz;
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        pktirsp->totalsz = totalsz;
        break;
    case PACKET_TYPE_BULKMSG:
        pktbmsg->totalsz = totalsz;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_status(Packet *cp, int status)
{
    struct elacp_packet_t pkt;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_RESPONSE:
        pktirsp->status = status;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_raw_data(Packet *cp, const void *data, size_t len)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(data);
    assert(len > 0);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MESSAGE:
        pktfmsg->msg = data;
        pktfmsg->len = len;
        break;
    case PACKET_TYPE_INVITE_REQUEST:
        pktireq->data = data;
        pktireq->len = len;
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        pktirsp->data = data;
        pktirsp->len = len;
        break;
    case PACKET_TYPE_BULKMSG:
        pktbmsg->data = data;
        pktbmsg->len = len;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_bundle(Packet *cp, const char *bundle)
 {
     struct elacp_packet_t pkt;
     assert(cp);

     pkt.u.cp = cp;

     switch(cp->type) {
     case PACKET_TYPE_INVITE_REQUEST:
         pktireq->bundle = bundle;
         break;
     case PACKET_TYPE_INVITE_RESPONSE:
         pktirsp->bundle = bundle;
         break;
     default:
         assert(0);
         break;
     }
}

void packet_set_reason(Packet *cp, const char *reason)
{
    struct elacp_packet_t pkt;

    assert(cp);
    assert(reason);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_RESPONSE:
        pktirsp->reason = reason;
        break;
    default:
        assert(0);
        break;
    }
}

uint8_t *packet_encode(Packet *cp, size_t *encoded_len)
{
    struct elacp_packet_t pkt;
    flatcc_builder_t builder;
    flatcc_builder_ref_t str;
    flatbuffers_uint8_vec_ref_t vec;
    flatbuffers_ref_t ref;
    carrier_anybody_union_ref_t body;
    uint8_t *encoded_data;

    assert(cp);
    assert(encoded_len);

    pkt.u.cp = cp;

    flatcc_builder_init(&builder);

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        carrier_userinfo_start(&builder);
        if (pktinfo->name) {
            str = flatcc_builder_create_string_str(&builder, pktinfo->name);
            carrier_userinfo_name_add(&builder, str);
        }
        str = flatcc_builder_create_string_str(&builder, pktinfo->descr);
        carrier_userinfo_descr_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktinfo->gender);
        carrier_userinfo_gender_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktinfo->phone);
        carrier_userinfo_phone_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktinfo->email);
        carrier_userinfo_email_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktinfo->region);
        carrier_userinfo_region_add(&builder, str);
        carrier_userinfo_avatar_add(&builder, pktinfo->has_avatar);
        ref = carrier_userinfo_end(&builder);
        break;

    case PACKET_TYPE_FRIEND_REQUEST:
        carrier_friendreq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktfreq->name);
        carrier_friendreq_name_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktfreq->descr);
        carrier_friendreq_descr_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktfreq->hello);
        carrier_friendreq_hello_add(&builder, str);
        ref = carrier_friendreq_end(&builder);
        break;

    case PACKET_TYPE_MESSAGE:
        carrier_friendmsg_start(&builder);
        if (cp->ext) {
            str = flatcc_builder_create_string_str(&builder, cp->ext);
            carrier_friendmsg_ext_add(&builder, str);
        }

        vec = flatbuffers_uint8_vec_create(&builder, pktfmsg->msg, pktfmsg->len);
        carrier_friendmsg_msg_add(&builder, vec);
        ref = carrier_friendmsg_end(&builder);
        break;

    case PACKET_TYPE_INVITE_REQUEST:
        carrier_invitereq_start(&builder);
        if (cp->ext) {
            str = flatcc_builder_create_string_str(&builder, cp->ext);
            carrier_invitereq_ext_add(&builder, str);
        }
        carrier_invitereq_tid_add(&builder, pktireq->tid);
        carrier_invitereq_totalsz_add(&builder, pktireq->totalsz);
        if (pktireq->bundle) {
             str = flatcc_builder_create_string_str(&builder, pktireq->bundle);
             carrier_invitereq_bundle_add(&builder, str);
        }
        vec = flatbuffers_uint8_vec_create(&builder, pktireq->data, pktireq->len);
        carrier_invitereq_data_add(&builder, vec);
        ref = carrier_invitereq_end(&builder);
        break;

    case PACKET_TYPE_INVITE_RESPONSE:
        carrier_invitersp_start(&builder);
        if (cp->ext) {
            str = flatcc_builder_create_string_str(&builder, cp->ext);
            carrier_invitersp_ext_add(&builder, str);
        }
        carrier_invitersp_tid_add(&builder, pktirsp->tid);
        carrier_invitersp_totalsz_add(&builder, pktirsp->totalsz);
        if (pktirsp->bundle) {
             str = flatcc_builder_create_string_str(&builder, pktirsp->bundle);
             carrier_invitersp_bundle_add(&builder, str);
        }
        carrier_invitersp_status_add(&builder, pktirsp->status);
        if (pktirsp->status && pktirsp->reason) {
            str = flatcc_builder_create_string_str(&builder, pktirsp->reason);
            carrier_invitersp_reason_add(&builder, str);
        } else {
            vec = flatbuffers_uint8_vec_create(&builder, pktirsp->data, pktirsp->len);
            carrier_invitersp_data_add(&builder, vec);
        }
        ref = carrier_invitersp_end(&builder);
        break;

    case PACKET_TYPE_BULKMSG:
        carrier_bulkmsg_start(&builder);
        if (cp->ext) {
            str = flatcc_builder_create_string_str(&builder, cp->ext);
            carrier_bulkmsg_ext_add(&builder, str);
        }
        carrier_bulkmsg_tid_add(&builder, pktbmsg->tid);
        carrier_bulkmsg_totalsz_add(&builder, pktbmsg->totalsz);
        vec = flatbuffers_uint8_vec_create(&builder, pktbmsg->data, pktbmsg->len);
        carrier_bulkmsg_data_add(&builder, vec);
        ref = carrier_bulkmsg_end(&builder);
        break;

    default:
        assert(0);
        ref = 0; // to clean builder.
        break;
    }

    if (!ref) {
        flatcc_builder_clear(&builder);
        return NULL;
    }

    switch(cp->type) {
    case PACKET_TYPE_USERINFO:
        body = carrier_anybody_as_userinfo(ref);
        break;
    case PACKET_TYPE_FRIEND_REQUEST:
        body = carrier_anybody_as_friendreq(ref);
        break;
    case PACKET_TYPE_MESSAGE:
        body = carrier_anybody_as_friendmsg(ref);
        break;
    case PACKET_TYPE_INVITE_REQUEST:
        body = carrier_anybody_as_invitereq(ref);
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        body = carrier_anybody_as_invitersp(ref);
        break;
    case PACKET_TYPE_BULKMSG:
        body = carrier_anybody_as_bulkmsg(ref);
        break;
    default:
        assert(0);
        return NULL;
    }

    carrier_packet_start_as_root(&builder);
    carrier_packet_type_add(&builder, cp->type);
    carrier_packet_body_add(&builder, body);
    if (!carrier_packet_end_as_root(&builder)) {
        flatcc_builder_clear(&builder);
        return NULL;
    }

    encoded_data = flatcc_builder_finalize_buffer(&builder, encoded_len);
    flatcc_builder_clear(&builder);

    return encoded_data;
}

Packet *packet_decode(const uint8_t *data, size_t len)
{
    Packet *cp;
    struct elacp_packet_t pkt;
    struct elacp_table_t  tbl;
    carrier_packet_table_t packet;
    flatbuffers_uint8_vec_t vec;
    uint8_t type;

    packet = carrier_packet_as_root(data);
    if (!packet)
        return NULL;

    type = carrier_packet_type(packet);
    switch(type) {
    case PACKET_TYPE_USERINFO:
    case PACKET_TYPE_FRIEND_REQUEST:
    case PACKET_TYPE_MESSAGE:
    case PACKET_TYPE_INVITE_REQUEST:
    case PACKET_TYPE_INVITE_RESPONSE:
    case PACKET_TYPE_BULKMSG:
        break;
    default:
        //TODO: clean resource for 'packet'; (how ?)
        return NULL;
    }

    cp = packet_create(type, NULL);
    if (!cp) {
        //TODO: clean resource for 'packet'; (how ?)
        return NULL;
    }
    pkt.u.cp = cp;

    if (!carrier_packet_body_is_present(packet)) {
        packet_free(cp);
        return NULL;
    }

    switch(type) {
    case PACKET_TYPE_USERINFO:
        tblinfo = carrier_packet_body(packet);
        if (carrier_userinfo_name_is_present(tblinfo))
            pktinfo->name = carrier_userinfo_name(tblinfo);
        pktinfo->descr  = carrier_userinfo_descr(tblinfo);
        pktinfo->gender = carrier_userinfo_gender(tblinfo);
        pktinfo->phone  = carrier_userinfo_phone(tblinfo);
        pktinfo->email  = carrier_userinfo_email(tblinfo);
        pktinfo->region = carrier_userinfo_region(tblinfo);
        pktinfo->has_avatar = carrier_userinfo_avatar(tblinfo);
        break;

    case PACKET_TYPE_FRIEND_REQUEST:
        tblfreq = carrier_packet_body(packet);
        pktfreq->name  = carrier_friendreq_name(tblfreq);
        pktfreq->descr = carrier_friendreq_descr(tblfreq);
        pktfreq->hello = carrier_friendreq_hello(tblfreq);
        break;

    case PACKET_TYPE_MESSAGE:
        tblfmsg = carrier_packet_body(packet);
        pktfmsg->msg = vec = carrier_friendmsg_msg(tblfmsg);
        pktfmsg->len = flatbuffers_uint8_vec_len(vec);
        if (carrier_friendmsg_ext_is_present(tblfmsg))
            cp->ext = carrier_friendmsg_ext(tblfmsg);
        break;

    case PACKET_TYPE_INVITE_REQUEST:
        tblireq = carrier_packet_body(packet);
        pktireq->tid = carrier_invitereq_tid(tblireq);
        pktireq->totalsz = carrier_invitereq_totalsz(tblireq);
        if (carrier_invitereq_bundle_is_present(tblireq))
             pktireq->bundle = carrier_invitereq_bundle(tblireq);
        pktireq->data = vec = carrier_invitereq_data(tblireq);
        pktireq->len = flatbuffers_uint8_vec_len(vec);
        if (carrier_invitereq_ext_is_present(tblireq))
            cp->ext = carrier_invitereq_ext(tblireq);
        break;

    case PACKET_TYPE_INVITE_RESPONSE:
        tblirsp = carrier_packet_body(packet);
        pktirsp->tid = carrier_invitersp_tid(tblirsp);
        pktireq->totalsz = carrier_invitersp_totalsz(tblirsp);
        if (carrier_invitersp_bundle_is_present(tblirsp))
             pktirsp->bundle = carrier_invitersp_bundle(tblirsp);
        pktirsp->status = carrier_invitersp_status(tblirsp);
        if (pktirsp->status)
            pktirsp->reason = carrier_invitersp_reason(tblirsp);
        else {
            pktirsp->data = vec = carrier_invitersp_data(tblirsp);
            pktirsp->len = flatbuffers_uint8_vec_len(vec);
        }
        if (carrier_invitersp_ext_is_present(tblirsp))
            cp->ext = carrier_invitersp_ext(tblirsp);
        break;

    case PACKET_TYPE_BULKMSG:
        tblbmsg = carrier_packet_body(packet);
        pktbmsg->tid = carrier_bulkmsg_tid(tblbmsg);
        pktbmsg->data = vec = carrier_bulkmsg_data(tblbmsg);
        pktbmsg->len = flatbuffers_uint8_vec_len(vec);
        pktbmsg->totalsz = carrier_bulkmsg_totalsz(tblbmsg);
        break;

    default:
        assert(0);
        break;
    }

    return cp;
}

int packet_decode_pullmsg(const uint8_t *data, PacketPullMsg *pullmsg)
{
    carrier_pullmsg_table_t pmsg_tbl;
    flatbuffers_uint8_vec_t vec;

    assert(data && pullmsg);
    memset(pullmsg, 0, sizeof(*pullmsg));

    pmsg_tbl = carrier_pullmsg_as_root(data);
    if (!pmsg_tbl)
        return -1;

    pullmsg->id = carrier_pullmsg_id(pmsg_tbl);
    pullmsg->from = carrier_pullmsg_from(pmsg_tbl);
    pullmsg->type = carrier_pullmsg_type(pmsg_tbl);
    pullmsg->timestamp = carrier_pullmsg_timestamp(pmsg_tbl);
    pullmsg->address = carrier_pullmsg_address(pmsg_tbl);
    pullmsg->payload = vec = carrier_pullmsg_payload(pmsg_tbl);
    pullmsg->payload_sz = flatbuffers_uint8_vec_len(vec);

    return 0;
}