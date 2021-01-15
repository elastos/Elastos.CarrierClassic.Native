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

struct PacketMgrpNewReq {
    Packet headr;
    const char *id;
    const char *title;
};

struct PacketMgrpSyncReq {
    Packet headr;
    uint64_t cur_ver;
};

struct PacketMgrpLeaveReq {
    Packet headr;
    const char *id;
};

struct PacketMgrpInviteReq {
    Packet headr;
    const char *svr_id;
    const char *id;
    const char *title;
};

struct PacketMgrpJoinReq {
    Packet headr;
    const char *id;
};

struct PacketMgrpKickReq {
    Packet headr;
    const char *id;
    const char *peer_id;
};

struct PacketMgrpMsgReq {
    Packet headr;
    const char *id;
    size_t len;
    const uint8_t *msg;
};

struct PacketMgrpSetTitleReq {
    Packet headr;
    const char *id;
    const char *title;
};

struct PacketMgrpSetNameReq {
    Packet headr;
    const char *id;
    const char *name;
};

struct PacketMgrpResp {
    Packet headr;
    int status;
    uint64_t ver;
};

struct PacketMgrpNewResp {
    Packet headr;
    int status;
    const char *name;
    uint64_t ver;
};

struct PacketMgrpNew {
    Packet headr;
    const char *id;
    const char *title;
    const char *admin;
    const char *name;
    uint64_t ver;
};

struct PacketMgrpDismiss {
    Packet headr;
    const char *id;
    uint64_t ver;
};

struct PacketMgrpTitleChange {
    Packet headr;
    const char *id;
    const char *title;
    uint64_t ver;
};

struct PacketMgrpPeerJoin {
    Packet headr;
    const char *id;
    const char *peer_id;
    const char *name;
    uint64_t ver;
};

struct PacketMgrpPeerLeft {
    Packet headr;
    const char *id;
    const char *peer_id;
    uint64_t ver;
};

struct PacketMgrpPeerKick {
    Packet headr;
    const char *id;
    const char *peer_id;
    uint64_t ver;
};

struct PacketMgrpPeerNameChange {
    Packet headr;
    const char *id;
    const char *peer_id;
    const char *name;
    uint64_t ver;
};

struct PacketMgrpMsg {
    Packet headr;
    const char *id;
    const char *peer_id;
    size_t len;
    const uint8_t *msg;
};

#pragma pack(pop)

#define pktinfo pkt.u.pkt_info
#define pktfreq pkt.u.pkt_freq
#define pktfmsg pkt.u.pkt_fmsg
#define pktireq pkt.u.pkt_ireq
#define pktirsp pkt.u.pkt_irsp
#define pktbmsg pkt.u.pkt_bmsg
#define pktgnewreq pkt.u.pkt_gnewreq
#define pktgsyncreq pkt.u.pkt_gsyncreq
#define pktgleavereq pkt.u.pkt_gleavereq
#define pktginvitereq pkt.u.pkt_ginvitereq
#define pktgjoinreq pkt.u.pkt_gjoinreq
#define pktgkickreq pkt.u.pkt_gkickreq
#define pktgmsgreq pkt.u.pkt_gmsgreq
#define pktgtitlereq pkt.u.pkt_gtitlereq
#define pktgnamereq pkt.u.pkt_gnamereq
#define pktgrsp pkt.u.pkt_grsp
#define pktgnewrsp pkt.u.pkt_gnewrsp
#define pktgnew pkt.u.pkt_gnew
#define pktgdismiss pkt.u.pkt_gdismiss
#define pktgtitlechange pkt.u.pkt_gtitlechange
#define pktgpeerjoin pkt.u.pkt_gpeerjoin
#define pktgpeerleft pkt.u.pkt_gpeerleft
#define pktgpeerkick pkt.u.pkt_gpeerkick
#define pktgpeernamechange pkt.u.pkt_gpeernamechange
#define pktgmsg pkt.u.pkt_gmsg

#define tblinfo tbl.u.tbl_info
#define tblfreq tbl.u.tbl_freq
#define tblfmsg tbl.u.tbl_fmsg
#define tblireq tbl.u.tbl_ireq
#define tblirsp tbl.u.tbl_irsp
#define tblbmsg tbl.u.tbl_bmsg
#define tblgireq tbl.u.tbl_gireq
#define tblgrsp tbl.u.tbl_grsp
#define tblgnewrsp tbl.u.tbl_gnewrsp
#define tblgnew tbl.u.tbl_gnew
#define tblgdismiss tbl.u.tbl_gdismiss
#define tblgtitlechange tbl.u.tbl_gtitlechange
#define tblgpeerjoin tbl.u.tbl_gpeerjoin
#define tblgpeerleft tbl.u.tbl_gpeerleft
#define tblgpeerkick tbl.u.tbl_gpeerkick
#define tblgpeernamechange tbl.u.tbl_gpeernamechange
#define tblgmsg tbl.u.tbl_gmsg
#define tblgnewreq tbl.u.tbl_gnewreq
#define tblgsyncreq tbl.u.tbl_gsyncreq
#define tblgleavereq tbl.u.tbl_gleavereq
#define tblgjoinreq tbl.u.tbl_gjoinreq
#define tblgkickreq tbl.u.tbl_gkickreq
#define tblgmsgreq tbl.u.tbl_gmsgreq
#define tblgtitlereq tbl.u.tbl_gtitlereq
#define tblgnamereq tbl.u.tbl_gnamereq

struct packet_t {
    union {
        struct Packet         *cp;
        struct PacketUserInfo  *pkt_info;
        struct PacketFriendReq *pkt_freq;
        struct PacketFriendMsg *pkt_fmsg;
        struct PacketInviteReq *pkt_ireq;
        struct PacketInviteRsp *pkt_irsp;
        struct PacketBulkMsg   *pkt_bmsg;
        struct PacketMgrpNewReq *pkt_gnewreq;
        struct PacketMgrpSyncReq *pkt_gsyncreq;
        struct PacketMgrpLeaveReq *pkt_gleavereq;
        struct PacketMgrpInviteReq *pkt_ginvitereq;
        struct PacketMgrpJoinReq *pkt_gjoinreq;
        struct PacketMgrpKickReq *pkt_gkickreq;
        struct PacketMgrpMsgReq *pkt_gmsgreq;
        struct PacketMgrpSetTitleReq *pkt_gtitlereq;
        struct PacketMgrpSetNameReq *pkt_gnamereq;
        struct PacketMgrpResp *pkt_grsp;
        struct PacketMgrpNewResp *pkt_gnewrsp;
        struct PacketMgrpJoinResp *pkt_gjoinrsp;
        struct PacketMgrpNew *pkt_gnew;
        struct PacketMgrpDismiss *pkt_gdismiss;
        struct PacketMgrpTitleChange *pkt_gtitlechange;
        struct PacketMgrpPeerJoin *pkt_gpeerjoin;
        struct PacketMgrpPeerLeft *pkt_gpeerleft;
        struct PacketMgrpPeerKick *pkt_gpeerkick;
        struct PacketMgrpPeerNameChange *pkt_gpeernamechange;
        struct PacketMgrpMsg *pkt_gmsg;
    } u;
};

struct table_t {
    union {
        carrier_userinfo_table_t  tbl_info;
        carrier_friendreq_table_t tbl_freq;
        carrier_friendmsg_table_t tbl_fmsg;
        carrier_invitereq_table_t tbl_ireq;
        carrier_invitersp_table_t tbl_irsp;
        carrier_bulkmsg_table_t   tbl_bmsg;
        carrier_mgrpinvitereq_table_t tbl_gireq;
        carrier_mgrprsp_table_t   tbl_grsp;
        carrier_mgrpnewrsp_table_t tbl_gnewrsp;
        carrier_mgrpnew_table_t tbl_gnew;
        carrier_mgrpdismiss_table_t tbl_gdismiss;
        carrier_mgrptitlechange_table_t tbl_gtitlechange;
        carrier_mgrpjoin_table_t tbl_gpeerjoin;
        carrier_mgrpleft_table_t tbl_gpeerleft;
        carrier_mgrpkick_table_t tbl_gpeerkick;
        carrier_mgrpnamechange_table_t tbl_gpeernamechange;
        carrier_mgrpmsg_table_t tbl_gmsg;
        carrier_mgrpnewreq_table_t tbl_gnewreq;
        carrier_mgrpsyncreq_table_t tbl_gsyncreq;
        carrier_mgrpleavereq_table_t tbl_gleavereq;
        carrier_mgrpjoinreq_table_t tbl_gjoinreq;
        carrier_mgrpkickreq_table_t tbl_gkickreq;
        carrier_mgrpmsgreq_table_t tbl_gmsgreq;
        carrier_mgrptitlereq_table_t tbl_gtitlereq;
        carrier_mgrpnamereq_table_t tbl_gnamereq;
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
    case PACKET_TYPE_MGRP_NEW_REQ:
        len = sizeof(struct PacketMgrpNewReq);
        break;
    case PACKET_TYPE_MGRP_SYNC_REQ:
        len = sizeof(struct PacketMgrpSyncReq);
        break;
    case PACKET_TYPE_MGRP_LEAVE_REQ:
        len = sizeof(struct PacketMgrpLeaveReq);
        break;
    case PACKET_TYPE_MGRP_INVITE_REQ:
        len = sizeof(struct PacketMgrpInviteReq);
        break;
    case PACKET_TYPE_MGRP_JOIN_REQ:
        len = sizeof(struct PacketMgrpJoinReq);
        break;
    case PACKET_TYPE_MGRP_KICK_REQ:
        len = sizeof(struct PacketMgrpKickReq);
        break;
    case PACKET_TYPE_MGRP_MSG_REQ:
        len = sizeof(struct PacketMgrpMsgReq);
        break;
    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
        len = sizeof(struct PacketMgrpSetTitleReq);
        break;
    case PACKET_TYPE_MGRP_SET_NAME_REQ:
        len = sizeof(struct PacketMgrpSetNameReq);
        break;
    case PACKET_TYPE_MGRP_NEW_GRP:
        len = sizeof(struct PacketMgrpNew);
        break;
    case PACKET_TYPE_MGRP_DISMISSED:
        len = sizeof(struct PacketMgrpDismiss);
        break;
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        len = sizeof(struct PacketMgrpTitleChange);
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        len = sizeof(struct PacketMgrpPeerJoin);
        break;
    case PACKET_TYPE_MGRP_PEER_LEFT:
        len = sizeof(struct PacketMgrpPeerLeft);
        break;
    case PACKET_TYPE_MGRP_PEER_KICKED:
        len = sizeof(struct PacketMgrpPeerKick);
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        len = sizeof(struct PacketMgrpPeerNameChange);
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        len = sizeof(struct PacketMgrpMsg);
        break;
    case PACKET_TYPE_MGRP_NEW_RESP:
        len = sizeof(struct PacketMgrpNewResp);
        break;
    case PACKET_TYPE_MGRP_RESP:
        len = sizeof(struct PacketMgrpResp);
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
    struct packet_t pkt;
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
    case PACKET_TYPE_MGRP_NEW_GRP:
        name = pktgnew->name;
        break;
    case PACKET_TYPE_MGRP_SET_NAME_REQ:
        name = pktgnamereq->name;
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        name = pktgpeerjoin->name;
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        name = pktgpeernamechange->name;
        break;
    case PACKET_TYPE_MGRP_NEW_RESP:
        name = pktgnewrsp->name;
        break;
    default:
        assert(0);
        break;
    }

    return name;
}

const char *packet_get_descr(Packet *cp)
{
    struct packet_t pkt;
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
    struct packet_t pkt;
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
    struct packet_t pkt;
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
    struct packet_t pkt;
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
    struct packet_t pkt;
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
    struct packet_t pkt;
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
    struct packet_t pkt;
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
    struct packet_t pkt;
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
    struct packet_t pkt;
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

uint64_t packet_get_ver(Packet *cp)
{
    struct packet_t pkt;
    uint64_t ver;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_RESP:
        ver = pktgrsp->ver;
        break;
    case PACKET_TYPE_MGRP_NEW_RESP:
        ver = pktgnewrsp->ver;
        break;
    case PACKET_TYPE_MGRP_NEW_GRP:
        ver = pktgnew->ver;
        break;
    case PACKET_TYPE_MGRP_DISMISSED:
        ver = pktgdismiss->ver;
        break;
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        ver = pktgtitlechange->ver;
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        ver = pktgpeerjoin->ver;
        break;
    case PACKET_TYPE_MGRP_PEER_LEFT:
        ver = pktgpeerleft->ver;
        break;
    case PACKET_TYPE_MGRP_PEER_KICKED:
        ver = pktgpeerkick->ver;
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        ver = pktgpeernamechange->ver;
        break;
    case PACKET_TYPE_MGRP_SYNC_REQ:
        ver = pktgsyncreq->cur_ver;
        break;
    default:
        assert(0);
        break;
    }

    return ver;
}

const char *packet_get_title(Packet *cp)
{
    struct packet_t pkt;
    const char *title = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_NEW_GRP:
        title = pktgnew->title;
        break;
    case PACKET_TYPE_MGRP_INVITE_REQ:
        title = pktginvitereq->title;
        break;
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        title = pktgtitlechange->title;
        break;
    case PACKET_TYPE_MGRP_NEW_REQ:
        title = pktgnewreq->title;
        break;
    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
        title = pktgtitlereq->title;
        break;
    default:
        assert(0);
        break;
    }

    return title;
}

const char *packet_get_admin(Packet *cp)
{
    struct packet_t pkt;
    const char *admin = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_NEW_GRP:
        admin = pktgnew->admin;
        break;
    default:
        assert(0);
        break;
    }

    return admin;
}

const char *packet_get_peer_id_at(Packet *cp, size_t idx)
{
    struct packet_t pkt;
    const char *pid = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    default:
        assert(0);
        break;
    }

    return pid;
}

size_t packet_get_peer_ids_length(Packet *cp)
{
    struct packet_t pkt;
    size_t len = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    default:
        assert(0);
        break;
    }

    return len;
}

const char *packet_get_peer_name_at(Packet *cp, size_t idx)
{
    struct packet_t pkt;
    const char *pname = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    default:
        assert(0);
        break;
    }

    return pname;
}

size_t packet_get_peer_names_length(Packet *cp)
{
    struct packet_t pkt;
    size_t len = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    default:
        assert(0);
        break;
    }

    return len;
}

const char *packet_get_group_id(Packet *cp)
{
    struct packet_t pkt;
    const char *grp_id = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_INVITE_REQ:
        grp_id = pktginvitereq->id;
        break;
    case PACKET_TYPE_MGRP_NEW_GRP:
        grp_id = pktgnew->id;
        break;
    case PACKET_TYPE_MGRP_DISMISSED:
        grp_id = pktgdismiss->id;
        break;
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        grp_id = pktgtitlechange->id;
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        grp_id = pktgpeerjoin->id;
        break;
    case PACKET_TYPE_MGRP_PEER_LEFT:
        grp_id = pktgpeerleft->id;
        break;
    case PACKET_TYPE_MGRP_PEER_KICKED:
        grp_id = pktgpeerkick->id;
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        grp_id = pktgpeernamechange->id;
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        grp_id = pktgmsg->id;
        break;
    case PACKET_TYPE_MGRP_NEW_REQ:
        grp_id = pktgnewreq->id;
        break;
    case PACKET_TYPE_MGRP_LEAVE_REQ:
        grp_id = pktgleavereq->id;
        break;
    case PACKET_TYPE_MGRP_JOIN_REQ:
        grp_id = pktgjoinreq->id;
        break;
    case PACKET_TYPE_MGRP_KICK_REQ:
        grp_id = pktgkickreq->id;
        break;
    case PACKET_TYPE_MGRP_MSG_REQ:
        grp_id = pktgmsgreq->id;
        break;
    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
        grp_id = pktgtitlereq->id;
        break;
    case PACKET_TYPE_MGRP_SET_NAME_REQ:
        grp_id = pktgnamereq->id;
        break;
    default:
        assert(0);
        break;
    }

    return grp_id;
}

const char *packet_get_peer_id(Packet *cp)
{
    struct packet_t pkt;
    const char *peer_id = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_PEER_JOINED:
        peer_id = pktgpeerjoin->peer_id;
        break;
    case PACKET_TYPE_MGRP_PEER_LEFT:
        peer_id = pktgpeerleft->peer_id;
        break;
    case PACKET_TYPE_MGRP_PEER_KICKED:
        peer_id = pktgpeerkick->peer_id;
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        peer_id = pktgpeernamechange->peer_id;
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        peer_id = pktgmsg->peer_id;
        break;
    case PACKET_TYPE_MGRP_KICK_REQ:
        peer_id = pktgkickreq->peer_id;
        break;
    default:
        assert(0);
        break;
    }

    return peer_id;
}

const char *packet_get_server_id(Packet *cp)
{
    struct packet_t pkt;
    const char *svr_id = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_INVITE_REQ:
        svr_id = pktginvitereq->svr_id;
        break;
    default:
        assert(0);
        break;
    }

    return svr_id;
}

int packet_get_status(Packet *cp)
{
    struct packet_t pkt;
    int status = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_RESPONSE:
        status = pktirsp->status;
        break;
    case PACKET_TYPE_MGRP_RESP:
        status = pktgrsp->status;
        break;
    case PACKET_TYPE_MGRP_NEW_RESP:
        status = pktgnewrsp->status;
        break;
    default:
        assert(0);
        break;
    }

    return status;
}

const void *packet_get_raw_data(Packet *cp)
{
    struct packet_t pkt;
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
    case PACKET_TYPE_MGRP_MSG_REQ:
        data = pktgmsgreq->msg;
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        data = pktgmsg->msg;
        break;
    default:
        assert(0);
        break;
    }

    return data;
}

size_t packet_get_raw_data_length(Packet *cp)
{
    struct packet_t pkt;
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
    case PACKET_TYPE_MGRP_MSG_REQ:
        len = pktgmsgreq->len;
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        len = pktgmsg->len;
        break;
    default:
        assert(0);
        break;
    }

    return len;
}

const char *packet_get_bundle(Packet *cp)
{
     struct packet_t pkt;
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
    struct packet_t pkt;
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
    struct packet_t pkt;

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
    case PACKET_TYPE_MGRP_SET_NAME_REQ:
        pktgnamereq->name = name;
        break;
    case PACKET_TYPE_MGRP_NEW_GRP:
        pktgnew->name = name;
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        pktgpeerjoin->name = name;
        break;
    case PACKET_TYPE_MGRP_NEW_RESP:
        pktgnewrsp->name = name;
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        pktgpeernamechange->name = name;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_descr(Packet *cp, const char *descr)
{
    struct packet_t pkt;

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
    struct packet_t pkt;

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
    struct packet_t pkt;

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
    struct packet_t pkt;

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
    struct packet_t pkt;

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
    struct packet_t pkt;

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
    struct packet_t pkt;

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
    struct packet_t pkt;

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
    struct packet_t pkt;

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
    struct packet_t pkt;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_INVITE_RESPONSE:
        pktirsp->status = status;
        break;
    case PACKET_TYPE_MGRP_RESP:
        pktgrsp->status = status;
        break;
    case PACKET_TYPE_MGRP_NEW_RESP:
        pktgnewrsp->status = status;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_raw_data(Packet *cp, const void *data, size_t len)
{
    struct packet_t pkt;

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
    case PACKET_TYPE_MGRP_MSG_REQ:
        pktgmsgreq->msg = data;
        pktgmsgreq->len = len;
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        pktgmsg->msg = data;
        pktgmsg->len = len;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_group_id(Packet *cp, const char *id)
{
    struct packet_t pkt;
    assert(cp);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_NEW_REQ:
        pktgnewreq->id = id;
        break;
    case PACKET_TYPE_MGRP_LEAVE_REQ:
        pktgleavereq->id = id;
        break;
    case PACKET_TYPE_MGRP_INVITE_REQ:
        pktginvitereq->id = id;
        break;
    case PACKET_TYPE_MGRP_JOIN_REQ:
        pktgjoinreq->id = id;
        break;
    case PACKET_TYPE_MGRP_KICK_REQ:
        pktgkickreq->id = id;
        break;
    case PACKET_TYPE_MGRP_MSG_REQ:
        pktgmsgreq->id = id;
        break;
    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
        pktgtitlereq->id = id;
        break;
    case PACKET_TYPE_MGRP_SET_NAME_REQ:
        pktgnamereq->id = id;
        break;
    case PACKET_TYPE_MGRP_NEW_GRP:
        pktgnew->id = id;
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        pktgpeerjoin->id = id;
        break;
    case PACKET_TYPE_MGRP_DISMISSED:
        pktgdismiss->id = id;
        break;
    case PACKET_TYPE_MGRP_PEER_LEFT:
        pktgpeerleft->id = id;
        break;
    case PACKET_TYPE_MGRP_PEER_KICKED:
        pktgpeerkick->id = id;
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        pktgmsg->id = id;
        break;
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        pktgtitlechange->id = id;
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        pktgpeernamechange->id = id;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_server_id(Packet *cp, const char *id)
{
    struct packet_t pkt;
    assert(cp);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_INVITE_REQ:
        pktginvitereq->svr_id = id;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_peer_id(Packet *cp, const char *peer_id)
{
    struct packet_t pkt;
    assert(cp);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_KICK_REQ:
        pktgkickreq->peer_id = peer_id;
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        pktgpeerjoin->peer_id = peer_id;
        break;
    case PACKET_TYPE_MGRP_PEER_LEFT:
        pktgpeerleft->peer_id = peer_id;
        break;
    case PACKET_TYPE_MGRP_PEER_KICKED:
        pktgpeerkick->peer_id = peer_id;
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        pktgmsg->peer_id = peer_id;
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        pktgpeernamechange->peer_id = peer_id;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_admin(Packet *cp, const char *admin)
{
    struct packet_t pkt;
    assert(cp);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_NEW_GRP:
        pktgnew->admin = admin;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_title(Packet *cp, const char *title)
{
    struct packet_t pkt;
    assert(cp);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_NEW_REQ:
        pktgnewreq->title = title;
        break;
    case PACKET_TYPE_MGRP_INVITE_REQ:
        pktginvitereq->title = title;
        break;
    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
        pktgtitlereq->title = title;
        break;
    case PACKET_TYPE_MGRP_NEW_GRP:
        pktgnew->title = title;
        break;
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        pktgtitlechange->title = title;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_ver(Packet *cp, uint64_t ver)
{
    struct packet_t pkt;
    assert(cp);

    pkt.u.cp = cp;

    switch(cp->type) {
    case PACKET_TYPE_MGRP_NEW_GRP:
        pktgnew->ver = ver;
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        pktgpeerjoin->ver = ver;
        break;
    case PACKET_TYPE_MGRP_SYNC_REQ:
        pktgsyncreq->cur_ver = ver;
        break;
    case PACKET_TYPE_MGRP_RESP:
        pktgrsp->ver = ver;
        break;
    case PACKET_TYPE_MGRP_NEW_RESP:
        pktgnewrsp->ver = ver;
        break;
    case PACKET_TYPE_MGRP_DISMISSED:
        pktgdismiss->ver = ver;
        break;
    case PACKET_TYPE_MGRP_PEER_LEFT:
        pktgpeerleft->ver = ver;
        break;
    case PACKET_TYPE_MGRP_PEER_KICKED:
        pktgpeerkick->ver = ver;
        break;
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        pktgtitlechange->ver = ver;
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        pktgpeernamechange->ver = ver;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_bundle(Packet *cp, const char *bundle)
 {
     struct packet_t pkt;
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
    struct packet_t pkt;

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
    struct packet_t pkt;
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

    case PACKET_TYPE_MGRP_NEW_REQ:
        carrier_mgrpnewreq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgnewreq->id);
        carrier_mgrpnewreq_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgnewreq->title);
        carrier_mgrpnewreq_title_add(&builder, str);
        ref = carrier_mgrpnewreq_end(&builder);
        break;

    case PACKET_TYPE_MGRP_SYNC_REQ:
        carrier_mgrpsyncreq_start(&builder);
        carrier_mgrpsyncreq_cur_ver_add(&builder, pktgsyncreq->cur_ver);
        ref = carrier_mgrpsyncreq_end(&builder);
        break;

    case PACKET_TYPE_MGRP_LEAVE_REQ:
        carrier_mgrpleavereq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgleavereq->id);
        carrier_mgrpleavereq_id_add(&builder, str);
        ref = carrier_mgrpleavereq_end(&builder);
        break;

    case PACKET_TYPE_MGRP_INVITE_REQ:
        carrier_mgrpinvitereq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktginvitereq->svr_id);
        carrier_mgrpinvitereq_svr_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktginvitereq->id);
        carrier_mgrpinvitereq_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktginvitereq->title);
        carrier_mgrpinvitereq_title_add(&builder, str);
        ref = carrier_mgrpinvitereq_end(&builder);
        break;

    case PACKET_TYPE_MGRP_JOIN_REQ:
        carrier_mgrpjoinreq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgjoinreq->id);
        carrier_mgrpjoinreq_id_add(&builder, str);
        ref = carrier_mgrpjoinreq_end(&builder);
        break;

    case PACKET_TYPE_MGRP_KICK_REQ:
        carrier_mgrpkickreq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgkickreq->id);
        carrier_mgrpkickreq_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgkickreq->peer_id);
        carrier_mgrpkickreq_peer_id_add(&builder, str);
        ref = carrier_mgrpkickreq_end(&builder);
        break;

    case PACKET_TYPE_MGRP_MSG_REQ:
        carrier_mgrpmsgreq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgmsgreq->id);
        carrier_mgrpmsgreq_id_add(&builder, str);
        vec = flatbuffers_uint8_vec_create(&builder, pktgmsgreq->msg, pktgmsgreq->len);
        carrier_mgrpmsgreq_msg_add(&builder, vec);
        ref = carrier_mgrpmsgreq_end(&builder);
        break;

    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
        carrier_mgrptitlereq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgtitlereq->id);
        carrier_mgrptitlereq_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgtitlereq->title);
        carrier_mgrptitlereq_title_add(&builder, str);
        ref = carrier_mgrptitlereq_end(&builder);
        break;

    case PACKET_TYPE_MGRP_SET_NAME_REQ:
        carrier_mgrpnamereq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgnamereq->id);
        carrier_mgrpnamereq_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgnamereq->name);
        carrier_mgrpnamereq_name_add(&builder, str);
        ref = carrier_mgrpnamereq_end(&builder);
        break;

    case PACKET_TYPE_MGRP_NEW_GRP:
        carrier_mgrpnew_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgnew->id);
        carrier_mgrpnew_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgnew->title);
        carrier_mgrpnew_title_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgnew->admin);
        carrier_mgrpnew_admin_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgnew->name);
        carrier_mgrpnew_name_add(&builder, str);
        carrier_mgrpnew_ver_add(&builder, pktgnew->ver);
        ref = carrier_mgrpnew_end(&builder);
        break;

    case PACKET_TYPE_MGRP_RESP:
        carrier_mgrprsp_start(&builder);
        carrier_mgrprsp_status_add(&builder, pktgrsp->status);
        carrier_mgrprsp_ver_add(&builder, pktgrsp->ver);
        ref = carrier_mgrprsp_end(&builder);
        break;

    case PACKET_TYPE_MGRP_NEW_RESP:
        carrier_mgrpnewrsp_start(&builder);
        carrier_mgrpnewrsp_status_add(&builder, pktgnewrsp->status);
        carrier_mgrpnewrsp_ver_add(&builder, pktgnewrsp->ver);
        str = flatcc_builder_create_string_str(&builder, pktgnewrsp->name);
        carrier_mgrpnewrsp_name_add(&builder, str);
        ref = carrier_mgrpnewrsp_end(&builder);
        break;

    case PACKET_TYPE_MGRP_PEER_JOINED:
        carrier_mgrpjoin_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgpeerjoin->id);
        carrier_mgrpjoin_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgpeerjoin->peer_id);
        carrier_mgrpjoin_peer_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgpeerjoin->name);
        carrier_mgrpjoin_name_add(&builder, str);
        carrier_mgrpjoin_ver_add(&builder, pktgpeerjoin->ver);
        ref = carrier_mgrpjoin_end(&builder);
        break;

    case PACKET_TYPE_MGRP_DISMISSED:
        carrier_mgrpdismiss_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgdismiss->id);
        carrier_mgrpdismiss_id_add(&builder, str);
        carrier_mgrpdismiss_ver_add(&builder, pktgdismiss->ver);
        ref = carrier_mgrpdismiss_end(&builder);
        break;

    case PACKET_TYPE_MGRP_PEER_LEFT:
        carrier_mgrpleft_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgpeerleft->id);
        carrier_mgrpleft_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgpeerleft->peer_id);
        carrier_mgrpleft_peer_id_add(&builder, str);
        carrier_mgrpleft_ver_add(&builder, pktgpeerleft->ver);
        ref = carrier_mgrpleft_end(&builder);
        break;

    case PACKET_TYPE_MGRP_PEER_KICKED:
        carrier_mgrpkick_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgpeerkick->id);
        carrier_mgrpkick_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgpeerkick->peer_id);
        carrier_mgrpkick_peer_id_add(&builder, str);
        carrier_mgrpkick_ver_add(&builder, pktgpeerkick->ver);
        ref = carrier_mgrpkick_end(&builder);
        break;

    case PACKET_TYPE_MGRP_PEER_MSG:
        carrier_mgrpmsg_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgmsg->id);
        carrier_mgrpmsg_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgmsg->peer_id);
        carrier_mgrpmsg_peer_id_add(&builder, str);
        vec = flatbuffers_uint8_vec_create(&builder, pktgmsg->msg, pktgmsg->len);
        carrier_mgrpmsg_msg_add(&builder, vec);
        ref = carrier_mgrpmsg_end(&builder);
        break;

    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        carrier_mgrptitlechange_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgtitlechange->id);
        carrier_mgrptitlechange_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgtitlechange->title);
        carrier_mgrptitlechange_title_add(&builder, str);
        carrier_mgrptitlechange_ver_add(&builder, pktgtitlechange->ver);
        ref = carrier_mgrptitlechange_end(&builder);
        break;

    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        carrier_mgrpnamechange_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktgpeernamechange->id);
        carrier_mgrpnamechange_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgpeernamechange->peer_id);
        carrier_mgrpnamechange_peer_id_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktgpeernamechange->name);
        carrier_mgrpnamechange_name_add(&builder, str);
        carrier_mgrpnamechange_ver_add(&builder, pktgpeernamechange->ver);
        ref = carrier_mgrpnamechange_end(&builder);
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
    case PACKET_TYPE_MGRP_NEW_REQ:
        body = carrier_anybody_as_mgrpnewreq(ref);
        break;
    case PACKET_TYPE_MGRP_SYNC_REQ:
        body = carrier_anybody_as_mgrpsyncreq(ref);
        break;
    case PACKET_TYPE_MGRP_LEAVE_REQ:
        body = carrier_anybody_as_mgrpleavereq(ref);
        break;
    case PACKET_TYPE_MGRP_INVITE_REQ:
        body = carrier_anybody_as_mgrpinvitereq(ref);
        break;
    case PACKET_TYPE_MGRP_JOIN_REQ:
        body = carrier_anybody_as_mgrpjoinreq(ref);
        break;
    case PACKET_TYPE_MGRP_KICK_REQ:
        body = carrier_anybody_as_mgrpkickreq(ref);
        break;
    case PACKET_TYPE_MGRP_MSG_REQ:
        body = carrier_anybody_as_mgrpmsgreq(ref);
        break;
    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
        body = carrier_anybody_as_mgrptitlereq(ref);
        break;
    case PACKET_TYPE_MGRP_SET_NAME_REQ:
        body = carrier_anybody_as_mgrpnamereq(ref);
        break;
    case PACKET_TYPE_MGRP_RESP:
        body = carrier_anybody_as_mgrprsp(ref);
        break;
    case PACKET_TYPE_MGRP_NEW_RESP:
        body = carrier_anybody_as_mgrpnewrsp(ref);
        break;
    case PACKET_TYPE_MGRP_DISMISSED:
        body = carrier_anybody_as_mgrpdismiss(ref);
        break;
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        body = carrier_anybody_as_mgrptitlechange(ref);
        break;
    case PACKET_TYPE_MGRP_NEW_GRP:
        body = carrier_anybody_as_mgrpnew(ref);
        break;
    case PACKET_TYPE_MGRP_PEER_JOINED:
        body = carrier_anybody_as_mgrpjoin(ref);
        break;
    case PACKET_TYPE_MGRP_PEER_LEFT:
        body = carrier_anybody_as_mgrpleft(ref);
        break;
    case PACKET_TYPE_MGRP_PEER_KICKED:
        body = carrier_anybody_as_mgrpkick(ref);
        break;
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        body = carrier_anybody_as_mgrpnamechange(ref);
        break;
    case PACKET_TYPE_MGRP_PEER_MSG:
        body = carrier_anybody_as_mgrpmsg(ref);
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
    struct packet_t pkt;
    struct table_t  tbl;
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
    case PACKET_TYPE_MGRP_RESP:
    case PACKET_TYPE_MGRP_NEW_RESP:
    case PACKET_TYPE_MGRP_DISMISSED:
    case PACKET_TYPE_MGRP_TITLE_CHANGED:
    case PACKET_TYPE_MGRP_NEW_GRP:
    case PACKET_TYPE_MGRP_PEER_JOINED:
    case PACKET_TYPE_MGRP_PEER_LEFT:
    case PACKET_TYPE_MGRP_PEER_KICKED:
    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
    case PACKET_TYPE_MGRP_PEER_MSG:
    case PACKET_TYPE_MGRP_NEW_REQ:
    case PACKET_TYPE_MGRP_SYNC_REQ:
    case PACKET_TYPE_MGRP_LEAVE_REQ:
    case PACKET_TYPE_MGRP_INVITE_REQ:
    case PACKET_TYPE_MGRP_JOIN_REQ:
    case PACKET_TYPE_MGRP_KICK_REQ:
    case PACKET_TYPE_MGRP_MSG_REQ:
    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
    case PACKET_TYPE_MGRP_SET_NAME_REQ:
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

    case PACKET_TYPE_MGRP_INVITE_REQ:
        tblgireq = carrier_packet_body(packet);
        pktginvitereq->svr_id = carrier_mgrpinvitereq_svr_id(tblgireq);
        pktginvitereq->id = carrier_mgrpinvitereq_id(tblgireq);
        pktginvitereq->title = carrier_mgrpinvitereq_title(tblgireq);
        break;

    case PACKET_TYPE_MGRP_RESP:
        tblgrsp = carrier_packet_body(packet);
        pktgrsp->status = carrier_mgrprsp_status(tblgrsp);
        pktgrsp->ver = carrier_mgrprsp_ver(tblgrsp);
        break;

    case PACKET_TYPE_MGRP_NEW_RESP:
        tblgnewrsp = carrier_packet_body(packet);
        pktgnewrsp->status = carrier_mgrpnewrsp_status(tblgnewrsp);
        pktgnewrsp->ver = carrier_mgrpnewrsp_ver(tblgnewrsp);
        pktgnewrsp->name = carrier_mgrpnewrsp_name(tblgnewrsp);
        break;

    case PACKET_TYPE_MGRP_NEW_GRP:
        tblgnew = carrier_packet_body(packet);
        pktgnew->id = carrier_mgrpnew_id(tblgnew);
        pktgnew->title = carrier_mgrpnew_title(tblgnew);
        pktgnew->admin = carrier_mgrpnew_admin(tblgnew);
        pktgnew->name = carrier_mgrpnew_name(tblgnew);
        pktgnew->ver = carrier_mgrpnew_ver(tblgnew);
        break;

    case PACKET_TYPE_MGRP_DISMISSED:
        tblgdismiss = carrier_packet_body(packet);
        pktgdismiss->id = carrier_mgrpdismiss_id(tblgdismiss);
        pktgdismiss->ver = carrier_mgrpdismiss_ver(tblgdismiss);
        break;

    case PACKET_TYPE_MGRP_TITLE_CHANGED:
        tblgtitlechange = carrier_packet_body(packet);
        pktgtitlechange->id = carrier_mgrptitlechange_id(tblgtitlechange);
        pktgtitlechange->title = carrier_mgrptitlechange_title(tblgtitlechange);
        pktgtitlechange->ver = carrier_mgrptitlechange_ver(tblgtitlechange);
        break;

    case PACKET_TYPE_MGRP_PEER_JOINED:
        tblgpeerjoin = carrier_packet_body(packet);
        pktgpeerjoin->id = carrier_mgrpjoin_id(tblgpeerjoin);
        pktgpeerjoin->peer_id = carrier_mgrpjoin_peer_id(tblgpeerjoin);
        pktgpeerjoin->name = carrier_mgrpjoin_name(tblgpeerjoin);
        pktgpeerjoin->ver = carrier_mgrpjoin_ver(tblgpeerjoin);
        break;

    case PACKET_TYPE_MGRP_PEER_LEFT:
        tblgpeerleft = carrier_packet_body(packet);
        pktgpeerleft->id = carrier_mgrpleft_id(tblgpeerleft);
        pktgpeerleft->peer_id = carrier_mgrpleft_peer_id(tblgpeerleft);
        pktgpeerleft->ver = carrier_mgrpleft_ver(tblgpeerleft);
        break;

    case PACKET_TYPE_MGRP_PEER_KICKED:
        tblgpeerkick = carrier_packet_body(packet);
        pktgpeerkick->id = carrier_mgrpkick_id(tblgpeerkick);
        pktgpeerkick->peer_id = carrier_mgrpkick_peer_id(tblgpeerkick);
        pktgpeerkick->ver = carrier_mgrpkick_ver(tblgpeerkick);
        break;

    case PACKET_TYPE_MGRP_PEER_NAME_CHANGED:
        tblgpeernamechange = carrier_packet_body(packet);
        pktgpeernamechange->id = carrier_mgrpnamechange_id(tblgpeernamechange);
        pktgpeernamechange->peer_id = carrier_mgrpnamechange_peer_id(tblgpeernamechange);
        pktgpeernamechange->name = carrier_mgrpnamechange_name(tblgpeernamechange);
        pktgpeernamechange->ver = carrier_mgrpnamechange_ver(tblgpeernamechange);
        break;

    case PACKET_TYPE_MGRP_PEER_MSG:
        tblgmsg = carrier_packet_body(packet);
        pktgmsg->id = carrier_mgrpmsg_id(tblgmsg);
        pktgmsg->peer_id = carrier_mgrpmsg_peer_id(tblgmsg);
        pktgmsg->msg = vec = carrier_mgrpmsg_msg(tblgmsg);
        pktgmsg->len = flatbuffers_uint8_vec_len(vec);
        break;

    case PACKET_TYPE_MGRP_NEW_REQ:
        tblgnewreq = carrier_packet_body(packet);
        pktgnewreq->id = carrier_mgrpnewreq_id(tblgnewreq);
        pktgnewreq->title = carrier_mgrpnewreq_title(tblgnewreq);
        break;

    case PACKET_TYPE_MGRP_SYNC_REQ:
        tblgsyncreq = carrier_packet_body(packet);
        pktgsyncreq->cur_ver = carrier_mgrpsyncreq_cur_ver(tblgsyncreq);
        break;

    case PACKET_TYPE_MGRP_LEAVE_REQ:
        tblgleavereq = carrier_packet_body(packet);
        pktgleavereq->id = carrier_mgrpleavereq_id(tblgleavereq);
        break;

    case PACKET_TYPE_MGRP_JOIN_REQ:
        tblgjoinreq = carrier_packet_body(packet);
        pktgjoinreq->id = carrier_mgrpjoinreq_id(tblgjoinreq);
        break;

    case PACKET_TYPE_MGRP_KICK_REQ:
        tblgkickreq = carrier_packet_body(packet);
        pktgkickreq->id = carrier_mgrpkickreq_id(tblgkickreq);
        pktgkickreq->peer_id = carrier_mgrpkickreq_peer_id(tblgkickreq);
        break;

    case PACKET_TYPE_MGRP_MSG_REQ:
        tblgmsgreq = carrier_packet_body(packet);
        pktgmsgreq->id = carrier_mgrpmsgreq_id(tblgmsgreq);
        pktgmsgreq->msg = vec = carrier_mgrpmsgreq_msg(tblgmsgreq);
        pktgmsgreq->len = flatbuffers_uint8_vec_len(vec);
        break;

    case PACKET_TYPE_MGRP_SET_TITLE_REQ:
        tblgtitlereq = carrier_packet_body(packet);
        pktgtitlereq->id = carrier_mgrptitlereq_id(tblgtitlereq);
        pktgtitlereq->title = carrier_mgrptitlereq_title(tblgtitlereq);
        break;

    case PACKET_TYPE_MGRP_SET_NAME_REQ:
        tblgnamereq = carrier_packet_body(packet);
        pktgnamereq->id = carrier_mgrpnamereq_id(tblgnamereq);
        pktgnamereq->name = carrier_mgrpnamereq_name(tblgnamereq);
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