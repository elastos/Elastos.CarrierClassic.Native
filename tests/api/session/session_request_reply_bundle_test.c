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
#include <assert.h>

#include <CUnit/Basic.h>
#include <vlog.h>

#include "ela_carrier.h"
#include "ela_session.h"

#include "cond.h"
#include "test_helper.h"
#include "test_assert.h"

static inline void wakeup(void* context)
{
    cond_signal(((CarrierContext *)context)->cond);
}

static void ready_cb(ElaCarrier *w, void *context)
{
    cond_signal(((CarrierContext *)context)->ready_cond);
}

static
void friend_added_cb(ElaCarrier *w, const ElaFriendInfo *info, void *context)
{
    wakeup(context);
}

static void friend_removed_cb(ElaCarrier *w, const char *friendid, void *context)
{
    wakeup(context);
}

static void friend_connection_cb(ElaCarrier *w, const char *friendid,
                                 ElaConnectionStatus status, void *context)
{
    CarrierContext *wctxt = (CarrierContext *)context;

    wakeup(context);
    wctxt->robot_online = (status == ElaConnectionStatus_Connected);

    vlogD("Robot connection status changed -> %s", connection_str(status));
}

static ElaCallbacks callbacks = {
    .idle            = NULL,
    .connection_status = NULL,
    .ready           = ready_cb,
    .self_info       = NULL,
    .friend_list     = NULL,
    .friend_connection = friend_connection_cb,
    .friend_info     = NULL,
    .friend_presence = NULL,
    .friend_request  = NULL,
    .friend_added    = friend_added_cb,
    .friend_removed  = friend_removed_cb,
    .friend_message  = NULL,
    .friend_invite   = NULL
};

static Condition DEFINE_COND(carrier_ready_cond);
static Condition DEFINE_COND(carrier_cond);

static CarrierContext carrier_context = {
    .cbs = &callbacks,
    .carrier = NULL,
    .robot_online = false,
    .ready_cond = &carrier_ready_cond,
    .cond = &carrier_cond,
    .extra = NULL
};

struct SessionContextExtra {
    char bundle[ELA_MAX_BUNDLE_LEN + 1];
    char robot_peer_id[(ELA_MAX_ID_LEN + 1) * 2];
    int callback_num;
};

static SessionContextExtra session_extra = {
    .bundle = {0},
    .robot_peer_id = {0},
    .callback_num = -1
};

static void session_request_callback(ElaCarrier *w, const char *from, const char *bundle,
                                    const char *sdp, size_t len, void *context)
{
    SessionContext *sctxt = (SessionContext *)context;
    SessionContextExtra *extra = sctxt->extra;

    strcpy(extra->bundle, bundle);

    strncpy(extra->robot_peer_id, from, strlen(from) + 1);
    extra->callback_num = 1;

    cond_signal(sctxt->request_cond);
}

static void session_request_callback_for_a(ElaCarrier *w, const char *from, const char *bundle,
                                     const char *sdp, size_t len, void *context)
{
    SessionContext *sctxt = (SessionContext *)context;
    SessionContextExtra *extra = sctxt->extra;

    if (bundle)
        strcpy(extra->bundle, bundle);

    strncpy(extra->robot_peer_id, from, strlen(from) + 1);
    extra->callback_num = 2;

    cond_signal(sctxt->request_cond);
}

static void session_request_callback_for_b(ElaCarrier *w, const char *from, const char *bundle,
                                     const char *sdp, size_t len, void *context)
{
    SessionContext *sctxt = (SessionContext *)context;
    SessionContextExtra *extra = sctxt->extra;

    if (bundle)
        strcpy(extra->bundle, bundle);

    strncpy(extra->robot_peer_id, from, strlen(from) + 1);
    extra->callback_num = 3;

    cond_signal(sctxt->request_cond);
}

static void global_session_request_callback(ElaCarrier *w, const char *from, const char *bundle,
                                     const char *sdp, size_t len, void *context)
{
    SessionContext *sctxt = (SessionContext *)context;
    SessionContextExtra *extra = sctxt->extra;

    if (bundle)
        strcpy(extra->bundle, bundle);

    strncpy(extra->robot_peer_id, from, strlen(from) + 1);
    extra->callback_num = 4;

    cond_signal(sctxt->request_cond);
}

static void session_request_complete_callback(ElaSession *ws, const char *bundle, int status,
                const char *reason, const char *sdp, size_t len, void *context)
{
    SessionContext *sctxt = (SessionContext *)context;

    vlogD("Session complete, status: %d, reason: %s", status,
          reason ? reason : "null");

    sctxt->request_complete_status = status;

    cond_signal(sctxt->request_complete_cond);
}

static Condition DEFINE_COND(session_request_cond);
static Condition DEFINE_COND(session_request_complete_cond);

static SessionContext session_context = {
    .request_cb = session_request_callback,
    .request_received = 0,
    .request_cond = &session_request_cond,

    .request_complete_cb = session_request_complete_callback,
    .request_complete_status = -1,
    .request_complete_cond = &session_request_complete_cond,

    .session = NULL,
    .extra   = &session_extra
};

static void stream_on_data(ElaSession *ws, int stream,
                           const void *data, size_t len, void *context)
{
    vlogD("Stream [%d] received data [%.*s]", stream, (int)len, (char*)data);
}

static void stream_state_changed(ElaSession *ws, int stream,
                                 ElaStreamState state, void *context)
{
    StreamContext *stream_ctxt = (StreamContext *)context;

    stream_ctxt->state = state;
    stream_ctxt->state_bits |= 1 << state;

    vlogD("Stream [%d] state changed to: %s", stream, stream_state_name(state));

    cond_signal(stream_ctxt->cond);
}

static ElaStreamCallbacks stream_callbacks = {
    .stream_data = stream_on_data,
    .state_changed = stream_state_changed
};

static Condition DEFINE_COND(stream_cond);

static StreamContext stream_context = {
    .cbs = &stream_callbacks,
    .stream_id = -1,
    .state = 0,
    .state_bits = 0,
    .cond = &stream_cond,
    .extra = NULL
};

static void test_context_reset(TestContext *context)
{
    SessionContext *session = context->session;
    StreamContext *stream = context->stream;

    cond_reset(session->request_cond);
    cond_reset(session->request_complete_cond);

    session->request_received = 0;
    session->request_complete_status = -1;
    session->session = NULL;

    cond_reset(context->stream->cond);

    stream->stream_id = -1;
    stream->state = 0;
    stream->state_bits = 0;
}

static TestContext test_context = {
    .carrier = &carrier_context,
    .session = &session_context,
    .stream  = &stream_context,

    .context_reset = test_context_reset,
};

static void test_session_bundle(ElaStreamType stream_type,
                    int stream_options, TestContext *context,
                    int (*do_work_cb)(TestContext *))
{
    CarrierContext *wctxt = context->carrier;
    SessionContext *sctxt = context->session;
    StreamContext *stream_ctxt = context->stream;
    SessionContextExtra *extra = context->session->extra;

    int rc = 0;
    char cmd[32] = {0};
    char result[32] = {0};
    char userid[ELA_MAX_ID_LEN + 1] = {0};
    const char *bundle = NULL;
    const char *bundle_a = "BundleA";
    const char *bundle_b = "BundleB";
    const char *bundle_c = "BundleC";

    context->context_reset(context);

    rc = add_friend_anyway(context, robotid, robotaddr);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_TRUE_FATAL(ela_is_friend(wctxt->carrier, robotid));

    rc = ela_session_init(wctxt->carrier, sctxt->request_cb, sctxt);
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    rc = robot_sinit();
    TEST_ASSERT_TRUE(rc > 0);

    rc = read_ack("%32s %32s", cmd, result);
    TEST_ASSERT_TRUE(rc == 2);
    TEST_ASSERT_TRUE(strcmp(cmd, "sinit") == 0);
    TEST_ASSERT_TRUE(strcmp(result, "success") == 0);

    ela_get_userid(wctxt->carrier, userid, sizeof(userid));

    if (!extra->bundle[0]) {
        rc = write_cmd("srequest %s %d\n", userid, stream_options);
        bundle = "";
    } else if (strcmp(extra->bundle, "empty") == 0) {
        rc = write_cmd("srequest %s %d %s\n", userid, stream_options, "");
        bundle = "";
    } else {
        rc = ela_session_set_callback(wctxt->carrier, bundle_a, session_request_callback_for_a, sctxt);
        CU_ASSERT_EQUAL_FATAL(rc, 0);

        rc = ela_session_set_callback(wctxt->carrier, bundle_b, session_request_callback_for_b, sctxt);
        CU_ASSERT_EQUAL_FATAL(rc, 0);

        rc = write_cmd("srequest %s %d %s\n", userid, stream_options, bundle_a);
        bundle = bundle_a;
    }
    TEST_ASSERT_TRUE(rc > 0);

    memset(cmd, 0, sizeof(cmd));
    memset(result, 0, sizeof(result));
    rc = read_ack("%32s %32s", cmd, result);
    TEST_ASSERT_TRUE(rc == 2);
    TEST_ASSERT_TRUE(strcmp(cmd, "srequest") == 0);
    TEST_ASSERT_TRUE(strcmp(result, "success") == 0);

    cond_wait(sctxt->request_cond);       //for session request callback
    if (!extra->bundle[0]) {
        TEST_ASSERT_TRUE(extra->bundle[0] == 0);
        TEST_ASSERT_TRUE(extra->callback_num == 1);
    } else {
        TEST_ASSERT_TRUE(strcmp(extra->bundle, bundle) == 0);
        TEST_ASSERT_TRUE(extra->callback_num == 2);
    }

    sctxt->session = ela_session_new(wctxt->carrier, extra->robot_peer_id);
    TEST_ASSERT_TRUE(sctxt->session != NULL);

    stream_ctxt->stream_id = ela_session_add_stream(sctxt->session,
                                    ElaStreamType_text, stream_options,
                                    stream_ctxt->cbs, stream_ctxt);
    TEST_ASSERT_TRUE(stream_ctxt->stream_id > 0);

    cond_wait(stream_ctxt->cond);
    TEST_ASSERT_TRUE(stream_ctxt->state == ElaStreamState_initialized);
    TEST_ASSERT_TRUE(stream_ctxt->state_bits & (1 << ElaStreamState_initialized));

    if (!extra->bundle[0])
        rc = ela_session_reply_request(sctxt->session, NULL, 0, NULL);
    else
        rc = ela_session_reply_request(sctxt->session, extra->bundle, 0, NULL);
    TEST_ASSERT_TRUE(rc == 0);

    memset(cmd, 0, sizeof(cmd));
    memset(result, 0, sizeof(result));
    rc = read_ack("%32s %32s", cmd, result);

    if (extra->bundle[0] != 0) {
        TEST_ASSERT_TRUE(rc == 2);
        TEST_ASSERT_TRUE(strcmp(cmd, "bundle") == 0);
        TEST_ASSERT_TRUE(strcmp(result, extra->bundle) == 0);
    }

    if (strcmp(extra->bundle, "filled") == 0) {
        rc = write_cmd("srequest %s %d %s %s\n", userid, stream_options, bundle_b, "new_callback");
        TEST_ASSERT_TRUE(rc > 0);

        memset(cmd, 0, sizeof(cmd));
        memset(result, 0, sizeof(result));
        rc = read_ack("%32s %32s", cmd, result);
        TEST_ASSERT_TRUE(rc == 2);
        TEST_ASSERT_TRUE(strcmp(cmd, "srequest") == 0);
        TEST_ASSERT_TRUE(strcmp(result, "success") == 0);

        cond_wait(sctxt->request_cond); //for session request callback
        TEST_ASSERT_TRUE(strcmp(extra->bundle, bundle_b) == 0);
        TEST_ASSERT_TRUE(extra->callback_num == 3);

        rc = ela_session_reply_request(sctxt->session, extra->bundle, 0, NULL);
        TEST_ASSERT_TRUE(rc == 0);
        memset(cmd, 0, sizeof(cmd));
        memset(result, 0, sizeof(result));
        rc = read_ack("%32s %32s", cmd, result);
        TEST_ASSERT_TRUE(rc == 2);
        TEST_ASSERT_TRUE(strcmp(cmd, "bundle") == 0);
        TEST_ASSERT_TRUE(strcmp(result, extra->bundle) == 0);

        rc = ela_session_set_callback(wctxt->carrier, NULL, global_session_request_callback, sctxt);
        CU_ASSERT_EQUAL_FATAL(rc, 0);
        rc = write_cmd("srequest %s %d %s %s\n", userid, stream_options, bundle_c, "new_callback");
        TEST_ASSERT_TRUE(rc > 0);

        memset(cmd, 0, sizeof(cmd));
        memset(result, 0, sizeof(result));
        rc = read_ack("%32s %32s", cmd, result);
        TEST_ASSERT_TRUE(rc == 2);
        TEST_ASSERT_TRUE(strcmp(cmd, "srequest") == 0);
        TEST_ASSERT_TRUE(strcmp(result, "success") == 0);

        cond_wait(sctxt->request_cond); //for session request callback
        TEST_ASSERT_TRUE(strcmp(extra->bundle, bundle_c) == 0);
        TEST_ASSERT_TRUE(extra->callback_num == 4);

        rc = ela_session_reply_request(sctxt->session, extra->bundle, 0, NULL);
        TEST_ASSERT_TRUE(rc == 0);

        memset(cmd, 0, sizeof(cmd));
        memset(result, 0, sizeof(result));
        rc = read_ack("%32s %32s", cmd, result);
        TEST_ASSERT_TRUE(rc == 2);
        TEST_ASSERT_TRUE(strcmp(cmd, "bundle") == 0);
        TEST_ASSERT_TRUE(strcmp(result, extra->bundle) == 0);
    }

cleanup:
    if (stream_ctxt->stream_id > 0) {
        ela_session_remove_stream(sctxt->session, stream_ctxt->stream_id);
        stream_ctxt->stream_id = -1;
    }

    if (sctxt->session) {
        ela_session_close(sctxt->session);
        sctxt->session = NULL;
    }

    ela_session_cleanup(wctxt->carrier);
    robot_sfree();
}

static void test_session_with_nullable_bundle(void)
{
    test_session_bundle(ElaStreamType_text, 0, &test_context, NULL);
}

static void test_session_with_empty_bundle(void)
{
    strcpy(session_extra.bundle, "empty");
    test_session_bundle(ElaStreamType_text, 0, &test_context, NULL);
}

static void test_session_with_filled_bundle(void)
{
    strcpy(session_extra.bundle, "filled");
    test_session_bundle(ElaStreamType_text, 0, &test_context, NULL);
}

static CU_TestInfo cases[] = {
    { "test_session_with_nullable_bundle",  test_session_with_nullable_bundle },
    { "test_session_with_empty_bundle",     test_session_with_empty_bundle },
    { "test_session_with_filled_bundle",    test_session_with_filled_bundle },
    { NULL, NULL }
};

CU_TestInfo *session_request_reply_bundle_test_get_cases(void)
{
    return cases;
}

int session_request_reply_bundle_test_suite_init(void)
{
    int rc;

    rc = test_suite_init(&test_context);
    if (rc < 0)
        CU_FAIL("Error: test suite initialize error");

    return rc;
}

int session_request_reply_bundle_test_suite_cleanup(void)
{
    test_suite_cleanup(&test_context);

    return 0;
}