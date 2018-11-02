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
#include <inttypes.h>
#include <pthread.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <CUnit/Basic.h>
#include <vlog.h>
#include <socket.h>
#if defined(_WIN32) || defined(_WIN64)
#include <posix_helper.h>
#endif

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

    wctxt->friend_status = (status == ElaConnectionStatus_Connected) ?
                         ONLINE : OFFLINE;
    cond_signal(wctxt->friend_status_cond);

    vlogD("Robot node connection status changed -> %s", connection_str(status));
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
static Condition DEFINE_COND(friend_status_cond);
static Condition DEFINE_COND(portforwarding_cond);

static CarrierContext carrier_context = {
    .cbs = &callbacks,
    .carrier = NULL,
    .ready_cond = &carrier_ready_cond,
    .cond = &carrier_cond,
    .friend_status_cond = &friend_status_cond,
    .extra = NULL
};

static
void session_request_complete_callback(ElaSession *ws, const char *bundle, int status,
                const char *reason, const char *sdp, size_t len, void *context)
{
    SessionContext *sctxt = (SessionContext *)context;

    vlogD("Session request complete, status:%d, reason: %s", status,
          reason ? reason : "null");

    sctxt->request_complete_status = status;

    if (status == 0) {
        int rc;

        rc = ela_session_start(ws, sdp, len);
        CU_ASSERT_TRUE(rc == 0);
    }

    cond_signal(sctxt->request_complete_cond);
}

static Condition DEFINE_COND(session_request_complete_cond);

static SessionContext session_context = {
    .request_cb = NULL,
    .request_received = 0,
    .request_cond = NULL,

    .request_complete_cb = session_request_complete_callback,
    .request_complete_status = -1,
    .request_complete_cond = &session_request_complete_cond,

    .session = NULL,
    .extra   = NULL,
};

static void stream_on_data(ElaSession *ws, int stream, const void *data,
                           size_t len, void *context)
{
    vlogD("Stream [%d] received data [%.*s]", stream, (int)len, (char*)data);
}

static void stream_state_changed(ElaSession *ws, int stream,
                                 ElaStreamState state, void *context)
{
    StreamContext *stream_ctxt = (StreamContext *)context;

    stream_ctxt->state = state;
    stream_ctxt->state_bits |= 1 << state;

    vlogD("stream %d state changed to: %s", stream, stream_state_name(state));

    cond_signal(stream_ctxt->cond);
}

static ElaStreamCallbacks stream_callbacks = {
    .stream_data = stream_on_data,
    .state_changed = stream_state_changed
};

static Condition DEFINE_COND(stream_cond);

struct StreamContextExtra {
    const char *service;
    const char *port;
    const char *shadow_port;
    int sent_count;
};

static StreamContextExtra stream_extra = {
    .service = "test_portforwarding_service",
    .port = "20172",
    .shadow_port = "20173",
    .sent_count = 1024
};

static StreamContext stream_context = {
    .cbs = &stream_callbacks,
    .stream_id = -1,
    .state = 0,
    .state_bits = 0,
    .cond = &stream_cond,
    .extra = &stream_extra
};

static void test_context_reset(TestContext *context)
{
    SessionContext *session = context->session;
    StreamContext *stream = context->stream;

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

    .context_reset = test_context_reset
};

#ifdef _MSC_VER
// For Windows socket API not compatible with POSIX: size_t vs. int
#pragma warning(push)
#pragma warning(disable: 4267)
#endif

static SOCKET tcp_socket_create(const char *host, const char *port)
{
    SOCKET sockfd = -1;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *p;
    int rc;

    assert(host);
    assert(port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(host, port, &hints, &ai);
    if (rc != 0)
        return -1;

    for (p = ai; p; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0)
            continue;

        int set = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*)&set, sizeof(set));
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) != 0) {
            socket_close(sockfd);
            sockfd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(ai);
    return sockfd;
}

static SOCKET tcp_socket_connect(const char *host, const char *port)
{
    SOCKET sockfd = -1;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *p;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    rc = getaddrinfo(host, port, &hints, &ai);
    if (rc != 0)
        return -1;

    for (p = ai; p; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if (p->ai_socktype == SOCK_STREAM) {
            if (connect(sockfd, p->ai_addr  , p->ai_addrlen) != 0) {
                socket_close(sockfd);
                sockfd = -1;
                continue;
            }
        }

        break;
    }

    freeaddrinfo(ai);
    return sockfd;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

static int tcp_socket_close(SOCKET sockfd)
{
#if !defined(_WIN32) && !defined(_WIN64)
    return close(sockfd);
#else
    return closesocket(sockfd);
#endif
}

typedef struct PortforwardingContext {
    const char *port;
    int sent_count;
    int recv_count;
    int return_val;
} PortForwardingContxt;

static void *client_thread_entry(void *argv)
{
    PortForwardingContxt *ctxt = (PortForwardingContxt *)argv;
    SOCKET sockfd;
    ssize_t rc;
    int i;
    char data[1024];

    memset(data, 'D', sizeof(data));

    ctxt->return_val = -1;

    sockfd = tcp_socket_connect("127.0.0.1", ctxt->port);
    if (sockfd < 0) {
        vlogE("client connect to 127.0.0.1:%s failed", ctxt->port);
        return NULL;
    }

    usleep(500);

    vlogI("client begin to send data:");

    for (i = 0; i < ctxt->sent_count; i++) {
        int left = sizeof(data);
        char *pos = data;

        while(left > 0) {
            rc = send(sockfd, pos, left, 0);
            if (rc < 0) {
                vlogE("client send data error (%d)", errno);
                tcp_socket_close(sockfd);
                return NULL;
            }

            left -= (int)rc;
            pos += rc;
        }

        vlogD(".");
    }

    vlogI("finished sending %d Kbytes data", ctxt->sent_count);
    vlogI("client send data in success");

    tcp_socket_close(sockfd);
    ctxt->return_val = 0;

    return NULL;
}

static void *server_thread_entry(void *argv)
{
    PortForwardingContxt *ctxt = (PortForwardingContxt *)argv;
    SOCKET sockfd;
    SOCKET data_sockfd;
    int rc;
    char data[1025];

    ctxt->return_val = -1;

    sockfd = tcp_socket_create("127.0.0.1", ctxt->port);
    if (sockfd < 0) {
        vlogE("server create on 127.0.0.1:%s failed (sockfd:%d) (%d)",
              ctxt->port, sockfd, errno);
        return NULL;
    }

    rc = listen(sockfd, 1);
    if (rc < 0) {
        vlogE("server listen failed (%d)", errno);
        tcp_socket_close(sockfd);
        return NULL;
    }

    cond_signal(&portforwarding_cond);

    data_sockfd = accept(sockfd, NULL, NULL);
    tcp_socket_close((sockfd));

    if (data_sockfd < 0) {
        vlogE("server accept new socket failed.");
        return NULL;
    }

    vlogI("server begin to receive data:");

    do {
        memset(data, 0, sizeof(data));

        rc = (int)recv(data_sockfd, data, sizeof(data) - 1, 0);
        if (rc > 0) {
            ctxt->recv_count += rc;
            vlogD("%s", data);
        }

    } while (rc > 0);

    if (rc == 0) {
        ctxt->recv_count /= 1024;
        vlogI("finished receiving %d Kbytes data, closed by remote peer.",
              ctxt->recv_count);
    } else if (rc < 0)
        vlogE("receiving error(%d)", errno);
    else
        assert(0);

    tcp_socket_close(data_sockfd);
    ctxt->return_val = 0;
    return NULL;
}

static
int forwarding_data(const char *service_port, const char *shadow_service_port)
{
    pthread_t client_thread;
    pthread_t server_thread;
    PortForwardingContxt client_ctxt;
    PortForwardingContxt server_ctxt;
    int rc;

    server_ctxt.port = service_port;
    server_ctxt.recv_count = 0;
    server_ctxt.sent_count = 0;
    server_ctxt.return_val = -1;

    rc = pthread_create(&server_thread, NULL, &server_thread_entry, &server_ctxt);
    if (rc != 0) {
        vlogE("create server thread failed (%d)", rc);
        return -1;
    }

    cond_wait(&portforwarding_cond);

    client_ctxt.port = shadow_service_port;
    client_ctxt.recv_count = 0;
    client_ctxt.sent_count = 1024;
    client_ctxt.return_val = -1;

    rc = pthread_create(&client_thread, NULL, &client_thread_entry, &client_ctxt);
    if (rc != 0) {
        vlogE("create client thread failed (%d)", rc);
        return -1;
    }

    pthread_join(client_thread, NULL);
    pthread_join(server_thread, NULL);

    if (client_ctxt.return_val == -1) {
        vlogE("client thread running failed");
        return -1;
    }

    if (server_ctxt.return_val == -1) {
        vlogE("server thread running failed");
        return -1;
    }

    if (client_ctxt.sent_count != server_ctxt.recv_count) {
        vlogE("the number of sent bytes not match with recv bytes.");
        return -1;
    }

    return 0;
}

static int do_portforwarding_internal(TestContext *context)
{
    StreamContextExtra *extra = context->stream->extra;
    int rc;
    char cmd[32];
    char result[32];
    int pfid = -1;

    rc = write_cmd("spfsvcadd %s tcp  127.0.0.1 %s\n", extra->service, extra->port);
    TEST_ASSERT_TRUE(rc > 0);

    rc = read_ack("%32s %32s", cmd, result);
    TEST_ASSERT_TRUE(rc == 2);
    TEST_ASSERT_TRUE(strcmp(cmd, "spfsvcadd") == 0);
    TEST_ASSERT_TRUE(strcmp(result, "success") == 0);

    pfid = ela_stream_open_port_forwarding(context->session->session,
                            context->stream->stream_id,
                            extra->service, PortForwardingProtocol_TCP, "127.0.0.1",
                            extra->shadow_port);

    if (pfid > 0) {
        vlogD("Open portforwarding successfully");
    } else {
        vlogE("Open portforwarding failed (0x%x)", pfid);
    }

    TEST_ASSERT_TRUE(pfid > 0);

    rc = forwarding_data(extra->port, extra->shadow_port);
    TEST_ASSERT_TRUE(rc == 0);

    rc = ela_stream_close_port_forwarding(context->session->session,
                                              context->stream->stream_id, pfid);
    TEST_ASSERT_TRUE(rc == 0);

    write_cmd("spfsvcremove %s\n", extra->service);

    return 0;

cleanup:
    if (pfid > 0)
        ela_stream_close_port_forwarding(context->session->session,
                                             context->stream->stream_id, pfid);

    write_cmd("spfsvcremove %s\n", extra->service);
    return -1;
}

static int do_reversed_portforwarding_internal(TestContext *context)
{
    StreamContextExtra *extra = context->stream->extra;
    int rc;
    char cmd[32];
    char result[32];

    rc = ela_session_add_service(context->session->session, extra->service,
                                     PortForwardingProtocol_TCP, "127.0.0.1",
                                     extra->port);
    TEST_ASSERT_TRUE(rc == 0);

    rc = write_cmd("spfopen %s tcp 127.0.0.1 %s\n", extra->service, extra->shadow_port);
    TEST_ASSERT_TRUE(rc > 0);

    rc = read_ack("%32s %32s", cmd, result);
    TEST_ASSERT_TRUE(rc == 2);
    TEST_ASSERT_TRUE(strcmp(cmd, "spfopen") == 0);
    TEST_ASSERT_TRUE(strcmp(result, "success") == 0);

    rc = forwarding_data(extra->port, extra->shadow_port);
    TEST_ASSERT_TRUE(rc == 0);

    rc = write_cmd("spfclose\n");
    TEST_ASSERT_TRUE(rc > 2);

    rc = read_ack("%32s %32s", cmd, result);
    TEST_ASSERT_TRUE(rc = 2);
    TEST_ASSERT_TRUE(strcmp(cmd, "spfclose") == 0);
    TEST_ASSERT_TRUE(strcmp(result, "success") == 0);

    ela_session_remove_service(context->session->session, extra->service);
    return 0;

cleanup:
    ela_session_remove_service(context->session->session, extra->service);
    return -1;
}

static inline void portforwarding_impl(int stream_options)
{
    test_stream_scheme(ElaStreamType_text, stream_options,
                       &test_context, do_portforwarding_internal);
}

static inline void reversed_portforwarding_impl(int stream_options)
{
    test_stream_scheme(ElaStreamType_text, stream_options,
                       &test_context, do_reversed_portforwarding_internal);
}

static void test_session_portforwarding_reliable(void)
{
    int stream_options = 0;
    stream_options |= ELA_STREAM_RELIABLE;
    stream_options |= ELA_STREAM_PORT_FORWARDING;

    portforwarding_impl(stream_options);
}

static void test_session_portforwarding_reliable_plain(void)
{
    int stream_options = 0;
    stream_options |= ELA_STREAM_RELIABLE;
    stream_options |= ELA_STREAM_PLAIN;
    stream_options |= ELA_STREAM_PORT_FORWARDING;

    portforwarding_impl(stream_options);
}

static void test_session_reversed_portforwarding_reliable(void)
{
    int stream_options = 0;
    stream_options |= ELA_STREAM_RELIABLE;
    stream_options |= ELA_STREAM_PORT_FORWARDING;

    reversed_portforwarding_impl(stream_options);
}

static
void test_session_reversed_portforwarding_reliable_plain(void)
{
    int stream_options = 0;

    stream_options |= ELA_STREAM_RELIABLE;
    stream_options |= ELA_STREAM_PLAIN;
    stream_options |= ELA_STREAM_PORT_FORWARDING;

    reversed_portforwarding_impl(stream_options);
}

static CU_TestInfo cases[] = {
    { "test_session_portforwarding_reliable", test_session_portforwarding_reliable },
    { "test_session_portforwarding_reliable_plain", test_session_portforwarding_reliable_plain },

    { "test_session_reversed_portforwarding_reliable", test_session_reversed_portforwarding_reliable },
    { "test_session_reversed_portforwarding_reliable_plain", test_session_reversed_portforwarding_reliable_plain },

    { NULL, NULL }
};

CU_TestInfo *session_portforwarding_test_get_cases(void)
{
    return cases;
}

int session_portforwarding_test_suite_init(void)
{
    int rc;

    rc = test_suite_init(&test_context);
    if (rc < 0)
        CU_FAIL("Error: test suite initialize error");

    return rc;
}

int session_portforwarding_test_suite_cleanup(void)
{
    test_suite_cleanup(&test_context);

    return 0;
}
