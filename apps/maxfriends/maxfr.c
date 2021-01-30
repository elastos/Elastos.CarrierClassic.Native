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

#if __linux__
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <crystal.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <errno.h>

#if defined(_WIN32) || defined(_WIN64)
#include <io.h>
#endif

#include <pthread.h>

#include <carrier.h>
#include <libconfig.h>
#include "carrier_config.h"

#define CONFIG_NAME   "maxfr.conf"

static const char *default_config_files[] = {
    "./"CONFIG_NAME,
    "../etc/carrier/"CONFIG_NAME,
#if !defined(_WIN32) && !defined(_WIN64)
    "/usr/local/etc/carrier/"CONFIG_NAME,
    "/etc/carrier/"CONFIG_NAME,
#endif
    NULL
};

typedef struct {
    CarrierOptions copts;
    size_t svrs_cnt;
    struct sockaddr_in *svrs;
} cfg_t;

static const char *cfg_file;
static cfg_t cfg;
static sigset_t mask;
static sigset_t old_mask;
static size_t nodes_per_svr = 1024;
static size_t msg_recved;
static size_t online_on_svrs;
static size_t connected_cnt;
static Carrier *w;
static pthread_t sig_thread;
static pthread_t carrier_thread;
static pthread_t svrs_thread;
static int *svr_fds;
static bool quit;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static void usage(void)
{
    printf("Max friends, tests how many friends a node can make.\n");
    printf("Usage: maxfr [OPTION]...\n");
    printf("\n");
    printf("First run options:\n");
    printf("  -c, --config=CONFIG_FILE   Set config file path.\n");
    printf("      --udp-enabled=0|1      Enable UDP, override the option in config.\n");
    printf("      --log-level=LEVEL      Log level(0-7), override the option in config.\n");
    printf("      --log-file=FILE        Log file name, override the option in config.\n");
    printf("      --data-dir=PATH        Data location, override the option in config.\n");
    printf("  -n, --nodes-per-server=NUM Number of carrier node each server creates.\n");
    printf("\n");
    printf("Debugging options:\n");
    printf("      --debug               Wait for debugger attach after start.\n");
    printf("\n");
}

static void *sig_poll(void *arg)
{
    int rc;
    int signo;

    (void)arg;

    while (1) {
        rc = sigwait(&mask, &signo);
        if (rc) {
            vlogE("sigwait() failed. Stopping...");
            goto quit_prog;
        }

        switch (signo) {
        case SIGINT:
        case SIGQUIT:
            goto quit_prog;
        default:
            break;
        }
    }

quit_prog:
    pthread_mutex_lock(&lock);
    quit = true;
    pthread_mutex_unlock(&lock);
    pthread_cond_signal(&cond);
    return NULL;
}

static int start_sig_poll()
{
    int rc;

    vlogI("Starting signal polling...");

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);

    rc = pthread_sigmask(SIG_BLOCK, &mask, &old_mask);
    if (rc) {
        vlogE("pthread_sigmask() failed.");
        return -1;
    }

    rc = pthread_create(&sig_thread, NULL, sig_poll, NULL);
    if (rc) {
        vlogE("Creating signal thread failed.");
        pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
        return -1;
    }

    return 0;
}

static void stop_sig_poll()
{
    pthread_cancel(sig_thread);
    pthread_join(sig_thread, NULL);

    pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
}

static int load_svrs(void *p, CarrierOptions *opts)
{
    config_t *c = p;
    config_setting_t *svrs_setting;
    const char *stropt;
    int entries;
    int intopt;
    int rc;
    int i;

    (void)opts;

    svrs_setting = config_lookup(c, "servers");
    if (!svrs_setting) {
        fprintf(stderr, "Missing servers section.\n");
        return -1;
    }

    entries = config_setting_length(svrs_setting);
    if (entries <= 0) {
        fprintf(stderr, "Empty servers option.\n");
        return -1;
    }
    cfg.svrs_cnt = entries;

    cfg.svrs = rc_zalloc(sizeof(cfg.svrs[0]) * entries, NULL);
    if (!cfg.svrs) {
        fprintf(stderr, "Load configuration failed, out of memory.\n");
        return -1;
    }

    for (i = 0; i < entries; i++) {
        cfg.svrs[i].sin_family = AF_INET;
        config_setting_t *setting;

        setting = config_setting_get_elem(svrs_setting, i);

        rc = config_setting_lookup_string(setting, "host", &stropt);
        if (!(rc && *stropt && inet_pton(AF_INET, stropt, &cfg.svrs[i].sin_addr) == 1)) {
            fprintf(stderr, "Invalid host option.\n");
            deref(cfg.svrs);
            return -1;
        }

        rc = config_setting_lookup_int(setting, "port", &intopt);
        if (rc && intopt)
            cfg.svrs[i].sin_port = htons(intopt);
        else {
            fprintf(stderr, "Invalid port option.\n");
            deref(cfg.svrs);
            return -1;
        }
    }

    return 0;
}

static int load_config(int argc, char *argv[])
{
    vlogI("Loading config...");

    cfg_file = get_config_file(cfg_file, default_config_files);
    if (!cfg_file) {
        fprintf(stderr, "Error: Missing config file.\n");
        return -1;
    }

    if (!carrier_config_load(cfg_file, load_svrs, &cfg.copts)) {
        fprintf(stderr, "loading configure failed !\n");
        return -1;
    }

    carrier_config_update(&cfg.copts, argc, argv);

    return 0;
}

static void friend_conn_cb(Carrier *w, const char *friendid,
                           CarrierConnectionStatus status, void *context)
{
    static size_t online = 0;

    switch (status) {
    case CarrierConnectionStatus_Connected:
        ++online;
        vlogI("%zu/%zu online", online, cfg.svrs_cnt * nodes_per_svr);
        break;

    case CarrierConnectionStatus_Disconnected:
        --online;
        vlogI("%zu/%zu online", online, cfg.svrs_cnt * nodes_per_svr);
        break;

    default:
        vlogE("Error!!! Got unknown connection status %d.", status);
    }
}

static void friend_req_cb(Carrier *w, const char *userid,
                          const CarrierUserInfo *info, const char *hello,
                          void *context)
{
    static size_t accepted = 0;
    int rc;

    rc = carrier_accept_friend(w, info->userid);
    if (rc < 0) {
        vlogE("Accepting friend request failed.");
        return;
    }

    ++accepted;
    vlogI("%zu/%zu accepted", accepted, cfg.svrs_cnt * nodes_per_svr);
}

static void msg_cb(Carrier *w, const char *from, const void *msg, size_t len,
                   int64_t timestamp, bool is_offline, void *context)
{
    pthread_mutex_lock(&lock);
    ++msg_recved;
    vlogI("%zu/%zu message received", msg_recved, cfg.svrs_cnt * nodes_per_svr);
    if (msg_recved == cfg.svrs_cnt * nodes_per_svr)
        pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);
}

static void *carrier_routine(void *arg)
{
    int rc;

    rc = carrier_run(w, 10);
    if (rc != 0)
        vlogE("Error start carrier loop: 0x%x\n", carrier_get_error());

    return NULL;
}

static void rm_data_dir()
{
    char cmd[PATH_MAX];

    snprintf(cmd, sizeof(cmd), "rm -rf %s", cfg.copts.persistent_location);
    system(cmd);
}

static int start_carrier()
{
    CarrierCallbacks cbs;
    int rc;

    vlogI("Starting carrier...");

    memset(&cbs, 0, sizeof(cbs));
    cbs.friend_connection = friend_conn_cb;
    cbs.friend_request = friend_req_cb;
    cbs.friend_message = msg_cb;

    w = carrier_new(&cfg.copts, &cbs, NULL);
    if (!w) {
        vlogE("Error create carrier instance: 0x%x", carrier_get_error());
        return -1;
    }

    rc = pthread_create(&carrier_thread, NULL, carrier_routine, NULL);
    if (rc) {
        vlogE("Creating Carrier thread failed.");
        carrier_kill(w);
        rm_data_dir();
        return -1;
    }

    return 0;
}

static void cleanup_config()
{
    carrier_config_free(&cfg.copts);
    deref(cfg.svrs);
}

static void close_fds(void *arg)
{
    int valid_fds = *(int *)arg;
    int i;

    for (i = 0; i < valid_fds; ++i)
        close(svr_fds[i]);
    free(svr_fds);
}

static void *connect_to_svrs_bg(void *arg)
{
    struct timeval tval = {
        .tv_sec = 60,
        .tv_usec = 0
    };
    fd_set connecting_fds;
    fd_set connected_fds;
    size_t connected;
    int valid_fds;
    int writable_cnt;
    int rc;
    int i;

    (void)arg;

    FD_ZERO(&connecting_fds);
    valid_fds = 0;

    svr_fds = malloc(sizeof(svr_fds[0]) * cfg.svrs_cnt);
    if (!svr_fds) {
        vlogE("OOM.");
        return NULL;
    }

    for (i = 0; i < cfg.svrs_cnt; ++i) {
        svr_fds[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        if (svr_fds[i] < 0) {
            vlogE("Creating socket failed.");
            goto quit_prog;
        }
        ++valid_fds;

        rc = fcntl(svr_fds[i], F_SETFL, fcntl(svr_fds[i], F_GETFL, 0) | O_NONBLOCK);
        if (rc < 0) {
            vlogE("Setting socket non-blocking failed.");
            goto quit_prog;
        }

        rc = connect(svr_fds[i], (struct sockaddr *)(cfg.svrs + i), sizeof(cfg.svrs[i]));
        if (rc < 0 && errno != EINPROGRESS) {
            vlogE("Connecting to server failed.");
            goto quit_prog;
        } else if (rc < 0)
            FD_SET(svr_fds[i], &connecting_fds);
        else {
            pthread_mutex_lock(&lock);
            ++connected_cnt;
            pthread_mutex_unlock(&lock);
        }
    }

    while (1) {
        pthread_mutex_lock(&lock);
        if (connected_cnt == cfg.svrs_cnt) {
            pthread_mutex_unlock(&lock);
            pthread_cond_signal(&cond);
            return NULL;
        }
        pthread_mutex_unlock(&lock);

        connected_fds = connecting_fds;
        pthread_cleanup_push(close_fds, &valid_fds);
        writable_cnt = select(FD_SETSIZE, NULL, &connected_fds, NULL, &tval);
        pthread_cleanup_pop(0);
        if (writable_cnt <= 0) {
            vlogE("select() failed.");
            goto quit_prog;
        }

        for (i = 0, connected = 0; i < cfg.svrs_cnt && writable_cnt; ++i) {
            if (!FD_ISSET(svr_fds[i], &connected_fds))
                continue;

            --writable_cnt;

            rc = connect(svr_fds[i], (struct sockaddr *)(cfg.svrs + i), sizeof(cfg.svrs[i]));
            if (!(rc < 0 && errno == EISCONN)) {
                vlogE("Connection failed.");
                goto quit_prog;
            }

            FD_CLR(svr_fds[i], &connecting_fds);
            ++connected;
        }

        pthread_mutex_lock(&lock);
        connected_cnt += connected;
        pthread_mutex_unlock(&lock);
    }

quit_prog:
    for (i = 0; i < valid_fds; ++i)
        close(svr_fds[i]);
    free(svr_fds);

    pthread_mutex_lock(&lock);
    quit = true;
    pthread_mutex_unlock(&lock);
    pthread_cond_signal(&cond);

    return NULL;
}

static void *poll_svrs(void *arg)
{
    fd_set poll_fds;
    fd_set readable_fds;
    int readable_cnt;
    char buf[1024];
    int rc;
    int i;

    FD_ZERO(&poll_fds);

    for (i = 0; i < cfg.svrs_cnt; ++i)
        FD_SET(svr_fds[i], &poll_fds);

    while (1) {
        readable_fds = poll_fds;
        readable_cnt = select(FD_SETSIZE, &readable_fds, NULL, NULL, NULL);
        if (readable_cnt <= 0) {
            vlogE("Select() failed. Stopping...");
            goto quit_prog;
        }

        for (i = 0; i < cfg.svrs_cnt && readable_cnt; ++i) {
            if (!FD_ISSET(svr_fds[i], &readable_fds))
                continue;

            --readable_cnt;

            rc = read(svr_fds[i], buf, sizeof(buf));
            if (rc <= 0) {
                vlogE("Read() from server failed. Stopping...");
                goto quit_prog;
            }

            if (!strcmp(buf, "carrier online")) {
                pthread_mutex_lock(&lock);
                if (++online_on_svrs == cfg.svrs_cnt)
                    pthread_cond_signal(&cond);
                pthread_mutex_unlock(&lock);
            } else {
                vlogE("Invalid server message. Stopping...");
                goto quit_prog;
            }
        }
    }

quit_prog:
    pthread_mutex_lock(&lock);
    quit = true;
    pthread_mutex_unlock(&lock);
    pthread_cond_signal(&cond);
    return NULL;
}

static int connect_to_svrs()
{
    int rc;

    vlogI("Connecting to servers...");

    rc = pthread_create(&svrs_thread, NULL, connect_to_svrs_bg, NULL);
    if (rc) {
        vlogE("Creating servers connection thread failed.");
        return -1;
    }

    pthread_mutex_lock(&lock);
    while (connected_cnt != cfg.svrs_cnt && !quit)
        pthread_cond_wait(&cond, &lock);
    if (quit) {
        pthread_mutex_unlock(&lock);
        pthread_cancel(svrs_thread);
        pthread_join(svrs_thread, NULL);
        return -1;
    }
    pthread_mutex_unlock(&lock);

    rc = pthread_create(&svrs_thread, NULL, poll_svrs, NULL);
    if (rc) {
        vlogE("Creating servers polling thread failed.");
        return -1;
    }

    return 0;
}


static void stop_carrier()
{
    vlogI("Stopping carrier...");

    carrier_kill(w);
    pthread_join(carrier_thread, NULL);
    rm_data_dir();
}

#define send_msg(fd, fmt, ...) (dprintf((fd), fmt"%c", ##__VA_ARGS__, '\0') < 0 ? -1 : 0)
static int send_carrier_addr_to_svrs()
{
    char addr[CARRIER_MAX_ADDRESS_LEN + 1];
    int rc;
    int i;

    vlogI("Notifying servers of carrier address...");

    for (i = 0; i < cfg.svrs_cnt; ++i) {
        rc = send_msg(svr_fds[i], "%s %zu",
                      carrier_get_address(w, addr, sizeof(addr)),
                      nodes_per_svr);
        if (rc < 0) {
            vlogE("Sending carrier address to server failed.");
            return -1;
        }
    }

    return 0;
}

static void disconnect_from_svrs()
{
    int i;

    vlogI("Disconnecting from servers...");

    pthread_cancel(svrs_thread);
    pthread_join(svrs_thread, NULL);

    for (i = 0; i < cfg.svrs_cnt; ++i)
        close(svr_fds[i]);

    free(svr_fds);
}

static int wait_for_node_online_on_svr()
{
    int rc;

    vlogI("Waiting for carrier online on servers...");

    pthread_mutex_lock(&lock);

    while (online_on_svrs != cfg.svrs_cnt && !quit)
        pthread_cond_wait(&cond, &lock);

    rc = quit ? -1 : 0;

    pthread_mutex_unlock(&lock);

    return rc;
}

static int order_nodes_to_send_msg()
{
    int rc;
    int i;

    vlogI("Ordering nodes to send message...");

    for (i = 0; i < cfg.svrs_cnt; ++i) {
        rc = send_msg(svr_fds[i], "%s", "send message");
        if (rc < 0) {
            vlogE("Ordering to send message failed.");
            return -1;
        }
    }

    return 0;
}

static int wait_for_msg_recved()
{
    int rc;

    vlogI("Waiting for messages...");

    pthread_mutex_lock(&lock);

    while (msg_recved != nodes_per_svr * cfg.svrs_cnt && !quit)
        pthread_cond_wait(&cond, &lock);

    rc = quit ? -1 : 0;

    pthread_mutex_unlock(&lock);

    vlogI("Message received: %zu/%zu", msg_recved, cfg.svrs_cnt * nodes_per_svr);

    return rc;
}

int main(int argc, char *argv[])
{
    int wait_for_attach = 0;
    int rc;

    int opt;
    int idx;
    struct option options[] = {
        { "nodes-per-server", required_argument,  NULL, 'n' },
        { "config",         required_argument,  NULL, 'c' },
        { "udp-enabled",    required_argument,  NULL, 1 },
        { "log-level",      required_argument,  NULL, 2 },
        { "log-file",       required_argument,  NULL, 3 },
        { "data-dir",       required_argument,  NULL, 4 },
        { "debug",          no_argument,        NULL, 5 },
        { "help",           no_argument,        NULL, 'h' },
        { NULL,             0,                  NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "n:c:h?", options, &idx)) != -1) {
        switch (opt) {
        case 'n':
            nodes_per_svr = atoi(optarg);
            break;

        case 'c':
            cfg_file = optarg;
            break;

        case 1:
        case 2:
        case 3:
        case 4:
            break;

        case 5:
            wait_for_attach = 1;
            break;

        case 'h':
        case '?':
        default:
            usage();
            exit(-1);
        }
    }

    if (wait_for_attach) {
        printf("Wait for debugger attaching, process id is: %d.\n", getpid());
#ifndef _MSC_VER
        printf("After debugger attached, press any key to continue......");
        getchar();
#else
        DebugBreak();
#endif
    }

    rc = start_sig_poll();
    if (rc < 0)
        return rc;

    rc = load_config(argc, argv);
    if (rc < 0) {
        stop_sig_poll();
        return rc;
    }

    rc = start_carrier();
    if (rc < 0) {
        cleanup_config();
        stop_sig_poll();
        return rc;
    }

    rc = connect_to_svrs();
    if (rc < 0) {
        stop_carrier();
        cleanup_config();
        stop_sig_poll();
        return rc;
    }

    rc = send_carrier_addr_to_svrs();
    if (rc < 0) {
        disconnect_from_svrs();
        stop_carrier();
        cleanup_config();
        stop_sig_poll();
        return rc;
    }

    rc = wait_for_node_online_on_svr();
    if (rc < 0) {
        disconnect_from_svrs();
        stop_carrier();
        cleanup_config();
        stop_sig_poll();
        return rc;
    }

    rc = order_nodes_to_send_msg();
    if (rc < 0) {
        disconnect_from_svrs();
        stop_carrier();
        cleanup_config();
        stop_sig_poll();
        return rc;
    }

    rc = wait_for_msg_recved();
    disconnect_from_svrs();
    stop_carrier();
    cleanup_config();
    stop_sig_poll();

    return rc;
}
