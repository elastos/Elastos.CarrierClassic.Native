/*
 * Copyright (c) 2021 Elastos Foundation
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
#include <sys/resource.h>

#if defined(_WIN32) || defined(_WIN64)
#include <io.h>
#endif

#include <pthread.h>

#include <carrier.h>
#include <libconfig.h>
#include "carrier_config.h"

#define CONFIG_NAME   "maxfrd.conf"

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
    struct sockaddr_in binding_addr;
} cfg_t;

static const char *cfg_file;
static cfg_t cfg;
static sigset_t mask;
static sigset_t old_mask;
static char client_carrier_addr[CARRIER_MAX_ADDRESS_LEN + 1];
static char cmd[1024];
static int client_fd;
static size_t carriers;
static size_t carriers_online;
static size_t online_on_carriers;
static Carrier **ws;
static pthread_t sig_thread;
static pthread_t carriers_thread;
static pthread_t polling_thread;
static bool client_connected;
static bool cmd_pending;
static bool error;
static bool quit;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static void usage(void)
{
    printf("Max friends daemon, tests how many friends a node can make.\n");
    printf("Usage: maxfrd [OPTION]...\n");
    printf("\n");
    printf("First run options:\n");
    printf("  -c, --config=CONFIG_FILE   Set config file path.\n");
    printf("      --udp-enabled=0|1      Enable UDP, override the option in config.\n");
    printf("      --log-level=LEVEL      Log level(0-7), override the option in config.\n");
    printf("      --log-file=FILE        Log file name, override the option in config.\n");
    printf("      --data-dir=PATH        Data location, override the option in config.\n");
    printf("\n");
    printf("Debugging options:\n");
    printf("      --debug               Wait for debugger attach after start.\n");
    printf("\n");
}

static int load_binding_addr(void *p, CarrierOptions *opts)
{
    config_t *c = p;
    const char *stropt;
    int intopt;
    int rc;

    (void)opts;

    memset(&cfg.binding_addr, 0, sizeof(cfg.binding_addr));
    cfg.binding_addr.sin_family = AF_INET;

    rc = config_lookup_string(c, "host", &stropt);
    if (!(rc && *stropt && inet_pton(AF_INET, stropt, &cfg.binding_addr.sin_addr) == 1)) {
        fprintf(stderr, "Missing host setting.\n");
        return -1;
    }

    rc = config_lookup_int(c, "port", &intopt);
    if (rc && intopt) {
        cfg.binding_addr.sin_port = htons(intopt);
        return 0;
    } else {
        fprintf(stderr, "Missing port setting.\n");
        return -1;
    }
}

static int load_config(int argc, char *argv[])
{
    vlogI("Loading config...");

    cfg_file = get_config_file(cfg_file, default_config_files);
    if (!cfg_file) {
        fprintf(stderr, "Error: Missing config file.\n");
        return -1;
    }

    if (!carrier_config_load(cfg_file, load_binding_addr, &cfg.copts)) {
        fprintf(stderr, "loading configure failed !\n");
        return -1;
    }

    carrier_config_update(&cfg.copts, argc, argv);

    return 0;
}

static void friend_conn_cb(Carrier *w, const char *friendid,
                           CarrierConnectionStatus status, void *context)
{
    switch (status) {
    case CarrierConnectionStatus_Connected:
        pthread_mutex_lock(&lock);
        ++online_on_carriers;
        vlogI("%zu/%zu online.", online_on_carriers, carriers);
        if (online_on_carriers == carriers)
            pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);
        break;

    case CarrierConnectionStatus_Disconnected:
        pthread_mutex_lock(&lock);
        --online_on_carriers;
        vlogI("%zu/%zu online.", online_on_carriers, carriers);
        pthread_mutex_unlock(&lock);
        break;

    default:
        vlogE("Error!!! Got unknown connection status %d.", status);
    }
}

static void conn_cb(Carrier *w,
                    CarrierConnectionStatus status, void *context)
{
    switch (status) {
    case CarrierConnectionStatus_Connected:
        pthread_mutex_lock(&lock);
        ++carriers_online;
        vlogI("%zu/%zu ready", carriers_online, carriers);
        if (carriers_online == carriers)
            pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);
        break;

    case CarrierConnectionStatus_Disconnected:
        pthread_mutex_lock(&lock);
        --carriers_online;
        vlogI("%zu/%zu ready", carriers_online, carriers);
        pthread_mutex_unlock(&lock);
        break;

    default:
        vlogE("Error!!! Got unknown connection status %d.", status);
    }
}

void carrier_prepare(Carrier *w);
bool carrier_is_stopped(Carrier *w);
struct timeval carrier_next_iteration(Carrier *w, int interval);
void carrier_iterate(Carrier *w);
void carrier_finish(Carrier *w);

static void *carriers_routine(void *arg)
{
    struct timeval expire;
    struct timeval check;
    struct timeval tmp;
    int i;

    for (i = 0; i < carriers; ++i)
        carrier_prepare(ws[i]);

    while (1) {
        for (i = 0; i < carriers; ++i)
            if (carrier_is_stopped(ws[i]))
                goto finish;

        for (i = 0; i < carriers; ++i)
            carrier_iterate(ws[i]);

        expire = carrier_next_iteration(ws[0], 0);
        for (i = 1; i < carriers; ++i) {
            tmp = carrier_next_iteration(ws[i], 0);
            if (timercmp(&expire, &tmp, >))
                expire = tmp;
        }
        gettimeofday(&check, NULL);
        if (timercmp(&expire, &check, >)) {
            timersub(&expire, &check, &tmp);
            usleep(tmp.tv_usec);
        }
    }

finish:
    for (i = 0; i < carriers; ++i)
        carrier_finish(ws[i]);
    return NULL;
}

static void rm_data_dir()
{
    char cmd[PATH_MAX];

    snprintf(cmd, sizeof(cmd), "rm -rf %s", cfg.copts.persistent_location);
    system(cmd);
}

static int start_carriers()
{
    char data_dir[PATH_MAX];
    char log_file[PATH_MAX];
    char *argv[] = {
        "ignore",
        "--data-dir", data_dir,
        "--log-file", log_file
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    CarrierCallbacks cbs;
    CarrierOptions opts;
    int valid_ws;
    int rc;
    int i;

    vlogI("Starting carriers...");

    ws = malloc(sizeof(ws[0]) * carriers);
    if (!ws) {
        vlogE("OOM");
        return -1;
    }

    memset(&cbs, 0, sizeof(cbs));
    cbs.friend_connection = friend_conn_cb;
    cbs.connection_status = conn_cb;

    carrier_config_copy(&opts, &cfg.copts);
    valid_ws = 0;
    for (i = 0; i < carriers; ++i) {
        snprintf(data_dir, sizeof(data_dir), "%s/%d", cfg.copts.persistent_location, i);
        snprintf(log_file, sizeof(log_file), "%s/maxfrd.log", data_dir);

        carrier_config_update(&opts, argc, argv);

        ws[i] = carrier_new(&opts, &cbs, NULL);
        if (!ws[i]) {
            vlogE("Error create carrier instance: 0x%x", carrier_get_error());
            carrier_config_free(&opts);
            goto failed;
        }
        ref(ws[i]);

        ++valid_ws;
    }
    carrier_config_free(&opts);

    rc = pthread_create(&carriers_thread, NULL, carriers_routine, NULL);
    if (rc) {
        vlogE("Creating Carrier thread failed.");
        goto failed;
    }

    return 0;

failed:
    for (i = 0; i < valid_ws; ++i) {
        deref(ws[i]);
        carrier_kill(ws[i]);
    }
    free(ws);
    rm_data_dir();
    return -1;
}

static void stop_carriers()
{
    int i;

    vlogI("Stopping carrier...");

    for (i = 0; i < carriers; ++i)
        carrier_kill(ws[i]);
    pthread_join(carriers_thread, NULL);
    for (i = 0; i < carriers; ++i)
        deref(ws[i]);
    free(ws);
    carriers = 0;
    carriers_online = 0;
    online_on_carriers = 0;
    rm_data_dir();
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

static void close_fd(void *arg)
{
    int *fd_tmp = arg;

    if (*fd_tmp >= 0)
        close(*fd_tmp);
}

static void *poll_client(void *arg)
{
    int rc;
    int fd;

    (void)arg;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) {
        vlogE("Creating socket failed.");
        goto poll_failed;
    }

    rc = bind(fd, (struct sockaddr *)&cfg.binding_addr, sizeof(cfg.binding_addr));
    if (rc < 0) {
        vlogE("bind() failed.");
        close(fd);
        goto poll_failed;
    }

    rc = listen(fd, 1);
    if (rc < 0) {
        vlogE("listen() failed.");
        close(fd);
        goto poll_failed;
    }

    pthread_cleanup_push(close_fd, &fd);
    pthread_cleanup_push(close_fd, &client_fd);
    client_fd = accept(fd, NULL, NULL);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    close(fd);
    if (client_fd < 0) {
        vlogE("accept() failed.");
        goto poll_failed;
    }

    pthread_mutex_lock(&lock);
    client_connected = true;
    pthread_mutex_unlock(&lock);
    pthread_cond_signal(&cond);

    while (1) {
        pthread_cleanup_push(close_fd, &client_fd);
        rc = read(client_fd, cmd, sizeof(cmd));
        pthread_cleanup_pop(0);
        if (rc <= 0) {
            close(client_fd);
            if (rc < 0)
                vlogE("read() failed.");
            else
                vlogI("Client disconnected.");
            goto poll_failed;
        }

        pthread_mutex_lock(&lock);
        cmd_pending = true;
        pthread_mutex_unlock(&lock);
        pthread_cond_signal(&cond);

        pthread_mutex_lock(&lock);
        while (cmd_pending) {
            pthread_cleanup_push((void *)pthread_mutex_unlock, &lock);
            pthread_cleanup_push(close_fd, &client_fd);
            pthread_cond_wait(&cond, &lock);
            pthread_cleanup_pop(0);
            pthread_cleanup_pop(0);
        }
        pthread_mutex_unlock(&lock);
    }

poll_failed:
    pthread_mutex_lock(&lock);
    error = true;
    pthread_mutex_unlock(&lock);
    pthread_cond_signal(&cond);
    return NULL;
}

static int wait_for_client_connected()
{
    int rc;

    vlogI("Waiting for client connected...");

    rc = pthread_create(&polling_thread, NULL, poll_client, NULL);
    if (rc) {
        vlogE("Polling thread failed to create.");
        return -1;
    }

    pthread_mutex_lock(&lock);

    while (!client_connected && !error && !quit)
        pthread_cond_wait(&cond, &lock);

    rc = (error || quit) ? -1 : 0;

    pthread_mutex_unlock(&lock);

    if (rc < 0) {
        pthread_cancel(polling_thread);
        pthread_join(polling_thread, NULL);
    }

    return rc;
}

static int get_client_carrier_addr()
{
    int rc;

    vlogI("Getting client carrier address...");

    pthread_mutex_lock(&lock);
    while (!cmd_pending && !error && !quit)
        pthread_cond_wait(&cond, &lock);

    if (error || quit) {
        pthread_mutex_unlock(&lock);
        return -1;
    }

    rc = sscanf(cmd, "%s %zu", client_carrier_addr, &carriers);
    if (rc != 2 || !carrier_address_is_valid(client_carrier_addr) || !carriers) {
        vlogE("Wrong command from client.");
        pthread_mutex_unlock(&lock);
        return -1;
    }

    cmd_pending = false;
    pthread_mutex_unlock(&lock);
    pthread_cond_signal(&cond);

    return 0;
}

static void disconnect_from_client()
{
    vlogI("Disconnecting from client...");

    pthread_cancel(polling_thread);
    pthread_join(polling_thread, NULL);
    client_connected = false;
    cmd_pending = false;
}

static int carriers_add_friend_with_client_carrier()
{
    int rc;
    int i;

    vlogI("Adding friend with client carrier...");

    pthread_mutex_lock(&lock);
    while (carriers_online != carriers && !error && !quit)
        pthread_cond_wait(&cond, &lock);
    if (error || quit) {
        pthread_mutex_unlock(&lock);
        return -1;
    }
    pthread_mutex_unlock(&lock);

    for (i = 0; i < carriers; ++i) {
        rc = carrier_add_friend(ws[i], client_carrier_addr, "hello");
        if (rc < 0) {
            vlogE("Adding friend failed.");
            return rc;
        }
        vlogI("%d/%zu friends added", i + 1, carriers);
    }

    return 0;
}

#define send_msg(fd, fmt, ...) (dprintf((fd), fmt"%c", ##__VA_ARGS__, '\0') < 0 ? -1 : 0)
static int carriers_wait_for_client_carrier_online()
{
    int rc;

    vlogI("Waiting for client carrier online...");

    pthread_mutex_lock(&lock);
    while (online_on_carriers != carriers && !error && !quit)
        pthread_cond_wait(&cond, &lock);
    if (error || quit) {
        pthread_mutex_unlock(&lock);
        return -1;
    }
    pthread_mutex_unlock(&lock);

    rc = send_msg(client_fd, "carrier online");
    if (rc < 0) {
        vlogE("write() failed.");
        return -1;
    }

    return 0;
}

static int wait_for_client_send_msg_cmd()
{
    vlogI("Waiting for client send message command...");

    pthread_mutex_lock(&lock);
    while (!cmd_pending && !error && !quit)
        pthread_cond_wait(&cond, &lock);

    if (error || quit) {
        pthread_mutex_unlock(&lock);
        return -1;
    }

    if (strcmp(cmd, "send message")) {
        pthread_mutex_unlock(&lock);
        vlogE("Wrong command from client.");
        return -1;
    }

    cmd_pending = false;
    pthread_mutex_unlock(&lock);
    pthread_cond_signal(&cond);

    return 0;
}

static int carriers_send_msg()
{
    char node_id[CARRIER_MAX_ID_LEN + 1];
    int rc;
    int i;

    vlogI("Sending message to client carrier...");

    carrier_get_id_by_address(client_carrier_addr, node_id, sizeof(node_id));

    for (i = 0; i < carriers; ++i) {
        rc = carrier_send_friend_message(ws[i], node_id, "hello", strlen("hello") + 1,
                                         NULL, NULL, NULL);
        if (rc < 0) {
            vlogE("Sending friend message failed.");
            return -1;
        }
    }

    return 0;
}

static void wait_for_client_disconnected()
{
    vlogI("Waiting for client disconnected...");

    pthread_mutex_lock(&lock);
    while (!error && !quit)
        pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);
}

static void cleanup_config()
{
    carrier_config_free(&cfg.copts);
}

int main(int argc, char *argv[])
{
    int wait_for_attach = 0;
    int rc;

    int opt;
    int idx;
    struct option options[] = {
        { "config",         required_argument,  NULL, 'c' },
        { "udp-enabled",    required_argument,  NULL, 1 },
        { "log-level",      required_argument,  NULL, 2 },
        { "log-file",       required_argument,  NULL, 3 },
        { "data-dir",       required_argument,  NULL, 4 },
        { "debug",          no_argument,        NULL, 5 },
        { "help",           no_argument,        NULL, 'h' },
        { NULL,             0,                  NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "c:h?", options, &idx)) != -1) {
        switch (opt) {
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

    while (1) {
        rc = wait_for_client_connected();
        if (rc < 0)
            goto done;

        rc = get_client_carrier_addr();
        if (rc < 0) {
            disconnect_from_client();
            goto done;
        }

        rc = start_carriers();
        if (rc < 0) {
            disconnect_from_client();
            goto done;
        }

        rc = carriers_add_friend_with_client_carrier();
        if (rc < 0) {
            stop_carriers();
            disconnect_from_client();
            goto done;
        }

        rc = carriers_wait_for_client_carrier_online();
        if (rc < 0) {
            stop_carriers();
            disconnect_from_client();
            goto done;
        }

        rc = wait_for_client_send_msg_cmd();
        if (rc < 0) {
            stop_carriers();
            disconnect_from_client();
            goto done;
        }

        rc = carriers_send_msg();
        if (rc < 0) {
            stop_carriers();
            disconnect_from_client();
            goto done;
        }

        wait_for_client_disconnected();

        stop_carriers();
        disconnect_from_client();

done:
        pthread_mutex_lock(&lock);
        if (quit) {
            pthread_mutex_unlock(&lock);
            break;
        }
        error = false;
        pthread_mutex_unlock(&lock);
    }

    cleanup_config();
    stop_sig_poll();

    return 0;
}
