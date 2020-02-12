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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <termios.h>

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
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <ela_carrier.h>
#include <cjson/cJSON.h>

#include "../carrier_config.h"
#include "../jsonrpc.h"
#include "../error_code.h"
#include "feeds_client.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>

static enum {
    STANDBY,
    TYPING,
    GOTCMD,
    STOP
} state;

static FeedsClient *fc;
static struct termios term;

static
void console_prompt(void)
{
    fprintf(stdout, "# ");
    fflush(stdout);
}

static
void console(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

static
void carrier_log_printer(const char *fmt, va_list ap)
{
    // do nothing
}

static
int sys_coredump_set(bool enable)
{
    const struct rlimit rlim = {
        enable ? RLIM_INFINITY : 0,
        enable ? RLIM_INFINITY : 0
    };

    return setrlimit(RLIMIT_CORE, &rlim);
}
#endif

static
void usage(void)
{
    console("Elastos feeds client CLI.");
    console("Usage: feeds_cli [OPTION]...");
    console("");
    console("First run options:");
    console("  -c, --config=CONFIG_FILE  Set config file path.");
    console("      --udp-enabled=0|1     Enable UDP, override the option in config.");
    console("      --log-level=LEVEL     Log level(0-7), override the option in config.");
    console("      --log-file=FILE       Log file name, override the option in config.");
    console("      --data-dir=PATH       Data location, override the option in config.");
    console("");
    console("Debugging options:");
    console("      --debug               Wait for debugger attach after start.");
    console("");
}

#define CONFIG_NAME "carrier.conf"
static const char *default_config_files[] = {
    "./"CONFIG_NAME,
    "../etc/carrier/"CONFIG_NAME,
    "/usr/local/etc/carrier/"CONFIG_NAME,
    "/etc/carrier/"CONFIG_NAME,
    NULL
};

static
char *read_cmd(void)
{
    int ch = 0;
    char *p;
    static int  cmd_len = 0;
    static char cmd_line[1024];

getchar:
    ch = fgetc(stdin);
    if (ch == EOF) {
        if (feof(stdin))
            state = STOP;
        return NULL;
    }

    if (isprint(ch)) {
        putchar(ch);

        cmd_line[cmd_len++] = ch;
        if (state == STANDBY)
            state = TYPING;
    } else if (ch == '\r' || ch == '\n') {
        putchar(ch);

        cmd_line[cmd_len] = 0;
        // Trim trailing spaces;
        for (p = cmd_line + cmd_len -1; p > cmd_line && isspace(*p); p--);
        *(++p) = 0;

        // Trim leading spaces;
        for (p = cmd_line; *p && isspace(*p); p++);

        cmd_len = 0;
        if (state == TYPING) {
            state = GOTCMD;
            return p;
        } else
            console_prompt();
    } else if (ch == 127) {
        if (state == TYPING)
            printf("\b \b");

        if (state == TYPING && !--cmd_len)
            state = STANDBY;
    }

    goto getchar;
}

static
void get_address(int argc, char *argv[])
{
    if (argc != 1) {
        console("Invalid command syntax.");
        return;
    }

    char addr[ELA_MAX_ADDRESS_LEN + 1] = {0};
    ela_get_address(feeds_client_get_carrier(fc), addr, sizeof(addr));
    console("Address: %s", addr);
}

static
void get_nodeid(int argc, char *argv[])
{
    if (argc != 1) {
        console("Invalid command syntax.");
        return;
    }

    char id[ELA_MAX_ID_LEN + 1] = {0};
    ela_get_nodeid(feeds_client_get_carrier(fc), id, sizeof(id));
    console("Node ID: %s", id);
}

static
void get_userid(int argc, char *argv[])
{
    if (argc != 1) {
        console("Invalid command syntax.");
        return;
    }

    char id[ELA_MAX_ID_LEN + 1] = {0};
    ela_get_userid(feeds_client_get_carrier(fc), id, sizeof(id));
    console("User ID: %s", id);
}

static
void friend_add(int argc, char *argv[])
{
    char node_id[ELA_MAX_ID_LEN + 1];
    int rc;

    if (argc != 3) {
        console("Invalid command syntax.");
        return;
    }

    if (!ela_address_is_valid(argv[1]))
        console("Invalid address.");

    rc = feeds_client_friend_add(fc, argv[1], argv[2]);
    if (rc < 0)
        console("Failed to add friend.");

    ela_get_id_by_address(argv[1], node_id, sizeof(node_id));
    console("Friend %s online.", node_id);
}

static
void friend_remove(int argc, char *argv[])
{
    int rc;

    if (argc != 2) {
        console("Invalid command syntax.");
        return;
    }

    rc = feeds_client_friend_remove(fc, argv[1]);
    if (rc < 0)
        console("Failed to remove friend.");
}

static int first_friends_item = 1;
static const char *connection_name[] = {
    "online",
    "offline"
};

static
bool get_friends_callback(const ElaFriendInfo *friend_info, void *context)
{
    static int count;

    if (first_friends_item) {
        count = 0;
        console("Friends list:");
        console("  %-46s %8s %s", "ID", "Connection", "Label");
        console("  %-46s %8s %s", "----------------", "----------", "-----");
    }

    if (friend_info) {
        console("  %-46s %8s %s", friend_info->user_info.userid,
               connection_name[friend_info->status], friend_info->label);
        first_friends_item = 0;
        count++;
    } else {
        /* The list ended */
        console("  ----------------");
        console("Total %d friends.", count);

        first_friends_item = 1;
    }

    return true;
}

static
void list_friends(int argc, char *argv[])
{
    if (argc != 1) {
        console("Invalid command syntax.");
        return;
    }

    ela_get_friends(feeds_client_get_carrier(fc), get_friends_callback, NULL);
}

static
void kill_carrier(int argc, char *argv[])
{
    state = STOP;
}

static
void create_topic(int argc, char *argv[])
{
    cJSON *resp;
    int rc;

    if (argc != 4) {
        console("Invalid command syntax.");
        return;
    }

    rc = feeds_client_wait_until_friend_connected(fc, argv[1]);
    if (rc < 0) {
        console("%s is not friend now.", argv[1]);
        return;
    }

    rc = feeds_client_create_topic(fc, argv[1], argv[2], argv[3], &resp);
    if (rc < 0)
        console("failed to create topic. Reason: %s",
                resp ? jsonrpc_get_error_message(resp) : "Local Error");

    if (resp)
        cJSON_Delete(resp);
}

static
void post_event(int argc, char *argv[])
{
    cJSON *resp;
    int rc;

    if (argc != 4) {
        console("Invalid command syntax.");
        return;
    }

    rc = feeds_client_wait_until_friend_connected(fc, argv[1]);
    if (rc < 0) {
        console("%s is not friend now.", argv[1]);
        return;
    }

    rc = feeds_client_post_event(fc, argv[1], argv[2], argv[3], &resp);
    if (rc < 0)
        console("Failed to post event. Reason: %s",
                resp ? jsonrpc_get_error_message(resp) : "Local Error");

    if (resp)
        cJSON_Delete(resp);
}

static
void list_owned_topics(int argc, char *argv[])
{
    const cJSON *topic;
    cJSON *resp;
    int i = 1;
    int rc;

    if (argc != 2) {
        console("Invalid command syntax.");
        return;
    }

    rc = feeds_client_wait_until_friend_connected(fc, argv[1]);
    if (rc < 0) {
        console("%s is not friend now.", argv[1]);
        return;
    }

    rc = feeds_client_list_owned_topics(fc, argv[1], &resp);
    if (rc < 0) {
        console("Failed to list owned topics. Reason: %s",
                resp ? jsonrpc_get_error_message(resp) : "Local Error");
        goto finally;
    }

    cJSON_ArrayForEach(topic, jsonrpc_get_result(resp))
        console("%d. name: %s, desc: %s", i++,
                cJSON_GetObjectItemCaseSensitive(topic, "name")->valuestring,
                cJSON_GetObjectItemCaseSensitive(topic, "desc")->valuestring);

finally:
    if (resp)
        cJSON_Delete(resp);
}

static
void subscribe(int argc, char *argv[])
{
    cJSON *resp;
    int rc;

    if (argc != 3) {
        console("Invalid command syntax.");
        return;
    }

    rc = feeds_client_wait_until_friend_connected(fc, argv[1]);
    if (rc < 0) {
        console("%s is not friend now.", argv[1]);
        return;
    }

    rc = feeds_client_subscribe(fc, argv[1], argv[2], &resp);
    if (rc < 0)
        console("Failed to subscribe topic. Reason: %s",
                resp ? jsonrpc_get_error_message(resp) : "Local Error");

    if (resp)
        cJSON_Delete(resp);
}

static
void unsubscribe(int argc, char *argv[])
{
    cJSON *resp;
    int rc;

    if (argc != 3) {
        console("Invalid command syntax.");
        return;
    }

    rc = feeds_client_wait_until_friend_connected(fc, argv[1]);
    if (rc < 0) {
        console("%s is not friend now.", argv[1]);
        return;
    }

    rc = feeds_client_unsubscribe(fc, argv[1], argv[2], &resp);
    if (rc < 0)
        console("Failed to unsubscribe topic. Reason: %s",
                resp ? jsonrpc_get_error_message(resp) : "Local Error");

    if (resp)
        cJSON_Delete(resp);
}

static
void explore_topics(int argc, char *argv[])
{
    const cJSON *topic;
    cJSON *resp;
    int i = 1;
    int rc;

    if (argc != 2) {
        console("Invalid command syntax.");
        return;
    }

    rc = feeds_client_wait_until_friend_connected(fc, argv[1]);
    if (rc < 0) {
        console("%s is not friend now.", argv[1]);
        return;
    }

    rc = feeds_client_explore_topics(fc, argv[1], &resp);
    if (rc < 0) {
        console("Failed to explore topics. Reason: %s",
                resp ? jsonrpc_get_error_message(resp) : "Local Error");
        goto finally;
    }

    cJSON_ArrayForEach(topic, jsonrpc_get_result(resp))
        console("%d. name: %s, desc: %s", i++,
                cJSON_GetObjectItemCaseSensitive(topic, "name")->valuestring,
                cJSON_GetObjectItemCaseSensitive(topic, "desc")->valuestring);

finally:
    if (resp)
        cJSON_Delete(resp);
}

static
void list_subscribed(int argc, char *argv[])
{
    const cJSON *topic;
    cJSON *resp;
    int i = 1;
    int rc;

    if (argc != 2) {
        console("Invalid command syntax.");
        return;
    }

    rc = feeds_client_wait_until_friend_connected(fc, argv[1]);
    if (rc < 0) {
        console("%s is not friend now.", argv[1]);
        return;
    }

    rc = feeds_client_list_subscribed(fc, argv[1], &resp);
    if (rc < 0) {
        console("Failed to list subscribed topics. Reason: %s",
                resp ? jsonrpc_get_error_message(resp) : "Local Error");
        goto finally;
    }

    cJSON_ArrayForEach(topic, jsonrpc_get_result(resp))
        console("%d. name: %s, desc: %s", i++,
                cJSON_GetObjectItemCaseSensitive(topic, "name")->valuestring,
                cJSON_GetObjectItemCaseSensitive(topic, "desc")->valuestring);

finally:
    if (resp)
        cJSON_Delete(resp);
}

static
void fetch_unreceived(int argc, char *argv[])
{
    const cJSON *elem;
    const cJSON *event;
    const cJSON *seqno;
    const cJSON *ts;
    cJSON *resp;
    int i = 1;
    int rc;

    if (argc != 4) {
        console("Invalid command syntax.");
        return;
    }

    rc = feeds_client_wait_until_friend_connected(fc, argv[1]);
    if (rc < 0) {
        console("%s is not friend now.", argv[1]);
        return;
    }

    rc = feeds_client_fetch_unreceived(fc, argv[1], argv[2], atoi(argv[3]), &resp);
    if (rc < 0) {
        console("Failed to list subscribed topics. Reason: %s",
                resp ? jsonrpc_get_error_message(resp) : "Local Error");
        goto finally;
    }

    cJSON_ArrayForEach(elem, jsonrpc_get_result(resp)) {
        event = cJSON_GetObjectItemCaseSensitive(elem, "event");
        seqno = cJSON_GetObjectItemCaseSensitive(elem, "seqno");
        ts = cJSON_GetObjectItemCaseSensitive(elem, "ts");

        console("%d. event: %s, seqno: %zu, ts: %zu",
                i++,
                event->valuestring,
                (size_t)seqno->valuedouble,
                (size_t)ts->valuedouble);
    }

finally:
    if (resp)
        cJSON_Delete(resp);
}

static void help(int argc, char *argv[]);
struct command {
    const char *cmd;
    void (*function)(int argc, char *argv[]);
    const char *help;
} commands[] = {
    { "help",              help,              "help - Display available command list. *OR* help [Command] - Display usage description for specific command." },

    { "address",           get_address,       "address - Display own address." },
    { "nodeid",            get_nodeid,        "nodeid - Display own node ID." },
    { "userid",            get_userid,        "userid - Display own user ID." },

    { "fadd",              friend_add,        "fadd [Address] [Message] - Add new friend." },
    { "fremove",           friend_remove,     "fremove [User ID] - Remove friend." },
    { "friends",           list_friends,      "friends - List all friends." },
    { "kill",              kill_carrier,      "kill - Stop carrier." },

    { "create_topic",      create_topic,      "create_topic [nodeid] [topic] [desc] - Create topic." },
    { "post_event",        post_event,        "post_event [nodeid] [topic] [event] - Post event." },
    { "list_owned_topics", list_owned_topics, "list_owned_topics [nodeid] - List owned topics." },
    { "subscribe",         subscribe,         "subscribe [nodeid] [topic] - Subscribe topic." },
    { "unsubscribe",       unsubscribe,       "unsubscribe [nodeid] [topic] - Unsubscribe topic." },
    { "explore_topics",    explore_topics,    "explore_topics [nodeid] - Explore topics." },
    { "list_subscribed",   list_subscribed,   "list_subscribed [nodeid] - List subscribed topics." },
    { "fetch_unreceived",  fetch_unreceived,  "fetch_unreceived [nodeid] [topic] [since] - Fetch unreceived topic events." },

    { NULL }
};

static
void help(int argc, char *argv[])
{
    char line[256] = {0};
    struct command *p;

    if (argc == 1) {
        console("available commands list:");

        for (p = commands; p->cmd; p++) {
            strcat(line, p->cmd);
            strcat(line, " ");
        }
        console("  %s", line);
        memset(line, 0, sizeof(line));
    } else {
        for (p = commands; p->cmd; p++) {
            if (strcmp(argv[1], p->cmd) == 0) {
                console("usage: %s", p->help);
                return;
            }
        }
        console("unknown command: %s", argv[1]);
    }
}

static
void do_cmd(char *line)
{
    char *args[64];
    int count = 0;
    char *p;
    int word = 0;

    for (p = line; *p != 0; p++) {
        if (isspace(*p)) {
            *p = 0;
            word = 0;
        } else {
            if (word == 0) {
                args[count] = p;
                count++;
            }
            word = 1;
        }
    }

    if (count > 0) {
        struct command *p;

        for (p = commands; p->cmd; p++) {
            if (strcmp(args[0], p->cmd) == 0) {
                p->function(count, args);
                return;
            }
        }
        console("unknown command: %s", args[0]);
    }
}

static
void reset_tcattr()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

static
void check_new_events()
{
    const cJSON *event;
    cJSON *events;
    int i = 1;

    events = feeds_client_get_new_events(fc);
    if (!events)
        return;

    console("");
    console("New event(s):");
    cJSON_ArrayForEach(event, events)
        console("  %d. topic: %s, event: %s, seqno: %zu, ts: %zu", i++,
                cJSON_GetObjectItemCaseSensitive(event, "topic")->valuestring,
                cJSON_GetObjectItemCaseSensitive(event, "event")->valuestring,
                (size_t)cJSON_GetObjectItemCaseSensitive(event, "seqno")->valuedouble,
                (size_t)cJSON_GetObjectItemCaseSensitive(event, "ts")->valuedouble);
    console_prompt();

    cJSON_Delete(events);
}

int main(int argc, char *argv[])
{
    const char *config_file = NULL;
    int wait_for_attach = 0;
    struct termios term_tmp;
    ElaOptions opts;
    char *cmd;
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

#ifdef HAVE_SYS_RESOURCE_H
    sys_coredump_set(true);
#endif

    memset(&opts, 0, sizeof(opts));

    while ((opt = getopt_long(argc, argv, "c:h?", options, &idx)) != -1) {
        switch (opt) {
        case 'c':
            config_file = optarg;
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
        console("Wait for debugger attaching, process id is: %d.", getpid());
        console("After debugger attached, press any key to continue......");
        getchar();
    }

    rc = fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
        console("set stdin NON-BLOCKING failed.\n");
        return -1;
    }

    rc = setvbuf(stdin, NULL, _IONBF, 0);
    if (rc < 0) {
        console("set stdin unbuffered failed.\n");
        return -1;
    }

    tcgetattr(STDIN_FILENO, &term_tmp);
    term = term_tmp;
    term_tmp.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_tmp);
    atexit(reset_tcattr);

    config_file = get_config_file(config_file, default_config_files);
    if (!config_file) {
        console("missing config file.");
        usage();
        return -1;
    }

    if (!carrier_config_load(config_file, NULL, &opts)) {
        console("loading configure failed!");
        return -1;
    }

    carrier_config_update(&opts, argc, argv);
    opts.log_printer = carrier_log_printer;

    console("connecting to carrier network");
    fc = feeds_client_create(&opts);
    carrier_config_free(&opts);
    if (!fc) {
        console("Error initializing feeds client");
        return -1;
    }
    feeds_client_wait_until_online(fc);

    do {
        state = STANDBY;
        console_prompt();
read_cmd:
        cmd = read_cmd();
        if (state == STANDBY) {
            check_new_events();
            goto read_cmd;
        } else if (state == TYPING)
            goto read_cmd;
        else if (state == GOTCMD)
            do_cmd(cmd);
    } while (state != STOP);

    feeds_client_delete(fc);
    return 0;
}