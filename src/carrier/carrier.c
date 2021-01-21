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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <sys/syslimits.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
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
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <inttypes.h>

#include <crystal.h>

#if !(defined(_WIN32) || defined(_WIN64))
#define O_BINARY 0
#endif

#include "version.h"
#include "carrier.h"
#include "carrier_error.h"
#include "carrier_impl.h"
#include "carrier_extension.h"

#include "hashtable_friends.h"
#include "hashtable_transacted_callbacks.h"
#include "hashtable_transacted_history.h"
#include "hashtable_transacted_assembly.h"
#include "hashtable_unconfirmed_msgs.h"
#include "hashtable_bulkmsgs.h"
#include "hashtable_extensions.h"

#include "packet.h"
#include "dht.h"
#include "express.h"

#define TASSEMBLY_TIMEOUT               (60) //60s.

/* it would conduct to pull offline messages at the regular interval
 * of 5 minutes except that connection status of at least one friend
 * changes, which would conduct at interval of 2 minutes only for
 * that moment.
 */
#define PULLMSG_REGULAR_INTERVAL (5 * 60) //5m
#define PULLMSG_INSTANT_INTERVAL (2 * 60) //2m

// Carrier invite request/response data transmission unit length.
#define INVITE_DATA_UNIT                (1280)

#define DHT_MSG_EXPIRE_TIME               (60) //60s.

const char* carrier_get_version(void)
{
    return carrier_version;
}

static bool is_valid_key(const char *key)
{
    char result[DHT_PUBLIC_KEY_SIZE];
    ssize_t len;

    len = base58_decode(key, strlen(key), result, sizeof(result));
    return len == DHT_PUBLIC_KEY_SIZE;
}

bool carrier_id_is_valid(const char *id)
{
    if (!id || !*id) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return false;
    }

    return is_valid_key(id);
}

static uint16_t address_checksum(const uint8_t *address, uint32_t len)
{
    uint8_t checksum[2] = {0};
    uint16_t check;
    uint32_t i;

    for (i = 0; i < len; ++i)
        checksum[i % 2] ^= address[i];

    memcpy(&check, checksum, sizeof(check));
    return check;
}

static bool is_valid_address(const char *address)
{
    uint8_t addr[DHT_ADDRESS_SIZE];
    uint16_t check, checksum;
    ssize_t len;

    len = base58_decode(address, strlen(address), addr, sizeof(addr));
    if (len != DHT_ADDRESS_SIZE)
        return false;

    memcpy(&check, addr + DHT_PUBLIC_KEY_SIZE + sizeof(uint32_t), sizeof(check));
    checksum = address_checksum(addr, DHT_ADDRESS_SIZE - sizeof(checksum));

    return checksum == check;
}

bool carrier_address_is_valid(const char *address)
{
    if (!address || !*address) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return false;
    }

    return is_valid_address(address);
}

char *carrier_get_id_by_address(const char *address, char *userid, size_t len)
{
    uint8_t addr[DHT_ADDRESS_SIZE];
    ssize_t addr_len;
    char *ret_userid;
    size_t userid_len = CARRIER_MAX_ID_LEN + 1;

    if (len <= CARRIER_MAX_ID_LEN) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return NULL;
    }

    addr_len = base58_decode(address, strlen(address), addr, sizeof(addr));
    if (addr_len != DHT_ADDRESS_SIZE) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return NULL;
    }

    memset(userid, 0, len);
    ret_userid = base58_encode(addr, DHT_PUBLIC_KEY_SIZE, userid, &userid_len);
    if (ret_userid == NULL) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return NULL;
    }

    return ret_userid;
}

void carrier_log_init(CarrierLogLevel level, const char *log_file,
                  void (*log_printer)(const char *format, va_list args))
{
#if !defined(__ANDROID__)
    vlog_init(level, log_file, log_printer);
#endif
}

static
int get_friend_number(Carrier *w, const char *friendid, uint32_t *friend_number)
{
    uint8_t pk[DHT_PUBLIC_KEY_SIZE];
    ssize_t len;
    int rc;

    assert(w);
    assert(friendid);
    assert(friend_number);

    len = base58_decode(friendid, strlen(friendid), pk, sizeof(pk));
    if (len != DHT_PUBLIC_KEY_SIZE) {
        vlogE("Carrier: friendid %s is not base58-encoded string", friendid);
        return CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS);
    }

    rc = dht_get_friend_number(&w->dht, pk, friend_number);
    if (rc < 0) {
        //vlogE("Carrier: friendid %s is not friend yet.", friendid);
        return CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST);
    }

    return rc;
}

static void fill_empty_user_descr(Carrier *w)
{
    Packet *cp;
    uint8_t *data;
    size_t data_len;

    assert(w);

    cp = packet_create(PACKET_TYPE_USERINFO, NULL);
    if (!cp) {
        vlogE("Carrier: Out of memory!!!");
        return;
    }

    packet_set_has_avatar(cp, false);
    packet_set_name(cp, "");
    packet_set_descr(cp, "");
    packet_set_gender(cp, "");
    packet_set_phone(cp, "");
    packet_set_email(cp, "");
    packet_set_region(cp, "");

    data = packet_encode(cp, &data_len);
    packet_free(cp);

    if (!data) {
        vlogE("Carrier: Encode user desc to packet error");
        return;
    }

    dht_self_set_desc(&w->dht, data, data_len);
    free(data);
}

static
int unpack_user_descr(const uint8_t *desc, size_t desc_len, CarrierUserInfo *info,
                     bool *changed)
{
    Packet *cp;
    const char *name;
    const char *descr;
    const char *gender;
    const char *phone;
    const char *email;
    const char *region;
    bool has_avatar;
    bool did_changed = false;

    assert(desc);
    assert(desc_len > 0);
    assert(info);

    cp = packet_decode(desc, desc_len);
    if (!cp)
        return -1;

    if (packet_get_type(cp) != PACKET_TYPE_USERINFO) {
        packet_free(cp);
        vlogE("Carrier: Unkown userinfo type (%d).", packet_get_type(cp));
        return -1;
    }

    has_avatar = packet_get_has_avatar(cp);

    name   = packet_get_name(cp)   ? packet_get_name(cp)  : "";
    descr  = packet_get_descr(cp)  ? packet_get_descr(cp) : "";
    gender = packet_get_gender(cp) ? packet_get_gender(cp) : "";
    phone  = packet_get_phone(cp)  ? packet_get_phone(cp) : "";
    email  = packet_get_email(cp)  ? packet_get_email(cp) : "";
    region = packet_get_region(cp) ? packet_get_region(cp) : "";

    if (strcmp(info->name, name)) {
        strcpy(info->name, name);
        did_changed = true;
    }

    if (strcmp(info->description, descr)) {
        strcpy(info->description, descr);
        did_changed = true;
    }

    if (strcmp(info->gender, gender)) {
        strcpy(info->gender, gender);
        did_changed = true;
    }

    if (strcmp(info->phone, phone)) {
        strcpy(info->phone, phone);
        did_changed = true;
    }

    if (strcmp(info->email, email)) {
        strcpy(info->email, email);
        did_changed = true;
    }

    if (strcmp(info->region, region)) {
        strcpy(info->region, region);
        did_changed = true;
    }

    if (info->has_avatar != has_avatar) {
        info->has_avatar = has_avatar;
        did_changed = true;
    }

    packet_free(cp);

    if (changed)
        *changed = did_changed;

    return 0;
}

static CarrierPresenceStatus normalize_presence_status(int user_status)
{
    if (user_status <= CarrierPresenceStatus_None)
        return CarrierPresenceStatus_None;
    if (user_status >= CarrierPresenceStatus_Busy)
        return CarrierPresenceStatus_Busy;

    return (CarrierPresenceStatus)user_status;
}

static void get_self_info_cb(const uint8_t *address, const uint8_t *public_key,
                             int user_status,
                             const uint8_t *desc, size_t desc_len,
                             void *context)
{
    Carrier *w = (Carrier *)context;
    CarrierUserInfo *ui = &w->me;
    size_t text_len;
    char dht_name[CARRIER_MAX_USER_NAME_LEN + 1];
    int name_len;

    memcpy(w->address, address, DHT_ADDRESS_SIZE);
    memcpy(w->public_key, public_key, DHT_PUBLIC_KEY_SIZE);

    text_len = sizeof(w->base58_addr);
    base58_encode(address, DHT_ADDRESS_SIZE, w->base58_addr, &text_len);
    text_len = sizeof(ui->userid);
    base58_encode(public_key, DHT_PUBLIC_KEY_SIZE, ui->userid, &text_len);

    w->presence_status = normalize_presence_status(user_status);

    if (desc_len > 0)
        unpack_user_descr(desc, desc_len, ui, NULL);
    else
        fill_empty_user_descr(w);

    name_len = dht_self_get_name(&w->dht, (uint8_t *)dht_name,
                                 sizeof(dht_name));
    if (name_len < 0)
        return;

    if ((name_len <= 1 && !*w->me.name) ||
        (name_len > 1 && !strcmp(dht_name, w->me.name)))
        return;

    dht_self_set_name(&w->dht, (uint8_t *)w->me.name, strlen(w->me.name) + 1);
}

static bool friends_iterate_cb(uint32_t friend_number,
                               const uint8_t *public_key,
                               int user_status,
                               const uint8_t *descr, size_t descr_len,
                               void *context)
{
    Carrier  *w = (Carrier *)context;
    FriendInfo  *fi;
    CarrierUserInfo *ui;
    size_t _len = sizeof(ui->userid);
    int rc;

    assert(friend_number != UINT32_MAX);

    fi = (FriendInfo *)rc_zalloc(sizeof(FriendInfo), NULL);
    if (!fi)
        return false;

    ui = &fi->info.user_info;
    base58_encode(public_key, DHT_PUBLIC_KEY_SIZE, ui->userid, &_len);

    if (descr_len > 0)
        rc = unpack_user_descr(descr, descr_len, ui, NULL);
    else
        rc = 0;

    if (rc < 0) {
        deref(fi);
        return false;
    }

    fi->info.status = CarrierConnectionStatus_Disconnected;
    fi->info.presence = normalize_presence_status(user_status);
    fi->friend_number = friend_number;

    // Label will be synched later from data file.

    friends_put(w->friends, fi);
    deref(fi);

    return true;
}

static const uint32_t PERSISTENCE_MAGIC = 0x0E0C0D0A;
static const uint32_t PERSISTENCE_REVISION = 2;

static const char *data_filename = "carrier.data";
static const char *old_dhtdata_filename = "dhtdata";
static const char *old_eladata_filename = "eladata";

#define MAX_PERSISTENCE_SECTION_SIZE        (16 * 1024 *1024)

#define ROUND256(s)     (((((s) + 64) >> 8) + 1) << 8)

typedef struct persistence_data {
    size_t dht_savedata_len;
    const uint8_t *dht_savedata;
    size_t extra_savedata_len;
    const uint8_t *extra_savedata;
} persistence_data;

static int convert_old_dhtdata(const char *data_location)
{
    uint8_t *buf;
    uint8_t *pos;
    char *dhtdata_filename;
    char *eladata_filename;
    char *journal_filename;
    char *filename;
    struct stat st;
    uint32_t val;
    int fd;

    size_t dht_data_len;
    size_t extra_data_len;
    size_t total_len;

    assert(data_location);

    dhtdata_filename = (char *)alloca(strlen(data_location) + strlen(old_dhtdata_filename) + 4);
    sprintf(dhtdata_filename, "%s/%s", data_location, old_dhtdata_filename);
    eladata_filename = (char *)alloca(strlen(data_location) + strlen(old_eladata_filename) + 4);
    sprintf(eladata_filename, "%s/%s", data_location, old_eladata_filename);

    if (stat(dhtdata_filename, &st) < 0)
        return CARRIER_SYS_ERROR(errno);

    dht_data_len = st.st_size;

    if (stat(eladata_filename, &st) < 0 ||
            st.st_size < (PUBLIC_KEY_BYTES + sizeof(uint32_t)))
        extra_data_len = 0;
    else
        extra_data_len = (st.st_size - PUBLIC_KEY_BYTES - sizeof(uint32_t));

    total_len = 256 + ROUND256(dht_data_len) + ROUND256(extra_data_len);
    buf = (uint8_t *)calloc(total_len, 1);
    if (!buf)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    pos = buf + 256;

    fd = open(dhtdata_filename, O_RDONLY | O_BINARY);
    if (fd < 0) {
        free(buf);
        return CARRIER_SYS_ERROR(errno);
    }

    if (read(fd, pos, dht_data_len) != dht_data_len) {
        free(buf);
        close(fd);
        return CARRIER_SYS_ERROR(errno);
    }

    close(fd);

    if (extra_data_len) {
        pos += ROUND256(dht_data_len);

        fd = open(eladata_filename, O_RDONLY | O_BINARY);
        if (fd < 0) {
            extra_data_len = 0;
            goto write_data;
        }

        // Skip public key
        lseek(fd, PUBLIC_KEY_BYTES, SEEK_SET);
        // read friends count
        if (read(fd, &val, sizeof(val)) != sizeof(val)) {
            close(fd);
            extra_data_len = 0;
            goto write_data;
        }

        if (val > 0) {
            if (read(fd, pos, extra_data_len) != extra_data_len) {
                close(fd);
                memset(pos, 0, extra_data_len);
                extra_data_len = 0;
                goto write_data;
            }

            uint8_t *rptr = pos;
            uint8_t *wptr = pos;
            uint32_t i;

            for (i = 0; i < val; i++) {
                uint32_t id = *(uint32_t *)rptr;
                rptr += sizeof(uint32_t);
                size_t label_len = strlen((const char *)rptr);
                if (label_len == 0) {
                    rptr++;
                    continue;
                }

                id = htonl(id);
                memcpy(wptr, &id, sizeof(id));
                wptr += sizeof(uint32_t);
                memmove(wptr, rptr, label_len + 1);
                wptr += (label_len + 1);
                rptr += (label_len + 1);
            }

            extra_data_len = wptr - pos;
            memset(wptr, 0, rptr - wptr);
        }

        close(fd);
    }

write_data:

    total_len = 256 + ROUND256(dht_data_len) + ROUND256(extra_data_len);

    pos = buf;
    val = htonl(PERSISTENCE_MAGIC);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl(PERSISTENCE_REVISION);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl((uint32_t)dht_data_len);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl((uint32_t)extra_data_len);
    memcpy(pos, &val, sizeof(uint32_t));

    pos = buf + 256;
    sha256(pos, total_len - 256, buf + (sizeof(uint32_t) * 4), SHA256_BYTES);

    filename = (char *)alloca(strlen(data_location) + strlen(data_filename) + 4);
    sprintf(filename, "%s/%s", data_location, data_filename);
    journal_filename = (char *)alloca(strlen(data_location) + strlen(data_filename) + 16);
    sprintf(journal_filename, "%s/%s.journal", data_location, data_filename);

    fd = open(journal_filename, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        free(buf);
        return CARRIER_SYS_ERROR(errno);
    }

    if (write(fd, buf, total_len) != total_len) {
        close(fd);
        remove(journal_filename);
        return CARRIER_SYS_ERROR(errno);
    }

    if (fsync(fd) < 0) {
        close(fd);
        remove(journal_filename);
        return CARRIER_SYS_ERROR(errno);
    }

    close(fd);
    free(buf);

    remove(dhtdata_filename);
    remove(eladata_filename);
    remove(filename);
    rename(journal_filename, filename);

    return 0;
}

#define DATA_LOADED (0)
#define NO_DATA_LOADED (-1)
#define DATA_LOAD_FAILED (-2)
static int _load_persistence_data_i(const char *filename, persistence_data *data)
{
    struct stat st;
    uint32_t val;
    size_t dht_data_len;
    size_t extra_data_len;
    unsigned char p_sum[SHA256_BYTES];
    unsigned char c_sum[SHA256_BYTES];
    int fd;
    uint8_t *buf;

    assert(!access(filename, R_OK | W_OK));

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0) {
        vlogE("Loading persistence data failed, cannot open file.");
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        return DATA_LOAD_FAILED;
    }

    if (fstat(fd, &st) < 0) {
        vlogW("Load persistence data failed, stat files error(%d).", errno);
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        close(fd);
        return DATA_LOAD_FAILED;
    }

    if (st.st_size < 256) {
        vlogW("Load persistence data failed, corrupt file.");
        close(fd);
        return NO_DATA_LOADED;
    }

    if (read(fd, (void *)&val, sizeof(val)) != sizeof(val)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        close(fd);
        return DATA_LOAD_FAILED;
    }
    val = ntohl(val);
    if (val != PERSISTENCE_MAGIC) {
        vlogW("Load persistence data failed, corrupt file.");
        close(fd);
        return NO_DATA_LOADED;
    }

    if (read(fd, (void *)&val, sizeof(val)) != sizeof(val)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        close(fd);
        return DATA_LOAD_FAILED;
    }
    val = ntohl(val);
    if (val != PERSISTENCE_REVISION) {
        vlogW("Load persistence data failed, unsupported date file version.");
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_BAD_PERSISTENT_DATA));
        close(fd);
        return DATA_LOAD_FAILED;
    }

    if (read(fd, (void *)&val, sizeof(val)) != sizeof(val)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        close(fd);
        return DATA_LOAD_FAILED;
    }
    dht_data_len = ntohl(val);
    if (dht_data_len > MAX_PERSISTENCE_SECTION_SIZE) {
        vlogW("Load persistence data failed, corrupt file.");
        close(fd);
        return NO_DATA_LOADED;
    }

    if (read(fd, (void *)&val, sizeof(val)) != sizeof(val)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        close(fd);
        return DATA_LOAD_FAILED;
    }
    extra_data_len = ntohl(val);
    if (extra_data_len > MAX_PERSISTENCE_SECTION_SIZE) {
        vlogW("Load persistence data failed, corrupt file.");
        close(fd);
        return NO_DATA_LOADED;
    }

    if (st.st_size != 256 + ROUND256(dht_data_len) + ROUND256(extra_data_len)) {
        vlogW("Load persistence data failed, corrupt file.");
        close(fd);
        return NO_DATA_LOADED;
    }

    if (read(fd, p_sum, sizeof(p_sum)) != sizeof(p_sum)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        close(fd);
        return DATA_LOAD_FAILED;
    }

    buf = (uint8_t *)malloc(st.st_size - 256);
    if (!buf) {
        vlogW("Load persistence data failed, out of memory.");
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        close(fd);
        return DATA_LOAD_FAILED;
    }

    lseek(fd, 256, SEEK_SET);
    if (read(fd, buf, st.st_size - 256) != (st.st_size - 256)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        close(fd);
        free(buf);
        return DATA_LOAD_FAILED;
    }

    close(fd);
    sha256(buf, st.st_size - 256, c_sum, sizeof(c_sum));
    if (memcmp(p_sum, c_sum, SHA256_BYTES) != 0) {
        vlogW("Load persistence data failed, corrupt file.");
        free(buf);
        return NO_DATA_LOADED;
    }

    data->dht_savedata_len = dht_data_len;
    data->dht_savedata = (const uint8_t *)buf;
    data->extra_savedata_len = extra_data_len;
    data->extra_savedata = (const uint8_t *)buf + ROUND256(dht_data_len);

    return DATA_LOADED;
}

static int load_persistence_data(const char *data_location, persistence_data *data)
{
    char *journal_fname;
    char *data_fname;
    char *dht_fname;
    bool journal_exists;
    bool data_exists;
    bool dht_exists;
    int rc;

    assert(data_location);
    assert(data);

    if (access(data_location, R_OK | W_OK | X_OK) && errno != ENOENT) {
        vlogE("Failed to access data location.");
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        return DATA_LOAD_FAILED;
    }

    journal_fname = (char *)alloca(strlen(data_location) + strlen(data_filename) + 16);
    sprintf(journal_fname, "%s/%s.journal", data_location, data_filename);
    rc = access(journal_fname, R_OK | W_OK);
    if (rc < 0 && errno != ENOENT) {
        vlogE("Failed to access data journal.");
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        return DATA_LOAD_FAILED;
    }
    journal_exists = !rc ? true : false;

    data_fname = (char *)alloca(strlen(data_location) + strlen(data_filename) + 16);
    sprintf(data_fname, "%s/%s", data_location, data_filename);
    rc = access(data_fname, R_OK | W_OK);
    if (rc < 0 && errno != ENOENT) {
        vlogE("Failed to access data file.");
        carrier_set_error(CARRIER_SYS_ERROR(errno));
        return DATA_LOAD_FAILED;
    }
    data_exists = !rc ? true : false;

    dht_fname = (char *)alloca(strlen(data_location) + strlen(data_filename) + 16);
    sprintf(dht_fname, "%s/%s", data_location, old_dhtdata_filename);
    dht_exists = !access(dht_fname, R_OK | W_OK) ? true : false;

    // Load from journal file first.
    if (!journal_exists)
        goto load_from_data_file;

    vlogD("Try to loading persistence data from: %s.", journal_fname);

    rc = _load_persistence_data_i(journal_fname, data);
    if (rc == NO_DATA_LOADED)
        goto load_from_data_file;
    else if (rc == DATA_LOAD_FAILED)
        return DATA_LOAD_FAILED;

    remove(data_fname);
    rename(journal_fname, data_fname);

    return DATA_LOADED;

load_from_data_file:
    if (!data_exists && dht_exists) {
        vlogT("Try convert old persistence data...");
        if (convert_old_dhtdata(data_location) < 0) {
            vlogE("Convert old persistence data failed.");
            return NO_DATA_LOADED;
        }

        vlogT("Convert old persistence data to current version.");
    } else if (!data_exists)
        return NO_DATA_LOADED;

    vlogD("Try to loading persistence data from: %s.", data_fname);
    return _load_persistence_data_i(data_fname, data);
}

static void apply_extra_data(Carrier *w, const uint8_t *extra_savedata, size_t extra_savedata_len)
{
    const uint8_t *pos = extra_savedata;

    while (extra_savedata_len > 0) {
        uint32_t friend_number;
        char *label;
        size_t label_len;
        FriendInfo *fi;

        friend_number = ntohl(*(uint32_t *)pos);
        pos += sizeof(uint32_t);
        label = (char *)pos;
        label_len = strlen(label);
        pos += label_len + 1;

        if (label_len == 0)
            break;

        fi = friends_get(w->friends, friend_number);
        if (fi) {
            strcpy(fi->info.label, label);
            deref(fi);
        }

        extra_savedata_len -= (sizeof(uint32_t) + label_len + 1);
    }
}

static void free_persistence_data(persistence_data *data)
{
    if (data && data->dht_savedata)
        free((void *)data->dht_savedata);
}

static int mkdir_internal(const char *path, mode_t mode)
{
    struct stat st;
    int rc = 0;

    if (stat(path, &st) != 0) {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            rc = -1;
    } else if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        rc = -1;
    }

    return rc;
}

static int mkdirs(const char *path, mode_t mode)
{
    int rc = 0;
    char *pp;
    char *sp;
    char copypath[PATH_MAX];

    strncpy(copypath, path, sizeof(copypath));
    copypath[sizeof(copypath) - 1] = 0;

    pp = copypath;
    while (rc == 0 && (sp = strchr(pp, '/')) != 0) {
        if (sp != pp) {
            /* Neither root nor double slash in path */
            *sp = '\0';
            rc = mkdir_internal(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }

    if (rc == 0)
        rc = mkdir_internal(path, mode);

    return rc;
}

static size_t get_extra_savedata_size(Carrier *w)
{
    linked_hashtable_iterator_t it;
    size_t total_len = 0;

    assert(w);
    assert(w->friends);

    friends_iterate(w->friends, &it);
    while(friends_iterator_has_next(&it)) {
        FriendInfo *fi;

        if (friends_iterator_next(&it, &fi) == 1) {
            size_t label_len = strlen(fi->info.label);
            if (label_len)
                total_len += sizeof(uint32_t) + label_len + 1;

            deref(fi);
        }
    }

    return total_len;
}

static void get_extra_savedata(Carrier *w, void *data, size_t len)
{
    linked_hashtable_iterator_t it;
    uint8_t *pos = (uint8_t *)data;

    assert(w);
    assert(w->friends);
    assert(data);

    friends_iterate(w->friends, &it);
    while(friends_iterator_has_next(&it) && len > 0) {
        FriendInfo *fi;

        if (friends_iterator_next(&it, &fi) == 1) {
            uint32_t nid;
            size_t label_len = strlen(fi->info.label);
            if (label_len) {
                if (len < (sizeof(uint32_t) + label_len + 1))
                    break;

                nid = htonl(fi->friend_number);
                memcpy(pos, &nid, sizeof(uint32_t));
                pos += sizeof(uint32_t);
                memcpy(pos, fi->info.label, label_len + 1);
                pos += (label_len + 1);

                len -= (sizeof(uint32_t) + label_len + 1);
            }

            deref(fi);
        }
    }

    return;
}

#ifdef _MSC_VER
// For Windows socket API not compatible with POSIX: size_t vs. int
#pragma warning(push)
#pragma warning(disable: 4267)
#endif

static int store_persistence_data(Carrier *w)
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    uint8_t *buf;
    uint8_t *pos;
    char *journal_filename;
    char *filename;
    uint32_t val;
    int fd;
    int rc;

    size_t dht_data_len;
    size_t extra_data_len;
    size_t total_len;

    assert(w);

    dht_data_len = dht_get_savedata_size(&w->dht);
    extra_data_len = get_extra_savedata_size(w);
    total_len = 256 + ROUND256(dht_data_len) + ROUND256(extra_data_len);

    buf = (uint8_t *)calloc(total_len, 1);
    if (!buf)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    pos = buf;
    val = htonl(PERSISTENCE_MAGIC);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl(PERSISTENCE_REVISION);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl((uint32_t)dht_data_len);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl((uint32_t)extra_data_len);
    memcpy(pos, &val, sizeof(uint32_t));

    pos = buf + 256;
    dht_get_savedata(&w->dht, pos);
    pos += ROUND256(dht_data_len);
    get_extra_savedata(w, pos, ROUND256(extra_data_len));

    pos = buf + 256;
    sha256(pos, total_len - 256, buf + (sizeof(uint32_t) * 4), SHA256_BYTES);

    pthread_mutex_lock(&lock);

    rc = mkdirs(w->pref.data_location, S_IRWXU);
    if (rc < 0) {
        free(buf);
        pthread_mutex_unlock(&lock);
        return CARRIER_SYS_ERROR(errno);
    }

    filename = (char *)alloca(strlen(w->pref.data_location) + strlen(data_filename) + 4);
    sprintf(filename, "%s/%s", w->pref.data_location, data_filename);
    journal_filename = (char *)alloca(strlen(w->pref.data_location) + strlen(data_filename) + 16);
    sprintf(journal_filename, "%s/%s.journal", w->pref.data_location, data_filename);

    fd = open(journal_filename, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        free(buf);
        pthread_mutex_unlock(&lock);
        return CARRIER_SYS_ERROR(errno);
    }

    if (write(fd, buf, total_len) != total_len) {
        close(fd);
        remove(journal_filename);
        pthread_mutex_unlock(&lock);
        return CARRIER_SYS_ERROR(errno);
    }

    if (fsync(fd) < 0) {
        close(fd);
        remove(journal_filename);
        pthread_mutex_unlock(&lock);
        return CARRIER_SYS_ERROR(errno);
    }

    close(fd);
    free(buf);

    remove(filename);
    rename(journal_filename, filename);

    pthread_mutex_unlock(&lock);

    return 0;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

static void carrier_destroy(void *argv)
{
    Carrier *w = (Carrier *)argv;

    if (w->pref.data_location)
        free(w->pref.data_location);

    if (w->pref.bootstrap_nodes) {
        int i;

        for (i = 0; i < w->pref.bootstrap_size; i++) {
            if(w->pref.bootstrap_nodes[i].ipv4)
                free(w->pref.bootstrap_nodes[i].ipv4);
            if(w->pref.bootstrap_nodes[i].ipv6)
                free(w->pref.bootstrap_nodes[i].ipv6);
        }
        free(w->pref.bootstrap_nodes);
    }

    if (w->pref.express_nodes) {
        int i;

        for(i = 0; i < w->pref.express_size; i++) {
            if(w->pref.express_nodes[i].ipv4)
                free(w->pref.express_nodes[i].ipv4);
        }
        free(w->pref.express_nodes);
    }

    if (w->tassembly_irsps)
        deref(w->tassembly_irsps);

    if (w->tassembly_ireqs)
        deref(w->tassembly_ireqs);

    if (w->tcallbacks)
        deref(w->tcallbacks);

    if (w->bulkmsgs)
        deref(w->bulkmsgs);

    if (w->unconfirmed)
        deref(w->unconfirmed);

    if (w->thistory)
        deref(w->thistory);

    if (w->friends)
        deref(w->friends);

    if (w->friend_events)
        deref(w->friend_events);

    if (w->connector)
        deref(w->connector);

    if (w->exts)
        deref(w->exts);

    dht_kill(&w->dht);
}

static void notify_offmsg_received(Carrier *w, const char *, const uint8_t *, size_t, uint64_t);
static void notify_offreq_received(Carrier *w, const char *, const uint8_t *, size_t, uint64_t);
static void notify_offreceipt_received(Carrier *w, const char *, ExpressMessageType, uint32_t, int);
Carrier *carrier_new(const CarrierOptions *opts, CarrierCallbacks *callbacks,
                 void *context)
{
    Carrier *w;
    persistence_data data;
    int rc;
    size_t i;

    if (!opts) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return NULL;
    }

    if (!opts->persistent_location || !*opts->persistent_location) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return NULL;
    }

    carrier_log_init(opts->log_level, opts->log_file, opts->log_printer);

    w = (Carrier *)rc_zalloc(sizeof(Carrier), carrier_destroy);
    if (!w) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    w->pref.udp_enabled = opts->udp_enabled;
    w->pref.data_location = strdup(opts->persistent_location);

    w->pref.bootstrap_size = opts->bootstraps_size;
    if (w->pref.bootstrap_size > 0) {
        w->pref.bootstrap_nodes = (BootstrapNodeBuf *)calloc(1,
                            sizeof(BootstrapNodeBuf) * w->pref.bootstrap_size);
        if (!w->pref.bootstrap_nodes) {
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return NULL;
        }
    }

    for (i = 0; i < w->pref.bootstrap_size; i++) {
        BootstrapNode *b = &opts->bootstraps[i];
        BootstrapNodeBuf *bi = &w->pref.bootstrap_nodes[i];
        char *endptr = "";
        ssize_t len;

        if (!b->ipv4 && !b->ipv6) {
            vlogE("Carrier: IPv4 and IPv6 address of bootstrap node are both empty");
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
            return NULL;
        }

        if (b->ipv4) bi->ipv4 = strdup(b->ipv4);
        if (b->ipv6) bi->ipv6 = strdup(b->ipv6);

        if (!bi->ipv4 && !bi->ipv6) {
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return NULL;
        }

        bi->port = b->port ? (int)strtol(b->port, &endptr, 10) : BOOTSTRAP_DEFAULT_PORT;
        if (bi->port < 1 || bi->port > 65535 || *endptr) {
            vlogE("Carrier: Port value (%s) of bootstrap node is invalid", b->port);
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
            return NULL;
        }

        len = base58_decode(b->public_key, strlen(b->public_key), bi->public_key,
                            sizeof(bi->public_key));
        if (len != DHT_PUBLIC_KEY_SIZE) {
            vlogE("Carrier: Public key (%s) of bootstrap node is invalid", b->public_key);
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
            return NULL;
        }
    }

    w->pref.express_size = opts->express_nodes_size;
    if (w->pref.express_size > 0) {
        w->pref.express_nodes = (ExpressNodeBuf *)calloc(1,
                            sizeof(ExpressNodeBuf) * w->pref.express_size);

        if (!w->pref.express_nodes) {
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return NULL;
        }
    }

    for (i = 0; i < w->pref.express_size; i++) {
        ExpressNode *n = &opts->express_nodes[i];
        ExpressNodeBuf *ni= &w->pref.express_nodes[i];
        char *endptr = "";
        ssize_t len;

        if (!n->ipv4) {
            vlogE("Carrier: IPv4 address (%s) of express node is empty", n->ipv4);
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
            return NULL;
        }

        ni->ipv4 = strdup(n->ipv4);
        if (!ni->ipv4) {
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return NULL;
        }

        ni->port = n->port ? (int)strtol(n->port, &endptr, 10) : EXPRESS_DEFAULT_PORT;
        if (ni->port < 1 || ni->port > 65535 || *endptr) {
            vlogE("Carrier: Port value (%s) of express node is invalid", n->port);
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
            return NULL;
        }

        len = base58_decode(n->public_key, strlen(n->public_key), ni->public_key,
                            sizeof(ni->public_key));
        if (len != DHT_PUBLIC_KEY_SIZE) {
            vlogE("Carrier: Public key (%s) of express node is invalid", n->public_key);
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
            return NULL;
        }
    }

    memset(&data, 0, sizeof(data));
    rc = load_persistence_data(opts->persistent_location, &data);
    if (rc == DATA_LOAD_FAILED) {
        deref(w);
        return NULL;
    }

    if (rc == NO_DATA_LOADED && opts->secret_key)
        rc = dht_new(opts->secret_key, 32, w->pref.udp_enabled, &w->dht);
    else
        rc = dht_new(data.dht_savedata, data.dht_savedata_len, w->pref.udp_enabled, &w->dht);

    if (rc < 0) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(rc);
        return NULL;
    }

    w->friends = friends_create(31);
    if (!w->friends) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    w->friend_events = linked_list_create(1, NULL);
    if (!w->friend_events) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    w->tcallbacks = transacted_callbacks_create(31);
    if (!w->tcallbacks) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    w->thistory = transaction_history_create(31);
    if (!w->thistory) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    w->tassembly_ireqs = tassemblies_create(17);
    if (!w->tassembly_ireqs) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    w->tassembly_irsps = tassemblies_create(17);
    if (!w->tassembly_irsps) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    w->bulkmsgs = bulkmsgs_create(8);
    if (!w->bulkmsgs) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    w->unconfirmed = unconfirmed_create();
    if (!w->unconfirmed) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    w->exts = extensions_create(8);
    if (!w->exts) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return NULL;
    }

    rc = dht_get_self_info(&w->dht, get_self_info_cb, w);
    if (rc < 0) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(rc);
        return NULL;
    }

    rc = dht_get_friends(&w->dht, friends_iterate_cb, w);
    if (rc < 0) {
        free_persistence_data(&data);
        deref(w);
        carrier_set_error(rc);
        return NULL;
    }

    if (w->pref.express_size) {
        w->connector = express_connector_create(w, notify_offmsg_received,
                                                notify_offreq_received,
                                                notify_offreceipt_received);
        if (!w->connector) {
            vlogE("Carrier: Creating express connector error (%x)", carrier_get_error());
            free_persistence_data(&data);
            deref(w);
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return NULL;
        }
    }

    apply_extra_data(w, data.extra_savedata, data.extra_savedata_len);
    free_persistence_data(&data);

    store_persistence_data(w);

    srand((unsigned int)time(NULL));

    if (callbacks) {
        w->callbacks = *callbacks;
        w->context = context;
    }

    vlogI("Carrier: Carrier instance created");

    return w;
}

void carrier_kill(Carrier *w)
{
    if (!w) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return;
    }

    if (w->connector)
        express_connector_kill(w->connector);

    if (w->running) {
        w->quit = 1;

        if (!pthread_equal(pthread_self(), w->main_thread))
            while(!w->quit) usleep(5000);
    }

    deref(w);
    vlogI("Carrier: Carrier node killed.");
}

static void notify_idle(Carrier *w)
{
    if (w->callbacks.idle)
        w->callbacks.idle(w, w->context);
}

static void notify_friends(Carrier *w)
{
    linked_hashtable_iterator_t it;

    friends_iterate(w->friends, &it);
    while(friends_iterator_has_next(&it)) {
        FriendInfo *fi;

        if (friends_iterator_next(&it, &fi) != 1) // end of interation.
            break;

        if (w->callbacks.friend_list) {
            CarrierFriendInfo _fi;

            memcpy(&_fi, &fi->info, sizeof(CarrierFriendInfo));
            w->callbacks.friend_list(w, &_fi, w->context);
        }

        deref(fi);
    }

    if (w->callbacks.friend_list)
        w->callbacks.friend_list(w, NULL, w->context);
}

static void notify_connection_cb(bool connected, void *context)
{
    Carrier *w = (Carrier *)context;

    if (!w->is_ready && connected) {
        w->is_ready = true;
        if (w->callbacks.ready)
            w->callbacks.ready(w, w->context);
    }

    w->connection_status = connection_status(connected);
    if (w->callbacks.connection_status)
        w->callbacks.connection_status(w, w->connection_status, w->context);

    if (w->connector && connected)
        express_enqueue_pull_messages(w->connector);
}

static
void notify_friend_description_cb(uint32_t friend_number, const uint8_t *descr,
                                  size_t length, void *context)
{
    Carrier *w = (Carrier *)context;
    FriendInfo *fi;
    bool changed = false;
    CarrierFriendInfo _fi;

    assert(friend_number != UINT32_MAX);
    assert(descr);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogW("Carrier: Unknown friend number %u, friend description message "
              "dropped.", friend_number);
        return;
    }

    if (length == 0) {
        vlogW("Carrier: Empty description message from friend "
              "number %u, dropped.", friend_number);
        deref(fi);
        return;
    }

    unpack_user_descr(descr, length, &fi->info.user_info, &changed);
    if (!changed) {
        deref(fi);
        return;
    }

    memcpy(&_fi, &fi->info, sizeof(_fi));
    if (w->callbacks.friend_info)
        w->callbacks.friend_info(w, _fi.user_info.userid, &_fi, w->context);

    deref(fi);
}

static void parse_address(const char *addr, char **uid, char **ext);
static int send_express_message(Carrier *w, const char *userid,
                                uint32_t msgid, const void *msg, size_t len,
                                const char *ext_name);
static void notify_friend_connection(Carrier *w, const char *friendid,
                                     CarrierConnectionStatus status)
{
    linked_hashtable_iterator_t it;

    assert(w);
    assert(friendid);

    if (w->callbacks.friend_connection)
        w->callbacks.friend_connection(w, friendid, status, w->context);

    if (status == CarrierConnectionStatus_Connected)
        return;

redo_check:
    unconfirmed_iterate(w->unconfirmed, &it);
    while (unconfirmed_iterator_has_next(&it)) {
        UnconfirmedMsg *item;
        CarrierReceiptState state;
        char *userid;
        char *ext_name;
        char *addr;
        int rc;

        rc = unconfirmed_iterator_next(&it, &item);
        if (rc == 0)
            break;
        else if (rc == -1)
            goto redo_check;

        addr = (char *)alloca(strlen(item->to) + 1);
        strcpy(addr, item->to);
        parse_address(addr, &userid, &ext_name);

        if (strcmp(friendid, userid) || item->offline_sending) {
            deref(item);
            continue;
        }

        vlogI("Carrier: Friend %s went offline, resend message as offline sending", userid);

        rc = w->connector ? send_express_message(w, userid, item->msgid,
                                                 item->data, item->size, ext_name) : -1;
        if (rc < 0) {
            unconfirmed_iterator_remove(&it);
            if (item->callback)
                item->callback(item->msgid, CarrierReceipt_Error, item->context);
            deref(item);
            continue;
        }

        item->offline_sending = true;
        deref(item);
    }
}

static void trigger_pull_offmsg_instantly(Carrier *w)
{
    struct timeval expireat;
    struct timeval interval;
    /*
     * - when the status of friend connection changes, it would trigger
     *   to pull offmsg in short interval (2m) for just once.
     * - In general, it would trigger to pull offmsg in genral interval(5m)
     */

    gettimeofday(&expireat, NULL);

    interval.tv_sec  = PULLMSG_INSTANT_INTERVAL;
    interval.tv_usec = 0;
    timeradd(&expireat, &interval, &expireat);

    if (timercmp(&expireat, &w->express_expiretime, <))
        w->express_expiretime = expireat;
}

static
void notify_friend_connection_cb(uint32_t friend_number, bool connected,
                                 void *context)
{
    Carrier *w = (Carrier *)context;
    CarrierConnectionStatus status;
    FriendInfo *fi;

    struct timeval expireat;
    struct timeval interval;

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogW("Carrier: Unknown friend number %u, connection status message "
              "dropped (%s).", friend_number, connected ? "true":"false");
        return;
    }

    status = connection_status(connected);
    if (status != fi->info.status) {
        char friendid[CARRIER_MAX_ID_LEN + 1];

        fi->info.status = status;
        strcpy(friendid, fi->info.user_info.userid);

        notify_friend_connection(w, friendid, status);
    }

    deref(fi);
    trigger_pull_offmsg_instantly(w);
}

static void notify_friend_presence(Carrier *w, const char *friendid,
                                   CarrierPresenceStatus presence)
{
    assert(w);
    assert(friendid);

    if (w->callbacks.friend_presence)
        w->callbacks.friend_presence(w, friendid, presence, w->context);
}

static
void notify_friend_status_cb(uint32_t friend_number, int status,
                             void *context)
{
    Carrier *w = (Carrier *)context;
    FriendInfo *fi;

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogW("Carrier: Unknown friend number (%u), friend presence message "
              "dropped.", friend_number);
        return;
    }

    if (status < CarrierPresenceStatus_None ||
        status > CarrierPresenceStatus_Busy) {
        vlogW("Carrier: Invalid friend status %d received, dropped it.", status);
        return;
    }

    if (status != fi->info.presence) {
        char friendid[CARRIER_MAX_ID_LEN + 1];

        fi->info.presence = status;
        strcpy(friendid, fi->info.user_info.userid);

        notify_friend_presence(w, friendid, status);
    }

    deref(fi);
}

static
void notify_friend_request_cb(const uint8_t *public_key, const uint8_t* greeting,
                              size_t length, void *context)
{
    Carrier *w = (Carrier *)context;
    uint32_t friend_number;
    Packet* cp;
    CarrierUserInfo ui;
    size_t _len = sizeof(ui.userid);
    const char *name;
    const char *desc;
    const char *hello;
    int rc;

    assert(public_key);
    assert(greeting);
    assert(length > 0);

    rc = dht_get_friend_number(&w->dht, public_key, &friend_number);
    if (rc == 0 && friend_number != UINT32_MAX) {
        vlogW("Carrier: friend already exist, dropped friend request.");
        return;
    }

    cp = packet_decode(greeting, length);
    if (!cp) {
        vlogE("Carrier: Inavlid friend request, dropped this request.");
        return;
    }

    if (packet_get_type(cp) != PACKET_TYPE_FRIEND_REQUEST) {
        vlogE("Carrier: Invalid friend request, dropped this request.");
        packet_free(cp);
        return;
    }

    memset(&ui, 0, sizeof(ui));
    base58_encode(public_key, DHT_PUBLIC_KEY_SIZE, ui.userid, &_len);

    name  = packet_get_name(cp)  ? packet_get_name(cp)  : "";
    desc  = packet_get_descr(cp) ? packet_get_descr(cp) : "";
    hello = packet_get_hello(cp) ? packet_get_hello(cp) : "";

    assert(strlen(name) < sizeof(ui.name));
    assert(strlen(desc) < sizeof(ui.description));

    strcpy(ui.name, name);
    strcpy(ui.description, desc);

    if (w->callbacks.friend_request)
        w->callbacks.friend_request(w, ui.userid, &ui, hello, w->context);

    packet_free(cp);
}

static void handle_add_friend_cb(EventBase *event, Carrier *w)
{
    FriendEvent *ev = (FriendEvent *)event;

    if (w->callbacks.friend_added)
        w->callbacks.friend_added(w, &ev->fi, w->context);
}

static void handle_remove_friend_cb(EventBase *event, Carrier *w)
{
    FriendEvent *ev = (FriendEvent *)event;
    linked_hashtable_iterator_t it;

    if (ev->fi.status == CarrierConnectionStatus_Connected &&
        w->callbacks.friend_connection)
        w->callbacks.friend_connection(w, ev->fi.user_info.userid,
                                       CarrierConnectionStatus_Disconnected,
                                       w->context);

    if (w->callbacks.friend_removed)
        w->callbacks.friend_removed(w, ev->fi.user_info.userid, w->context);

redo_check:
    unconfirmed_iterate(w->unconfirmed, &it);
    while (unconfirmed_iterator_has_next(&it)) {
        UnconfirmedMsg *item;
        CarrierReceiptState state;
        char *userid;
        char *ext_name;
        char *addr;
        int rc;

        rc = unconfirmed_iterator_next(&it, &item);
        if (rc == 0)
            break;
        else if (rc == -1)
            goto redo_check;

        addr = (char *)alloca(strlen(item->to) + 1);
        strcpy(addr, item->to);
        parse_address(addr, &userid, &ext_name);

        if (strcmp(ev->fi.user_info.userid, userid)) {
            deref(item);
            continue;
        }

        unconfirmed_iterator_remove(&it);

        if (item->callback)
            item->callback(item->msgid, CarrierReceipt_Error, item->context);
        deref(item);
    }
}

static void notify_friend_changed(Carrier *w, CarrierFriendInfo *fi,
                                  void (*cb)(EventBase *, Carrier *))
{
    FriendEvent *event;

    assert(w);
    assert(fi);

    store_persistence_data(w);

    event = (FriendEvent *)rc_alloc(sizeof(FriendEvent), NULL);
    if (event) {
        memcpy(&event->fi, fi, sizeof(*fi));
        event->base.le.data = event;
        event->base.handle  = cb;
        linked_list_push_tail(w->friend_events, &event->base.le);
        deref(event);
    }
}

static void do_friend_events(Carrier *w)
{
    linked_list_t *events = w->friend_events;
    linked_list_iterator_t it;

redo_events:
    linked_list_iterate(events, &it);
    while (linked_list_iterator_has_next(&it)) {
        EventBase *event;
        int rc;

        rc = linked_list_iterator_next(&it, (void **)&event);
        if (rc == 0)
            break;

        if (rc == -1)
            goto redo_events;

        event->handle(event, w);
        linked_list_iterator_remove(&it);

        deref(event);
    }
}

static void do_tassemblies_expire(linked_hashtable_t *tassemblies)
{
    linked_hashtable_iterator_t it;
    struct timeval now;

    gettimeofday(&now, NULL);

redo_expire:
    tassemblies_iterate(tassemblies, &it);
    while(tassemblies_iterator_has_next(&it)) {
        TransactedAssembly *item;
        int rc;

        rc = tassemblies_iterator_next(&it, &item);
        if (rc == 0)
            break;

        if (rc == -1)
            goto redo_expire;

        if (timercmp(&now, &item->expire_time, >))
            tassemblies_iterator_remove(&it);

        deref(item);
    }
}

static
void transacted_callback_expire(Carrier *w, TransactedCallback *callback)
{
    char friendid[CARRIER_MAX_ID_LEN + 1];
    CarrierFriendInviteResponseCallback *callback_func;
    FriendInfo *fi;

    fi = friends_get(w->friends, callback->friend_number);
    if (!fi) {
        vlogW("Carrier: Unknown friend number (%u), friend presence message "
              "dropped.", callback->friend_number);
        return;
    }

    strcpy(friendid, fi->info.user_info.userid);
    deref(fi);

    callback_func = (CarrierFriendInviteResponseCallback *)callback->callback_func;
    assert(callback_func);

    callback_func(w, friendid, callback->bundle, CARRIER_STATUS_TIMEOUT, "timeout",
                  NULL, 0, callback->callback_context);
}

static void do_transacted_callabcks_expire(Carrier *w)
{
    linked_hashtable_iterator_t it;
    struct timeval now;

    gettimeofday(&now, NULL);

redo_expire:
    transacted_callbacks_iterate(w->tcallbacks, &it);
    while(transacted_callbacks_iterator_has_next(&it)) {
        TransactedCallback *tcb;
        int rc;

        rc = transacted_callbacks_iterator_next(&it, &tcb);
        if (rc == 0)
            break;

        if (rc == -1)
            goto redo_expire;

        if (timercmp(&now, &tcb->expire_time, >)) {
            linked_hashtable_iterator_remove(&it);
            transacted_callback_expire(w, tcb);
        }

        deref(tcb);
    }
}

static void do_bulkmsgs_expire(linked_hashtable_t *bulkmsgs)
{
    linked_hashtable_iterator_t it;
    struct timeval now;

    gettimeofday(&now, NULL);


redo_exipre:
    bulkmsgs_iterate(bulkmsgs, &it);
    while (bulkmsgs_iterator_has_next(&it)) {
        BulkMsg *item;
        int rc;

        rc = bulkmsgs_iterator_next(&it, &item);
        if (rc == 0)
            break;

        if (rc == -1)
            goto redo_exipre;

        if (timercmp(&now, &item->expire_time, >))
            bulkmsgs_iterator_remove(&it);

        deref(item);
    }
}

static void do_express_expire(Carrier *w)
{
    struct timeval timeout;
    struct timeval now;

    if (!w->connector)
        return;

    gettimeofday(&now, NULL);
    if (timercmp(&now, &w->express_expiretime, <=))
        return;

    express_enqueue_pull_messages(w->connector);

    timeout.tv_sec  = PULLMSG_REGULAR_INTERVAL;
    timeout.tv_usec = 0;
    timeradd(&now, &timeout, &w->express_expiretime);
}


static inline int64_t current_timestamp(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    return now.tv_sec * (int64_t)1000000 + now.tv_usec;
}

static
void handle_friend_message(Carrier *w, uint32_t friend_number, Packet *cp)
{
    FriendInfo *fi;
    char friendid[CARRIER_MAX_ID_LEN + 1];
    const char *name;
    const void *msg;
    size_t len;

    assert(w);
    assert(cp);
    assert(friend_number != UINT32_MAX);
    assert(packet_get_type(cp) == PACKET_TYPE_MESSAGE);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogW("Carrier: Unknown friend number %u, friend message dropped.",
              friend_number);
        return;
    }

    strcpy(friendid, fi->info.user_info.userid);
    deref(fi);

    name = packet_get_extension(cp);
    msg  = packet_get_raw_data(cp);
    len  = packet_get_raw_data_length(cp);

    if (name && *name) {
        ExtensionHolder *ext;

        ext = extensions_get(w->exts, name);
        if (ext) {
            if (ext->callbacks.friend_message)
                ext->callbacks.friend_message(w, friendid, msg, len, current_timestamp(),
                                              false, ext->ext);
            deref(ext);
        }
    } else if (w->callbacks.friend_message) {
        w->callbacks.friend_message(w, friendid, msg, len, current_timestamp(), false,
                                    w->context);
    }
}

static
void handle_friend_bulkmsg(Carrier *w, uint32_t friend_number, Packet *cp)
{
    FriendInfo *fi;
    char friendid[CARRIER_MAX_ID_LEN + 1];
    BulkMsg *msg;
    const char *name;
    const void *data;
    int64_t tid;
    size_t len;
    size_t totalsz;
    bool need_add = false;

    assert(w);
    assert(friend_number != UINT32_MAX);
    assert(cp);
    assert(packet_get_type(cp) == PACKET_TYPE_BULKMSG);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %u, friend message dropped.",
              friend_number);
        return;
    }

    strcpy(friendid, fi->info.user_info.userid);
    deref(fi);

    name = packet_get_extension(cp);
    data = packet_get_raw_data(cp);
    len  = packet_get_raw_data_length(cp);
    tid  = packet_get_tid(cp);
    totalsz = packet_get_totalsz(cp);

    msg = bulkmsgs_get(w->bulkmsgs, &tid);
    if (!msg) {
        if (!totalsz || totalsz > CARRIER_MAX_APP_BULKMSG_LEN) {
            vlogW("Carrier: Received bulk message with invalid totalsz %z,"
                  "dropped.", totalsz);
            return;
        }

        msg = (BulkMsg *)rc_zalloc(sizeof(*msg) + totalsz, NULL);
        if (!msg)
            return;

        strcpy(msg->ext, name ? name : "");
        strcpy(msg->friendid, friendid);

        msg->tid = tid;
        msg->data_cap = totalsz;
        msg->data_offset = 0;
        msg->data = (uint8_t*)(msg + 1);

        gettimeofday_elapsed(&msg->expire_time, TASSEMBLY_TIMEOUT);
        need_add = true;  //Ready to put into bulkmsgs hashtable.
    }

    if ((name && strcmp(msg->ext, name)) ||
        strcmp(msg->friendid, friendid) || !len || len > CARRIER_MAX_APP_MESSAGE_LEN ||
        msg->data_offset + len < len || msg->data_offset + len > msg->data_cap) {
        vlogE("Carrier: Inavlid bulkmsg fragment (or HACKED), dropped.");
        deref(msg);
        return;
    }

    memcpy(msg->data + msg->data_offset, data, len);
    msg->data_offset += len;

    if (msg->data_offset == msg->data_cap) {
        struct timeval now;
        gettimeofday(&now, NULL);
        int64_t timestamp = now.tv_sec * (int64_t)1000000 + now.tv_usec;

        if (name && *name) {
            ExtensionHolder *ext;

            ext = extensions_get(w->exts, name);
            if (ext) {
                if (ext->callbacks.friend_message)
                    ext->callbacks.friend_message(w, friendid, msg->data, msg->data_cap, timestamp, false, ext->ext);
                deref(ext);
            }
        } else {

            w->callbacks.friend_message(w, friendid, msg->data, msg->data_cap, timestamp, false, w->context);
        }

        if (!need_add)
            bulkmsgs_remove(w->bulkmsgs, &tid);
        else
            need_add = false;
    }

    if (need_add)
        bulkmsgs_put(w->bulkmsgs, msg);
    deref(msg);
}

static
void handle_invite_request(Carrier *w, uint32_t friend_number, Packet *cp)
{
    FriendInfo *fi;
    char friendid[CARRIER_MAX_ID_LEN + 1];
    const char *name;
    const void *data;
    const char *bundle;
    size_t bundle_len;
    size_t len;
    int64_t tid;
    size_t totalsz;
    bool need_add = false;
    char from[CARRIER_MAX_ID_LEN + CARRIER_MAX_EXTENSION_NAME_LEN + 4];
    TransactedAssembly *ireq = NULL;

    assert(w);
    assert(friend_number != UINT32_MAX);
    assert(cp);
    assert(packet_get_type(cp) == PACKET_TYPE_INVITE_REQUEST);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %u, invite request dropped.",
              friend_number);
        return;
    }

    strcpy(friendid, fi->info.user_info.userid);
    deref(fi);

    bundle = packet_get_bundle(cp);
    bundle_len = bundle ? strlen(bundle) + 1 : 0;
    name = packet_get_extension(cp);
    data = packet_get_raw_data(cp);
    len  = packet_get_raw_data_length(cp);
    tid  = packet_get_tid(cp);
    totalsz = packet_get_totalsz(cp);

    ireq = tassemblies_get(w->tassembly_ireqs, &tid);
    if (!ireq) {
        if (!totalsz || totalsz > CARRIER_MAX_INVITE_DATA_LEN) {
            vlogW("Carrier: Received invite request fragment with invalid "
                  "totalsz %z, dropped.", totalsz);
            return;
        }

        ireq = (TransactedAssembly *)rc_zalloc(sizeof(*ireq) + totalsz + bundle_len, NULL);
        if (!ireq) {
            vlogW("Carrier: Out of memory, invite request fragment dropped.");
            return;
        }

        strcpy(ireq->ext, name ? name : "");
        strcpy(ireq->friendid, friendid);
        ireq->tid = tid;
        ireq->data_len = totalsz;
        ireq->data_off = 0;
        ireq->data = (uint8_t*)(ireq + 1);
        if (bundle_len > 0) {
            ireq->bundle = (char *)(ireq->data + totalsz);
            strcpy(ireq->bundle, bundle);
        } else {
            ireq->bundle = NULL;
        }

        gettimeofday_elapsed(&ireq->expire_time, TASSEMBLY_TIMEOUT);
        need_add = true;  //Ready to put into tassembly hashtable.
    }

    if ((name && strcmp(ireq->ext, name)) ||
        strcmp(ireq->friendid, friendid) || !len || len > INVITE_DATA_UNIT ||
        ireq->data_off + len < len || ireq->data_off + len > ireq->data_len) {
        vlogE("Carrier: Inavlid invite request fragment (or HACKED), dropped.");
        deref(ireq);
        return;
    }

    memcpy(ireq->data + ireq->data_off, data, len);
    ireq->data_off += len;

    if (ireq->data_off == ireq->data_len) {
        strcpy(from, friendid);
        if (name) {
            strcat(from, ":");
            strcat(from, name);
        }
        transaction_history_put_invite(w->thistory, from, tid);

        if (name) {
            ExtensionHolder *ext;

            ext = extensions_get(w->exts, name);
            if (ext) {
                if (ext->callbacks.friend_invite)
                    ext->callbacks.friend_invite(w, friendid, ireq->bundle,
                                                 (const void *)ireq->data,
                                                 ireq->data_len, ext->ext);
                deref(ext);
            }
        } else {
            if (w->callbacks.friend_invite)
                w->callbacks.friend_invite(w, friendid, ireq->bundle,
                                           (const void *)ireq->data,
                                           ireq->data_len, w->context);
        }

        if (!need_add)
            tassemblies_remove(w->tassembly_ireqs, &tid);
        else
            need_add = false;
    }

    if (need_add)
        tassemblies_put(w->tassembly_ireqs, ireq);
    deref(ireq);
}

static
void handle_invite_response(Carrier *w, uint32_t friend_number, Packet *cp)
{
    FriendInfo *fi;
    char friendid[CARRIER_MAX_ID_LEN + 1];
    TransactedCallback *tcb;
    CarrierFriendInviteResponseCallback *callback_func;
    void *callback_ctxt;
    int64_t tid;
    size_t totalsz;
    int status;
    const char *bundle;
    const char *name;
    const void *data = NULL;
    const char *reason = NULL;
    size_t bundle_len;
    size_t reason_len = 0;
    size_t data_len = 0;
    bool need_add = false;
    TransactedAssembly *irsp = NULL;

    assert(w);
    assert(friend_number != UINT32_MAX);
    assert(cp);
    assert(packet_get_type(cp) == PACKET_TYPE_INVITE_RESPONSE);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %u, invite response dropped.",
              friend_number);
        return;
    }

    strcpy(friendid, fi->info.user_info.userid);
    deref(fi);

    tid = packet_get_tid(cp);
    tcb = transacted_callbacks_get(w->tcallbacks, tid);
    if (!tcb) {
        vlogE("Carrier: No transaction to handle invite response.");
        return;
    }

    bundle = packet_get_bundle(cp);
    bundle_len = bundle ? strlen(bundle) + 1 : 0;
    name = packet_get_extension(cp);
    totalsz = packet_get_totalsz(cp);
    status = packet_get_status(cp);
    if (status) {
        reason = packet_get_reason(cp);
        reason_len = strlen(reason) + 1;
    } else {
        data = packet_get_raw_data(cp);
        data_len = packet_get_raw_data_length(cp);
    }

    irsp = tassemblies_get(w->tassembly_irsps, &tid);
    if (!irsp) {
        if (totalsz > CARRIER_MAX_INVITE_DATA_LEN) {
            vlogW("Carrier: Received overlong invite request fragment, "
                  "dropped.");
            deref(tcb);
            return;
        }

        irsp = (TransactedAssembly *)rc_zalloc(sizeof(*irsp) + totalsz +
                                            + bundle_len + reason_len, NULL);
        if (!irsp) {
            vlogW("Carrier: Out of memory, invite response fragment dropped.");
            deref(tcb);
            return;
        }

        strcpy(irsp->ext, name ? name : "");
        strcpy(irsp->friendid, friendid);
        irsp->tid = tid;
        irsp->data_len = totalsz;
        irsp->data_off = 0;
        irsp->data = totalsz ? (uint8_t *)(irsp + 1) : NULL;

        if (bundle_len > 0) {
            irsp->bundle = (char *)(irsp + 1) + totalsz;
            strcpy(irsp->bundle, bundle);
        }

        if (reason_len > 0) {
            irsp->reason = (char *)(irsp + 1) + totalsz + bundle_len;
            strcpy(irsp->reason, reason);
        }

        gettimeofday_elapsed(&irsp->expire_time, TASSEMBLY_TIMEOUT);
        need_add = true;
    }

    if ((name && strcmp(irsp->ext, name)) || strcmp(irsp->friendid, friendid) ||
        data_len > INVITE_DATA_UNIT || irsp->data_off + data_len < data_len ||
        irsp->data_off + data_len > irsp->data_len) {
        vlogE("Carrier: Inavlid invite response fragment (or HACKED), dropped.");
        deref(irsp);
        deref(tcb);
        return;
    }

    if (data) {
        memcpy(irsp->data + irsp->data_off, data, data_len);
        irsp->data_off += data_len;
    }

    if (irsp->data_off == irsp->data_len) {
        callback_func = (CarrierFriendInviteResponseCallback *)tcb->callback_func;
        callback_ctxt = tcb->callback_context;
        assert(callback_func);

        transacted_callbacks_remove(w->tcallbacks, tid);

        callback_func(w, friendid, irsp->bundle, status, reason, irsp->data, irsp->data_len,
                      callback_ctxt);

        if (!need_add)
            tassemblies_remove(w->tassembly_irsps, &tid);
        else
            need_add = false;
    }

    if (need_add)
        tassemblies_put(w->tassembly_irsps, irsp);

    deref(irsp);
    deref(tcb);
}

static
void notify_friend_message_cb(uint32_t friend_number, const uint8_t *message,
                              size_t length, void *context)
{
    Carrier *w = (Carrier *)context;
    Packet *cp;

    cp = packet_decode(message, length);
    if (!cp) {
        vlogE("Carrier: Invalid DHT message, dropped.");
        return;
    }

    switch(packet_get_type(cp)) {
    case PACKET_TYPE_MESSAGE:
        handle_friend_message(w, friend_number, cp);
        break;
    case PACKET_TYPE_INVITE_REQUEST:
        handle_invite_request(w, friend_number, cp);
        break;
    case PACKET_TYPE_INVITE_RESPONSE:
        handle_invite_response(w, friend_number, cp);
        break;
    case PACKET_TYPE_BULKMSG:
        handle_friend_bulkmsg(w, friend_number, cp);
        break;
    default:
        vlogE("Carrier: Unknown DHT message, dropped.");
        break;
    }

    packet_free(cp);
}

static
void notify_friend_read_receipt_cb(uint32_t friend_number, uint32_t msgid,
                                   void *context)
{
    Carrier *w = (Carrier *)context;
    UnconfirmedMsg *item;

    item = unconfirmed_remove(w->unconfirmed, msgid);
    if (!item)
        return;

    if (item->callback)
        item->callback(item->msgid, CarrierReceipt_ByFriend, item->context);

    deref(item);
}

static
void notify_group_invite_cb(uint32_t friend_number, const uint8_t *cookie,
                            size_t len, void *user_data)
{
    FriendInfo *fi;
    Carrier *w = (Carrier *)user_data;

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogW("Carrier: Unknown friend number %u, group invitation dropped.",
              friend_number);
        return;
    }

    if (w->callbacks.group_invite) {
        char friendid[CARRIER_MAX_ID_LEN + 1];

        strcpy(friendid, fi->info.user_info.userid);
        w->callbacks.group_invite(w, friendid, cookie, len, w->context);
    }

    deref(fi);
}

static
int get_groupid_by_number(Carrier *w, uint32_t group_number,
                          char *groupid_buf, size_t length)
{
    uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
    size_t textlen = length;
    int rc;

    assert(length >= CARRIER_MAX_ID_LEN + 1);

    rc = dht_group_get_public_key(&w->dht, group_number, public_key);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    base58_encode(public_key, sizeof(public_key), groupid_buf, &textlen);

    return 0;
}

static
int get_peerid_by_number(Carrier *w, uint32_t group_number,
                         uint32_t peer_number, char *peerid_buf, size_t length)
{
    uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
    size_t textlen = length;
    int rc;

    assert(length >= CARRIER_MAX_ID_LEN + 1);

    rc = dht_group_get_peer_public_key(&w->dht, group_number, peer_number,
                                       public_key);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    base58_encode(public_key, sizeof(public_key), peerid_buf, &textlen);

    return 0;
}

static
void notify_group_connected_cb(uint32_t group_number, void *user_data)
{
    Carrier *w = (Carrier *)user_data;
    char groupid[CARRIER_MAX_ID_LEN + 1];
    int rc;

    rc = get_groupid_by_number(w, group_number, groupid, sizeof(groupid));
    if (rc < 0) {
        vlogE("Carrier: Unknown group number %u, group connection dropped.",
              group_number);
        return;
    }

    if (w->callbacks.group_callbacks.group_connected)
        w->callbacks.group_callbacks.group_connected(w, groupid, w->context);
}

static
void notify_group_message_cb(uint32_t group_number, uint32_t peer_number,
                             const uint8_t *msg, size_t len, void *user_data)
{
    Carrier *w = (Carrier *)user_data;
    char groupid[CARRIER_MAX_ID_LEN + 1];
    char peerid[CARRIER_MAX_ID_LEN + 1];
    int rc;

    rc = get_groupid_by_number(w, group_number, groupid, sizeof(groupid));
    if (rc < 0) {
        vlogE("Carrier: Unknown group number %u, group message dropped.",
              group_number);
        return;
    }

    rc = get_peerid_by_number(w, group_number, peer_number, peerid,
                              sizeof(peerid));
    if (rc < 0) {
        vlogE("Carrier: Unknown peer number %u, group message dropped.",
              peer_number);
        return;
    }

    if (w->callbacks.group_callbacks.group_message)
        w->callbacks.group_callbacks.group_message(w, groupid, peerid,
                                                  msg, len, w->context);
}

static
void notify_group_title_cb(uint32_t group_number, uint32_t peer_number,
                           const uint8_t *title, size_t length, void *user_data)
{
    Carrier *w = (Carrier *)user_data;
    char groupid[CARRIER_MAX_ID_LEN + 1];
    char peerid[CARRIER_MAX_ID_LEN + 1];
    int rc;

    if (peer_number == UINT32_MAX) {
        vlogI("Carrier: Do not notify newly joined peer about the group name.");
        return;
    }

    rc = get_groupid_by_number(w, group_number, groupid, sizeof(groupid));
    if (rc < 0) {
        vlogE("Carrier: Unknown group number %u, group titile change event "
              "dropped.", group_number);
        return;
    }

    rc = get_peerid_by_number(w, group_number, peer_number, peerid,
                              sizeof(peerid));
    if (rc < 0) {
        vlogE("Carrier: Unknown peer number %u, group titile change event "
              "dropped.", peer_number);
        return;
    }

    if (w->callbacks.group_callbacks.group_title)
        w->callbacks.group_callbacks.group_title(w, groupid, peerid,
                                                length ?
                                                (const char *)title : "",
                                                w->context);

    store_persistence_data(w);
}

static
void notify_group_peer_name_cb(uint32_t group_number, uint32_t peer_number,
                               const uint8_t *name, size_t length,
                               void *user_data)
{
    Carrier *w = (Carrier *)user_data;
    char groupid[CARRIER_MAX_ID_LEN + 1];
    char peerid[CARRIER_MAX_ID_LEN + 1];
    int rc;

    rc = get_groupid_by_number(w, group_number, groupid, sizeof(groupid));
    if (rc < 0) {
        vlogE("Carrier: Unknown group number %u, group peer name change event "
              "dropped.", group_number);
        return;
    }

    rc = get_peerid_by_number(w, group_number, peer_number, peerid,
                              sizeof(peerid));
    if (rc < 0) {
        vlogE("Carrier: Unknown peer number %u, group peer name change event "
              "dropped.", peer_number);
        return;
    }

    if (w->callbacks.group_callbacks.peer_name)
        w->callbacks.group_callbacks.peer_name(w, groupid, peerid,
                                               length ? (char *)name : "",
                                               w->context);

    store_persistence_data(w);
}

static
void notify_group_peer_list_changed_cb(uint32_t group_number, void *user_data)
{
    Carrier *w = (Carrier *)user_data;
    char groupid[CARRIER_MAX_ID_LEN + 1];
    int rc;

    rc = get_groupid_by_number(w, group_number, groupid, sizeof(groupid));
    if (rc < 0) {
        vlogE("Carrier: Unknown group number %u, group titile change event "
              "dropped.", group_number);
        return;
    }

    if (w->callbacks.group_callbacks.peer_list_changed)
        w->callbacks.group_callbacks.peer_list_changed(w, groupid, w->context);

    store_persistence_data(w);
}

static void connect_to_bootstraps(Carrier *w)
{
    int i;

    for (i = 0; i < w->pref.bootstrap_size; i++) {
        BootstrapNodeBuf *bi = &w->pref.bootstrap_nodes[i];
        char id[CARRIER_MAX_ID_LEN + 1] = {0};
        size_t id_len = sizeof(id);
        int rc;

        base58_encode(bi->public_key, DHT_PUBLIC_KEY_SIZE, id, &id_len);
        rc = _dht_bootstrap(&w->dht, bi->ipv4, bi->ipv6, bi->port, bi->public_key);
        if (rc < 0) {
            vlogW("Carrier: Try to connect to bootstrap "
                  "[ipv4:%s, ipv6:%s, port:%d, public_key:%s] error.",
                  *bi->ipv4 ? bi->ipv4 : "N/A", *bi->ipv6 ? bi->ipv6 : "N/A",
                  bi->port, id);
        } else {
            vlogT("Carrier: Try to connect to bootstrap "
                  "[ipv4:%s, ipv6:%s, port:%" PRIu16 ", public_key:%s] succeess.",
                  bi->ipv4 ? bi->ipv4 : "N/A", bi->ipv6 ? bi->ipv6 : "N/A",
                  bi->port, id);
        }
    }
}

int carrier_run(Carrier *w, int interval)
{
    if (!w || interval < 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (interval == 0)
        interval = 1000; // in milliseconds.

    ref(w);

    w->dht_callbacks.notify_connection = notify_connection_cb;
    w->dht_callbacks.notify_friend_desc = notify_friend_description_cb;
    w->dht_callbacks.notify_friend_connection = notify_friend_connection_cb;
    w->dht_callbacks.notify_friend_status = notify_friend_status_cb;
    w->dht_callbacks.notify_friend_request = notify_friend_request_cb;
    w->dht_callbacks.notify_friend_message = notify_friend_message_cb;
    w->dht_callbacks.notify_friend_read_receipt = notify_friend_read_receipt_cb;
    w->dht_callbacks.notify_group_invite = notify_group_invite_cb;
    w->dht_callbacks.notify_group_connected = notify_group_connected_cb;
    w->dht_callbacks.notify_group_message = notify_group_message_cb;
    w->dht_callbacks.notify_group_title = notify_group_title_cb;
    w->dht_callbacks.notify_group_peer_name = notify_group_peer_name_cb;
    w->dht_callbacks.notify_group_peer_list_changed = notify_group_peer_list_changed_cb;
    w->dht_callbacks.context = w;

    notify_friends(w);

    w->running = 1;

    connect_to_bootstraps(w);

    while(!w->quit) {
        int idle_interval;
        struct timeval expire;
        struct timeval check;
        struct timeval tmp;
        bool conn_made;

        gettimeofday(&expire, NULL);

        idle_interval = dht_iteration_idle(&w->dht);
        if (idle_interval > interval)
            idle_interval = interval;

        tmp.tv_sec = 0;
        tmp.tv_usec = idle_interval * 1000;

        timeradd(&expire, &tmp, &expire);

        do_friend_events(w);
        do_tassemblies_expire(w->tassembly_ireqs);
        do_tassemblies_expire(w->tassembly_irsps);
        do_transacted_callabcks_expire(w);
        do_bulkmsgs_expire(w->bulkmsgs);
        do_express_expire(w);

        if (idle_interval > 0)
            notify_idle(w);

        gettimeofday(&check, NULL);

        if (timercmp(&expire, &check, >)) {
            timersub(&expire, &check, &tmp);
            usleep(tmp.tv_usec);
        }

        dht_iterate(&w->dht, &w->dht_callbacks);
    }

    w->running = 0;

    store_persistence_data(w);

    deref(w);

    return 0;
}

char *carrier_get_address(Carrier *w, char *address, size_t length)
{
    if (!w || !address || !length) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return NULL;
    }

    if (strlen(w->base58_addr) >= length) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_BUFFER_TOO_SMALL));
        return NULL;
    }

    strcpy(address, w->base58_addr);
    return address;
}

char *carrier_get_nodeid(Carrier *w, char *nodeid, size_t len)
{
    if (!w || !nodeid || !len) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return NULL;
    }

    if (strlen(w->me.userid) >= len) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_BUFFER_TOO_SMALL));
        return NULL;
    }

    strcpy(nodeid, w->me.userid);
    return nodeid;
}

char *carrier_get_userid(Carrier *w, char *userid, size_t len)
{
    return carrier_get_nodeid(w, userid, len);
}

int carrier_set_self_nospam(Carrier *w, uint32_t nospam)
{
    int rc;

    if (!w) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    dht_self_set_nospam(&w->dht, nospam);

    rc = dht_get_self_info(&w->dht, get_self_info_cb, w);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    store_persistence_data(w);

    return 0;
}

int carrier_get_self_nospam(Carrier *w, uint32_t *nospam)
{
    if (!w || !nospam) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    *nospam = dht_self_get_nospam(&w->dht);

    return 0;
}

int carrier_set_self_info(Carrier *w, const CarrierUserInfo *info)
{
    Packet *cp;
    uint8_t *data;
    size_t data_len;
    bool did_changed = false;

    if (!w || !info) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (strcmp(info->userid, w->me.userid) != 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    cp = packet_create(PACKET_TYPE_USERINFO, NULL);
    if (!cp) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    if (info->has_avatar != w->me.has_avatar ||
        strcmp(info->name, w->me.name) ||
        strcmp(info->description, w->me.description) ||
        strcmp(info->gender, w->me.gender) ||
        strcmp(info->phone, w->me.phone) ||
        strcmp(info->email, w->me.email) ||
        strcmp(info->region, w->me.region)) {
        did_changed = true;
    } else {
        packet_free(cp);
    }

    if (did_changed) {
        if (strcmp(info->name, w->me.name)) {
            int rc = dht_self_set_name(&w->dht, (uint8_t *)info->name,
                                       strlen(info->name) + 1);
            if (rc) {
                packet_free(cp);
                carrier_set_error(rc);
                return -1;
            }
        }

        packet_set_has_avatar(cp, !!info->has_avatar);
        packet_set_name(cp, info->name);
        packet_set_descr(cp, info->description);
        packet_set_gender(cp, info->gender);
        packet_set_phone(cp, info->phone);
        packet_set_email(cp, info->email);
        packet_set_region(cp, info->region);

        data = packet_encode(cp, &data_len);
        packet_free(cp);

        if (!data) {
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return -1;
        }

        /* Use tox status message as user information. The total length of
           user information is about 700, far less than the max length
           value of status message (1007).
         */
        w->me.has_avatar = info->has_avatar;
        strcpy(w->me.name, info->name);
        strcpy(w->me.description, info->description);
        strcpy(w->me.gender, info->gender);
        strcpy(w->me.phone, info->phone);
        strcpy(w->me.email, info->email);
        strcpy(w->me.region, info->region);
        dht_self_set_desc(&w->dht, data, data_len);

        store_persistence_data(w);

        free(data);
    }

    return 0;
}

int carrier_get_self_info(Carrier *w, CarrierUserInfo *info)
{
    if (!w || !info) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    memcpy(info, &w->me, sizeof(CarrierUserInfo));

    return 0;
}

int carrier_set_self_presence(Carrier *w, CarrierPresenceStatus status)
{
    if (!w) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (status < CarrierPresenceStatus_None ||
        status > CarrierPresenceStatus_Busy) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    dht_self_set_status(&w->dht, (int)status);

    return 0;
}

int carrier_get_self_presence(Carrier *w, CarrierPresenceStatus *status)
{
    int presence_status;

    if (!w || !status) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    presence_status = dht_self_get_status(&w->dht);

    if (presence_status < CarrierPresenceStatus_None)
        *status = CarrierPresenceStatus_None;
    else if (presence_status > CarrierPresenceStatus_Busy)
        *status = CarrierPresenceStatus_None;
    else
        *status = (CarrierPresenceStatus)presence_status;

    return 0;
}

bool carrier_is_ready(Carrier *w)
{
    if (!w) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return false;
    }

    carrier_set_error(0);
    return w->is_ready;
}

int carrier_get_friends(Carrier *w,
                    CarrierFriendsIterateCallback *callback, void *context)
{
    linked_hashtable_iterator_t it;

    if (!w || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    friends_iterate(w->friends, &it);
    while(friends_iterator_has_next(&it)) {
        FriendInfo *fi;

        if (friends_iterator_next(&it, &fi) == 1) {
            CarrierFriendInfo wfi;

            memcpy(&wfi, &fi->info, sizeof(CarrierFriendInfo));
            deref(fi);

            if (!callback(&wfi, context))
                return 0;
        }
    }

    /* Friend list is end */
    callback(NULL, context);

    return 0;
}

int carrier_get_friend_info(Carrier *w, const char *friendid,
                        CarrierFriendInfo *info)
{
    uint32_t friend_number;
    FriendInfo *fi;
    int rc;

    if (!w || !friendid || !*friendid || !info) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    rc = get_friend_number(w, friendid, &friend_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }
    assert(!strcmp(friendid, fi->info.user_info.userid));

    memcpy(info, &fi->info, sizeof(CarrierFriendInfo));

    deref(fi);

    return 0;
}

int carrier_set_friend_label(Carrier *w,
                         const char *friendid, const char *label)
{
    uint32_t friend_number;
    FriendInfo *fi;
    int rc;

    if (!w || !friendid || !*friendid) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (label && strlen(label) > CARRIER_MAX_USER_NAME_LEN) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    rc = get_friend_number(w, friendid, &friend_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }
    assert(!strcmp(friendid, fi->info.user_info.userid));

    strcpy(fi->info.label, label ? label : "");

    deref(fi);

    store_persistence_data(w);

    return 0;
}

bool carrier_is_friend(Carrier *w, const char *userid)
{
    uint32_t friend_number;
    int rc;

    if (!w || !userid || !*userid) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return false;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc < 0 || friend_number == UINT32_MAX) {
        carrier_set_error(rc);
        return false;
    }

    carrier_set_error(0);
    return !!friends_exist(w->friends, friend_number);
}

int carrier_add_friend(Carrier *w, const char *address, const char *hello)
{
    uint32_t friend_number;
    FriendInfo *fi;
    uint8_t addr[DHT_ADDRESS_SIZE];
    Packet *cp;
    uint8_t *data;
    size_t data_len;
    size_t _len;
    int rc;

    if (!w || !hello || !*hello || !address || !*address) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_address(address)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!strcmp(address, w->base58_addr)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    base58_decode(address, strlen(address), addr, sizeof(addr));

    cp = packet_create(PACKET_TYPE_FRIEND_REQUEST, NULL);
    if (!cp) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    packet_set_name(cp, w->me.name);
    packet_set_descr(cp, w->me.description);
    packet_set_hello(cp, hello);

    data = packet_encode(cp, &data_len);
    packet_free(cp);

    if (!data) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    rc = dht_get_friend_number(&w->dht, addr, &friend_number);
    if (rc < 0 && rc != CARRIER_DHT_ERROR(ERROR_NOT_EXIST)) {
        carrier_set_error(rc);
        free(data);
        return -1;
    }

    if (rc == 0) { // friend already exist.
        rc = dht_friend_add(&w->dht, addr, data, data_len, &friend_number);
        free(data);

        if (rc < 0) {
            carrier_set_error(rc);
            return -1;
        }
        return 0;
    }

    // this is the first time send friend request.
    fi = (FriendInfo *)rc_zalloc(sizeof(FriendInfo), NULL);
    if (!fi) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        free(data);
        return -1;
    }

    rc = dht_friend_add(&w->dht, addr, data, data_len, &friend_number);
    if (rc < 0) {
        carrier_set_error(rc);
        free(data);
        deref(fi);
        return -1;
    }

    if (w->connector) {
        rc = express_enqueue_post_request(w->connector, address, data, data_len);
        if (rc < 0)
            vlogW("Carrier: Enqueue offline friend request error (%d)", rc);
    }

    free(data);

    _len = sizeof(fi->info.user_info.userid);
    base58_encode(addr, DHT_PUBLIC_KEY_SIZE, fi->info.user_info.userid, &_len);

    fi->friend_number = friend_number;
    fi->info.presence = CarrierPresenceStatus_None;
    fi->info.status   = CarrierConnectionStatus_Disconnected;
    friends_put(w->friends, fi);

    notify_friend_changed(w, &fi->info, handle_add_friend_cb);

    deref(fi);

    return 0;
}

int carrier_accept_friend(Carrier *w, const char *userid)
{
    uint32_t friend_number = UINT32_MAX;
    uint8_t pubkey[DHT_PUBLIC_KEY_SIZE];
    FriendInfo *fi;
    int rc;

    if (!w || !userid || !*userid) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(userid)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (strcmp(userid, w->me.userid) == 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc == 0 && friend_number != UINT32_MAX) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_ALREADY_EXIST));
        return -1;
    }

    fi = (FriendInfo *)rc_zalloc(sizeof(FriendInfo), NULL);
    if (!fi) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    base58_decode(userid, strlen(userid), pubkey, sizeof(pubkey));
    rc = dht_friend_add_norequest(&w->dht, pubkey, &friend_number);
    if (rc < 0) {
        deref(fi);
        carrier_set_error(rc);
        return -1;
    }

    strcpy(fi->info.user_info.userid, userid);

    fi->friend_number = friend_number;
    fi->info.presence = CarrierPresenceStatus_None;
    fi->info.status   = CarrierConnectionStatus_Disconnected;

    friends_put(w->friends, fi);

    notify_friend_changed(w, &fi->info, handle_add_friend_cb);
    deref(fi);

    return 0;
}

int carrier_remove_friend(Carrier *w, const char *friendid)
{
    uint32_t friend_number;
    FriendInfo *fi;
    int rc;

    if (!w || !friendid || !*friendid) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(friendid)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_friend_number(w, friendid, &friend_number);
    if (rc < 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    fi = friends_remove(w->friends, friend_number);
    if (!fi) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    dht_friend_delete(&w->dht, friend_number);

    notify_friend_changed(w, &fi->info, handle_remove_friend_cb);
    deref(fi);

    return 0;
}

static void parse_address(const char *addr, char **userid, char **ext)
{
    char *colon_pos = NULL;

    assert(addr);
    assert(userid);
    assert(ext);

    /* Parse address with scheme like 'userid:extension' */
    *userid = (char *)addr;

    colon_pos = strchr(addr, ':');
    if (colon_pos) {
        *ext = colon_pos+1;
        *colon_pos = 0;
    } else {
        *ext = NULL;
    }
}

static int send_general_message(Carrier *w, uint32_t friend_number,
                                    const void *msg, size_t len,
                                    const char *ext_name,
                                    uint32_t msgid)
{
    Packet *cp;
    uint8_t *data;
    size_t data_len;
    int rc;

    cp = packet_create(PACKET_TYPE_MESSAGE, ext_name);
    if (!cp)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    packet_set_raw_data(cp, msg, len);

    data = packet_encode(cp, &data_len);
    packet_free(cp);

    if (!data)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    rc = dht_friend_message(&w->dht, friend_number, data, data_len, msgid);
    free(data);

    return rc;
}

static int64_t generate_tid(void)
{
    int64_t tid;

    do {
        tid = time(NULL);
        tid += rand();
    } while (tid == 0);

    return tid;
}

static int send_bulk_message(Carrier *w, uint32_t friend_number,
                                 const void *msg, size_t len,
                                 const char *ext_name,
                                 uint32_t msgid)
{
    Packet *cp;
    int64_t tid;
    uint8_t *data;
    size_t data_len;
    char *pos = (char *)msg;
    size_t left = len;
    int index = 0;
    int rc;

    tid = generate_tid();

    do {
        size_t send_len;

        cp = packet_create(PACKET_TYPE_BULKMSG, ext_name);
        if (!cp)
            return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

        packet_set_tid(cp, &tid);
        ++index;

        if (left < CARRIER_MAX_APP_MESSAGE_LEN)
            send_len = left;
        else
            send_len = CARRIER_MAX_APP_MESSAGE_LEN;

        packet_set_totalsz(cp, (index == 1)? left : 0);
        packet_set_raw_data(cp, pos, send_len);

        pos  += send_len;
        left -= send_len;

        data = packet_encode(cp, &data_len);
        packet_free(cp);

        if (!data)
            return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

        rc = dht_friend_message(&w->dht, friend_number, data, data_len, !left ? msgid : 0);
        free(data);

    } while (left > 0 && !rc);

    return rc;
}

static int send_express_message(Carrier *w, const char *userid,
                                uint32_t msgid, const void *msg, size_t len,
                                const char *ext_name)
{
    Packet *cp;
    uint8_t *data;
    size_t data_len;
    int rc;

    assert(w->connector);

    cp = packet_create(PACKET_TYPE_MESSAGE, ext_name);
    if (!cp)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    packet_set_raw_data(cp, msg, len);

    data = packet_encode(cp, &data_len);
    packet_free(cp);

    if (!data)
        return CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY);

    rc = express_enqueue_post_message_with_receipt(w->connector, userid, data, data_len, msgid);
    free(data);

    if (rc < 0)
        vlogW("Carrier: Enqueu offline friend message error.");

    return 0;
}

static int send_friend_message_internal(Carrier *w, const char *to,
                                        const void *msg, size_t len,
                                        uint32_t msgid)
{
    char *addr;
    char *userid;
    char *ext_name;
    FriendInfo *fi;
    bool online;
    uint32_t friend_number;
    int rc;

    if (!w || !to || !msg || !len || len > CARRIER_MAX_APP_BULKMSG_LEN) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    addr = (char *)alloca(strlen(to) + 1);
    strcpy(addr, to);
    parse_address(addr, &userid, &ext_name);

    if (!is_valid_key(userid)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (ext_name && strlen(ext_name) > CARRIER_MAX_USER_NAME_LEN) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (strcmp(userid, w->me.userid) == 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        vlogE("Carrier: Send message to myself not allowed.");
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc < 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    online = (fi->info.status == CarrierConnectionStatus_Connected);
    deref(fi);

    if (online) {
        if (len <= CARRIER_MAX_APP_MESSAGE_LEN)
            rc = send_general_message(w, friend_number, msg, len, ext_name, msgid);
        else
            rc = send_bulk_message(w, friend_number, msg, len, ext_name, msgid);
    } else {
        rc = CARRIER_DHT_ERROR(ERROR_FRIEND_OFFLINE);
    }

    if (rc < 0 && w->connector)
        rc = send_express_message(w, userid, msgid, msg, len, ext_name);

    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    return rc;
}

static void handle_offline_friend_message_cb(EventBase *base, Carrier *w)
{
    OfflineEvent* event = (OfflineEvent *)base;
    Packet *cp;
    const char* name;
    const void* data;
    size_t len;

    assert(event->timestamp > 0);
    assert(event->length > 0);

    if (!carrier_is_friend(w, event->from)) {
        vlogW("Carrier: Offline message is not from friends, dropped");
        return;
    }

    cp = packet_decode(event->data, event->length);
    if (!cp) {
        vlogE("Carrier: Decode offline message content failed, dropped");
        return;
    }

    if (packet_get_type(cp) != PACKET_TYPE_MESSAGE) {
        packet_free(cp);
        vlogE("Carrier: Invalid offline message type, dropped");
        return;
    }

    name = packet_get_extension(cp);
    data = packet_get_raw_data(cp);
    len  = packet_get_raw_data_length(cp);

    assert(data);
    assert(len > 0);

    if (w->callbacks.friend_message && (!name || !*name))
        w->callbacks.friend_message(w, event->from, data, len, event->timestamp,
                                    true, w->context);

    packet_free(cp);
}

static void notify_offmsg_received(Carrier *w, const char *from,
                                   const uint8_t *msg, size_t len,
                                   uint64_t timestamp)
{
    OfflineEvent *event;

    assert(w);
    assert(from && *from);
    assert(msg);
    assert(len);

    event = rc_zalloc(sizeof(OfflineEvent) + len, NULL);
    if (event) {
        strcpy(event->from, from);
        event->timestamp = timestamp;
        event->length = len;
        memcpy(event->data, msg, len);

        event->base.le.data = event;
        event->base.handle = handle_offline_friend_message_cb;
        linked_list_push_tail(w->friend_events, &event->base.le);
        deref(event);
    }
}

static void handle_offline_friend_request_cb(EventBase *base, Carrier *w)
{
    OfflineEvent *event = (OfflineEvent *)base;
    uint8_t pubkey[DHT_PUBLIC_KEY_SIZE] = {0};
    ssize_t len;

    len = base58_decode(event->from, strlen(event->from), pubkey, sizeof(pubkey));
    if (len != (ssize_t)sizeof(pubkey)) {
        vlogE("Carrier: Base8 decode offline friend request failed.", event->from);
        return;
    }

    notify_friend_request_cb(pubkey, event->data, event->length, w);
}

static void notify_offreq_received(Carrier *w, const char *from,
                                   const uint8_t *greeting, size_t len,
                                   uint64_t timestamp)
{
    OfflineEvent *event;

    assert(w);
    assert(from && *from);
    assert(greeting);
    assert(len);

    event = rc_zalloc(sizeof(OfflineEvent) + len, NULL);
    if (event) {
        strcpy(event->from, from);
        event->timestamp = timestamp;
        event->length = len;
        memcpy(event->data, greeting, len);

        event->base.le.data = event;
        event->base.handle = handle_offline_friend_request_cb;
        linked_list_push_tail(w->friend_events, &event->base.le);
        deref(event);
    }
}

static void handle_offline_message_receipt_cb(EventBase *base, Carrier *w)
{
    MsgidEvent *event = (MsgidEvent *)base;
    UnconfirmedMsg *item;
    CarrierReceiptState state;

    item = unconfirmed_remove(w->unconfirmed, event->msgid);
    if (!item)
        return;

    if(event->errcode == 0)
        state = CarrierReceipt_Offline;
    else
        state = CarrierReceipt_Error;

    if (item->callback)
        item->callback(item->msgid, state, item->context);

    deref(item);
}

static void notify_offreceipt_received(Carrier *w, const char *to,
                                       ExpressMessageType type,
                                       uint32_t msgid, int errcode)
{
    MsgidEvent *event;

    assert(w);
    assert(to && *to);

    if (type == EXPRESS_FRIEND_REQUEST) {
        vlogI("Carrier: offline request friend %s %s(%x).",
              to, (errcode == 0 ? "success" : "failed"), errcode);
        return;
    }

    event = rc_zalloc(sizeof(MsgidEvent), NULL);
    if (event) {
        strcpy(event->friendid, to);
        event->msgid = msgid;
        event->errcode = errcode;

        event->base.le.data = event;
        event->base.handle = handle_offline_message_receipt_cb;
        linked_list_push_tail(w->friend_events, &event->base.le);
        deref(event);
    }
}

static uint32_t generate_msgid(Carrier *w)
{
    static uint32_t msg_id = 0;
    return ++msg_id == 0 ? ++msg_id : msg_id;
}

static
int send_message_with_receipt_internal(Carrier *w, const char *to,
                                const void *msg, size_t len,
                                uint32_t *msgid,
                                CarrierFriendMessageReceiptCallback *cb,
                                void *context)
{
    UnconfirmedMsg *item;
    uint32_t _msgid;
    int rc;

    item = (UnconfirmedMsg *)rc_zalloc(sizeof(UnconfirmedMsg) + len, NULL);
    if (!item) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    _msgid = generate_msgid(w);

    strcpy(item->to, to);
    item->callback = cb;
    item->context  = context;
    item->size     = len;
    item->msgid    = _msgid;
    item->offline_sending = 0;
    memcpy(item->data, msg, len);

    unconfirmed_put(w->unconfirmed, item);

    rc = send_friend_message_internal(w, to, msg, len, _msgid);
    deref(item);
    if (rc < 0) {
        deref(unconfirmed_remove(w->unconfirmed, _msgid));
        return -1;
    }

    if (msgid)
        *msgid = _msgid;

    return 0;
}

int carrier_send_friend_message(Carrier *w, const char *to,
                            const void *message, size_t len,
                            uint32_t *msgid,
                            CarrierFriendMessageReceiptCallback *cb, void *context)
{
    return send_message_with_receipt_internal(w, to, message, len, msgid, cb, context);
}

int carrier_invite_friend(Carrier *w, const char *to, const char *bundle,
                      const void *data, size_t len,
                      CarrierFriendInviteResponseCallback *callback,
                      void *context)
{
    char *addr, *userid, *ext_name;
    uint32_t friend_number;
    Packet *cp;
    int rc;
    int64_t tid;
    int index = 0;
    int bundle_len = bundle ? strlen(bundle) : 0;
    char *pos = (char *)data;
    size_t send_len = 0;

    if (!w || (bundle && (!*bundle || bundle_len > CARRIER_MAX_BUNDLE_LEN))
           || !data || !len || len > CARRIER_MAX_INVITE_DATA_LEN || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!to || !(*to) || strlen(to) >
            (CARRIER_MAX_ID_LEN + sizeof(':') + CARRIER_MAX_EXTENSION_NAME_LEN)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    addr = alloca(strlen(to) + 1);
    strcpy(addr, to);
    parse_address(addr, &userid, &ext_name);

    if (!is_valid_key(userid)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (ext_name && (!(*ext_name) || strlen(ext_name) >
                                     CARRIER_MAX_EXTENSION_NAME_LEN)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc < 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    if (!friends_exist(w->friends, friend_number)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    tid = generate_tid();

    do {
        uint8_t *_data;
        size_t _data_len;

        cp = packet_create(PACKET_TYPE_INVITE_REQUEST, ext_name);
        if (!cp) {
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return -1;
        }

        packet_set_tid(cp, &tid);
        ++index;

        if (len > 0) {
            if (bundle) {
                if (len + bundle_len <= INVITE_DATA_UNIT)
                    send_len = len;
                else
                    send_len = INVITE_DATA_UNIT - bundle_len;

                if (index == 1) {
                    packet_set_bundle(cp, bundle);
                    bundle_len = 0;
                }
            } else {
                send_len = (len > INVITE_DATA_UNIT) ? INVITE_DATA_UNIT : len;
            }

            packet_set_totalsz(cp, (index == 1 ? len : 0));
            packet_set_raw_data(cp, pos, send_len);
            pos += send_len;
            len -= send_len;
        }

        _data = packet_encode(cp, &_data_len);
        packet_free(cp);

        if (!_data) {
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return -1;
        }

        if (len == 0) {
            TransactedCallback *tcb;
            tcb = (TransactedCallback *)rc_alloc(sizeof(TransactedCallback) +
                                    (bundle ? strlen(bundle) + 1 : 0), NULL);
            if (!tcb) {
                carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
                free(_data);
                return -1;
            }

            tcb->tid = tid;
            tcb->callback_func = callback;
            tcb->friend_number = friend_number;
            tcb->callback_context = context;
            if (bundle) {
                tcb->bundle = (char*)(tcb + 1);
                strcpy(tcb->bundle, bundle);
            } else {
                tcb->bundle = NULL;
            }

            transacted_callbacks_put(w->tcallbacks, tcb);
            deref(tcb);
        }

        rc = dht_friend_message(&w->dht, friend_number, _data, _data_len, 0);
        free(_data);

        if (rc < 0) {
            if (len == 0)
                transacted_callbacks_remove(w->tcallbacks, tid);

            carrier_set_error(rc);
            return -1;
        }
    } while (len > 0);

    return 0;
}

int carrier_reply_friend_invite(Carrier *w, const char *to, const char *bundle,
                            int status, const char *reason,
                            const void *data, size_t len)
{
    char *addr, *userid, *ext_name;
    uint32_t friend_number;
    int64_t tid;
    int index = 0;
    int bundle_len = bundle ? strlen(bundle) : 0;
    int reason_len = reason ? strlen(reason) : 0;
    char *pos = (char*)data;
    size_t send_len;
    Packet *cp;
    int rc;

    if (!w || (bundle && (!*bundle || bundle_len > CARRIER_MAX_BUNDLE_LEN))) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (status && (!reason || reason_len > CARRIER_MAX_INVITE_REPLY_REASON_LEN
            || data || len > 0)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!status && (reason || !data || !len || len > CARRIER_MAX_INVITE_DATA_LEN)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!to || !(*to) || strlen(to) >
            (CARRIER_MAX_ID_LEN + sizeof(':') + CARRIER_MAX_EXTENSION_NAME_LEN)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    addr = alloca(strlen(to) + 1);
    strcpy(addr, to);
    parse_address(addr, &userid, &ext_name);

    if (!is_valid_key(userid)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (ext_name && (!(*ext_name) || strlen(ext_name) >
                                     CARRIER_MAX_EXTENSION_NAME_LEN)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc < 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    if (!friends_exist(w->friends, friend_number)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return -1;
    }

    tid = transaction_history_get_invite(w->thistory, to);
    if (tid == 0) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NO_MATCHED_REQUEST));
        return -1;
    }

    do {
        uint8_t *_data;
        size_t _data_len;

        cp = packet_create(PACKET_TYPE_INVITE_RESPONSE, ext_name);
        if (!cp) {
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return -1;
        }

        packet_set_tid(cp, &tid);
        packet_set_status(cp, status);
        ++index;

        if (index == 1) {
            if (bundle)
                packet_set_bundle(cp, bundle);

            if (status)
                packet_set_reason(cp, reason);
        }

        if (!status && pos && len > 0) {
            if (bundle_len + len <= INVITE_DATA_UNIT)
                send_len = len;
            else {
                send_len = INVITE_DATA_UNIT;
                if (bundle_len > 0) {
                    send_len -= bundle_len;
                    bundle_len = 0;
                }
            }

            packet_set_totalsz(cp, (index == 1 ? len : 0));
            packet_set_raw_data(cp, pos, send_len);

            pos += send_len;
            len -= send_len;
        }

        _data = packet_encode(cp, &_data_len);
        packet_free(cp);

        if (!_data) {
            carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
            return -1;
        }

        rc = dht_friend_message(&w->dht, friend_number, _data, _data_len, 0);
        free(_data);

        if (rc < 0) {
            carrier_set_error(rc);
            return -1;
        }
    } while (len > 0);

    transaction_history_remove_invite(w->thistory, to);

    return 0;
}

int carrier_new_group(Carrier *w, char *groupid, size_t length)
{
    uint32_t group_number;
    int rc;

    if (!w || !groupid || length <= CARRIER_MAX_ID_LEN) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = dht_group_new(&w->dht, &group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    rc = get_groupid_by_number(w, group_number, groupid, length);
    if (rc < 0) {
        dht_group_leave(&w->dht, group_number);
        carrier_set_error(rc);
        return -1;
    }

    store_persistence_data(w);

    vlogD("Carrier: Group %s created.", groupid);

    return 0;
}

static
int get_group_number(Carrier *w, const char *groupid, uint32_t *group_number)
{
    uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
    ssize_t len;
    int rc;

    assert(w);
    assert(groupid);
    assert(group_number);

    len = base58_decode(groupid, strlen(groupid), public_key, sizeof(public_key));
    if (len != DHT_PUBLIC_KEY_SIZE) {
        vlogE("Carrier: groupid %s not base58 encoded.", groupid);
        return CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS);
    }

    rc = dht_group_number_by_public_key(&w->dht, public_key, group_number);
    if (rc < 0)
        return CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST);

    return rc;
}

int carrier_leave_group(Carrier *w, const char *groupid)
{
    uint32_t group_number;
    int rc;

    if (!w || !groupid || !*groupid) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_group_number(w, groupid, &group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    rc = dht_group_leave(&w->dht, group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    store_persistence_data(w);

    vlogD("Carrier: Leaved from Group %s", groupid);

    return 0;
}

int carrier_group_invite(Carrier *w, const char *groupid, const char *friendid)
{
    uint32_t friend_number;
    uint32_t group_number;
    int rc;

    if (!w || !groupid || !*groupid || !friendid || !*friendid) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_group_number(w, groupid, &group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    rc = get_friend_number(w, friendid, &friend_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    rc = dht_group_invite(&w->dht, group_number, friend_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    vlogD("Carrier: Invite friend %s into group %s success", friendid,
          groupid);

    return 0;
}

int carrier_group_join(Carrier *w, const char *friendid, const void *cookie,
                   size_t cookie_len, char *groupid, size_t length)
{
    uint32_t friend_number;
    uint32_t group_number;
    int rc;

    if (!w || !friendid || !*friendid || !cookie || !cookie_len ||
        !groupid || length <= CARRIER_MAX_ID_LEN) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_friend_number(w, friendid, &friend_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    rc = dht_group_join(&w->dht, friend_number, (const uint8_t *)cookie,
                        cookie_len, &group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    rc = get_groupid_by_number(w, group_number, groupid, length);
    if (rc < 0) {
        dht_group_leave(&w->dht, group_number);
        carrier_set_error(rc);
        return -1;
    }

    vlogD("Carrier: Friend %s joined group %s success", friendid, groupid);

    return 0;
}

int carrier_group_send_message(Carrier *w, const char *groupid, const void *msg,
                           size_t length)
{
    uint32_t group_number;
    int rc;

    if (!w || !groupid || !*groupid || !msg || !length ||
        length > CARRIER_MAX_APP_MESSAGE_LEN) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_group_number(w, groupid, &group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return  -1;
    }

    rc = dht_group_send_message(&w->dht, group_number, msg, length);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    return 0;
}

int carrier_group_get_title(Carrier *w, const char *groupid, char *title,
                        size_t length)
{
    uint32_t group_number;
    int rc;

    if (!w || !groupid || !*groupid || !title || !length) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_group_number(w, groupid, &group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return  -1;
    }

    memset(title, 0, length);
    rc = dht_group_get_title(&w->dht, group_number, (uint8_t *)title, length);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    return 0;
}

int carrier_group_set_title(Carrier *w, const char *groupid, const char *title)
{
    uint32_t group_number;
    char buf[CARRIER_MAX_GROUP_TITLE_LEN + 1];
    int rc;

    if (!w || !groupid || !*groupid || !title || !*title ||
        strlen(title) > CARRIER_MAX_GROUP_TITLE_LEN) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_group_number(w, groupid, &group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    rc = dht_group_get_title(&w->dht, group_number, (uint8_t *)buf, sizeof(buf));
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    if ((rc <= 1 && !*title) || (rc > 1 && strcmp(buf, title) == 0))
        return 0;

    rc = dht_group_set_title(&w->dht, group_number, (uint8_t *)title,
                             strlen(title) + 1);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    store_persistence_data(w);

    return 0;
}

int carrier_group_get_peers(Carrier *w, const char *groupid,
                        CarrierGroupPeersIterateCallback *callback,
                        void *context)
{
    uint32_t group_number;
    uint32_t peer_count;
    uint32_t i;
    int rc;

    if (!w || !groupid || !*groupid || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_group_number(w, groupid, &group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    rc = dht_group_peer_count(&w->dht, group_number, &peer_count);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    for (i = 0; i < peer_count; i++) {
        uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
        CarrierGroupPeer peer;
        size_t text_sz = sizeof(peer.userid);
        char *peerid;

        rc = dht_group_get_peer_name(&w->dht, group_number, i, peer.name,
                                     sizeof(peer.name));
        if (rc < 0) {
            vlogW("Carrier: Get peer %lu name from group:%lu error.",
                  i, group_number);
            continue;
        } else if (rc == 0) {
            peer.name[0] = '\0';
        } else {
            //Dothing.
        }

        rc = dht_group_get_peer_public_key(&w->dht, group_number, i, public_key);
        if (rc < 0) {
            vlogW("Carrier: Get peer %lu public key from group %lu error.",
                  i, group_number);
            continue;
        }

        peerid = base58_encode(public_key, sizeof(public_key), peer.userid,
                               &text_sz);
        if (!peerid) {
            vlogW("Carrier: Convert public key to userid error");
            continue;
        }

        if (!callback(&peer, context))
            return 0;
    }

    rc = dht_group_offline_peer_count(&w->dht, group_number, &peer_count);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    for (i = 0; i < peer_count; i++) {
        uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
        CarrierGroupPeer peer;
        size_t text_sz = sizeof(peer.userid);
        char *peerid;

        rc = dht_group_get_offline_peer_name(&w->dht, group_number, i, peer.name,
                                             sizeof(peer.name));
        if (rc < 0) {
            vlogW("Carrier: Get peer %lu name from group:%lu error.",
                  i, group_number);
            continue;
        } else if (rc == 0) {
            peer.name[0] = '\0';
        } else {
            //Dothing.
        }

        rc = dht_group_get_offline_peer_public_key(&w->dht, group_number, i, public_key);
        if (rc < 0) {
            vlogW("Carrier: Get peer %lu public key from group %lu error.",
                  i, group_number);
            continue;
        }

        peerid = base58_encode(public_key, sizeof(public_key), peer.userid,
                               &text_sz);
        if (!peerid) {
            vlogW("Carrier: Convert public key to userid error");
            continue;
        }

        if (!callback(&peer, context))
            return 0;
    }

    callback(NULL, context);
    return 0;
}

int carrier_group_get_peer(Carrier *w, const char *groupid,
                       const char *peerid, CarrierGroupPeer *peer)
{
    uint8_t peerpk[DHT_PUBLIC_KEY_SIZE];
    uint32_t group_number;
    uint32_t peer_count;
    uint32_t i;
    int rc;

    if (!w || !groupid || !*groupid || !peerid || !*peerid || !peer) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    rc = (int)base58_decode(peerid, strlen(peerid), peerpk, sizeof(peerpk));
    if (rc != sizeof(peerpk)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_BEING_READY));
        return -1;
    }

    rc = get_group_number(w, groupid, &group_number);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    rc = dht_group_peer_count(&w->dht, group_number, &peer_count);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    for (i = 0; i < peer_count; i++) {
        uint8_t public_key[DHT_PUBLIC_KEY_SIZE];

        rc = dht_group_get_peer_public_key(&w->dht, group_number, i, public_key);
        if (rc < 0) {
            vlogW("Carrier: Get peer %lu name from group:%lu error.",
                  i, group_number);
            continue;
        }

        if (memcmp(peerpk, public_key, sizeof(peerpk)) == 0) {
            memset(peer->name, 0, sizeof(peer->name));
            rc = dht_group_get_peer_name(&w->dht, group_number, i, peer->name,
                                         sizeof(peer->name));
            if (rc < 0) {
                vlogE("Carrier: Get peer %lu name from group:%lu error.", i,
                      group_number);
                carrier_set_error(rc);
                return -1;
            }

            strcpy(peer->userid, peerid);

            return 0;
        }
    }

    rc = dht_group_offline_peer_count(&w->dht, group_number, &peer_count);
    if (rc < 0) {
        carrier_set_error(rc);
        return -1;
    }

    for (i = 0; i < peer_count; i++) {
        uint8_t public_key[DHT_PUBLIC_KEY_SIZE];

        rc = dht_group_get_offline_peer_public_key(&w->dht, group_number, i, public_key);
        if (rc < 0) {
            vlogW("Carrier: Get peer %lu name from group:%lu error.",
                  i, group_number);
            continue;
        }

        if (memcmp(peerpk, public_key, sizeof(peerpk)) == 0) {
            memset(peer->name, 0, sizeof(peer->name));
            rc = dht_group_get_offline_peer_name(&w->dht, group_number, i, peer->name,
                                                 sizeof(peer->name));
            if (rc < 0) {
                vlogE("Carrier: Get peer %lu name from group:%lu error.", i,
                      group_number);
                carrier_set_error(rc);
                return -1;
            }

            strcpy(peer->userid, peerid);

            return 0;
        }
    }

    vlogE("Carrier: Can not find peer (%s) in group (%lu)", peerid, group_number);
    carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
    return -1;
}

int carrier_get_groups(Carrier *w, CarrierIterateGroupCallback *callback,
                   void *context)
{
    uint32_t group_count;
    uint32_t *group_number_list;
    uint32_t i;

    if (!w || !callback) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    group_count = dht_get_group_count(&w->dht);
    if (!group_count) {
        callback(NULL, context);
        return 0;
    }

    group_number_list = (uint32_t *)alloca(sizeof(uint32_t) * group_count);
    dht_get_group_list(&w->dht, group_number_list);

    for (i = 0; i < group_count; i++) {
        char groupid[CARRIER_MAX_ID_LEN + 1];
        int rc;

        rc = get_groupid_by_number(w, group_number_list[i], groupid,
                                   sizeof(groupid));
        if (rc < 0)
            continue;

        if (!callback(groupid, context))
            return 0;
    }

    callback(NULL, context);
    return 0;
}

int carrier_leave_all_groups(Carrier *w)
{
    uint32_t group_count;
    uint32_t *group_number_list;
    uint32_t i;

    if (!w) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    group_count = dht_get_group_count(&w->dht);
    if (!group_count)
        return 0;

    group_number_list = (uint32_t *)alloca(sizeof(uint32_t) * group_count);
    dht_get_group_list(&w->dht, group_number_list);

    for (i = 0; i < group_count; i++)
        dht_group_leave(&w->dht, group_number_list[i]);

    return 0;
}
