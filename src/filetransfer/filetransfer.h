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

#ifndef __FILETRANSFER_H__
#define __FILETRANSFER_H__

#include <stdint.h>
#include <pthread.h>

#ifdef __APPLE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdocumentation"
#endif

#ifdef __APPLE__
#pragma GCC diagnostic pop
#endif

#include <crystal.h>

#include <carrier_extension.h>
#include <carrier_session.h>
#include "carrier_filetransfer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CARRIER_MAX_TRANSFERFILE_COUNT      5
#define CARRIER_MAX_EXTENSION_NAME_LEN      31

#define SENDER                          1
#define RECEIVER                        2

#define _LLUV(val)                      ((unsigned long long)(val))
#define _LLUP(addr)                     ((unsigned long long *)(addr))

typedef struct FileTransferExt          FileTransferExt;
typedef struct FileTransferItem         FileTransferItem;

struct FileTransferExt {
    CarrierExtension        base;

    CarrierFileTransferConnectCallback *connect_callback;
    void                    *connect_context;

    CarrierStreamCallbacks  stream_callbacks;
    linked_hashtable_t             *filereqs;
};

enum {
    FileTransferState_none,
    FileTransferState_standby,
    FileTransferState_transfering,
    FileTransferState_finished,
};

struct FileTransferItem {
    char fileid[CARRIER_MAX_FILE_ID_LEN + 1];
    char *filename;
    uint64_t filesz;

    void *userdata;
    int state;
    int channel;
};

struct CarrierFileTransfer {
    FileTransferExt         *ext;

    char                    address[CARRIER_MAX_EXTENSION_NAME_LEN + CARRIER_MAX_ID_LEN + 2];
    FileTransferItem        files[CARRIER_MAX_TRANSFERFILE_COUNT];

    CarrierSession          *session;
    int                     stream;
    int                     error;
    int                     state;  //CarrierFileTransferConnection.

    CarrierFileTransferCallbacks   callbacks;
    void                    *callbacks_context;

    char                    *sdp;
    size_t                  sdp_len;

    int                     sender_receiver;    // 1: sender. 0: receiver.

    CarrierStreamCallbacks  *stream_callbacks;

    bool                    ready_to_connect;
};

#define item_counts(ft) ((int)(sizeof(ft->files) / sizeof(FileTransferItem)))

static inline
FileTransferItem *get_fileinfo_free(CarrierFileTransfer *ft)
{
    size_t i;
    for (i = 0; i < item_counts(ft); i++) {
        if (ft->files[i].state == FileTransferState_none)
            break;
    }

    return (i < item_counts(ft) ? &ft->files[i] : NULL);
}

static inline
FileTransferItem *get_fileinfo_channel(CarrierFileTransfer *ft, int channel)
{
    size_t i;
    for (i = 0; i < item_counts(ft); i++) {
        if (channel == ft->files[i].channel)
            break;
    }

    return (i < item_counts(ft) ? &ft->files[i] : NULL);
}

static inline
FileTransferItem *get_fileinfo_fileid(CarrierFileTransfer *ft, const char *fileid)
{
    size_t i;
    for (i = 0; i < item_counts(ft); i++) {
        if (strcmp(fileid, ft->files[i].fileid) == 0)
            break;
    }

    return (i < item_counts(ft) ? &ft->files[i] : NULL);
}

static inline
FileTransferItem *get_fileinfo_name(CarrierFileTransfer *ft, const char *filename)
{
    size_t i;
    for (i = 0; i < item_counts(ft); i++) {
        if (strcmp(filename, ft->files[i].filename) == 0)
            break;
    }

    return (i < item_counts(ft) ? &ft->files[i] : NULL);
}

static inline void filename_safe_free(FileTransferItem *item) {
    if (item && item->filename) {
        free(item->filename);
        item->filename = NULL;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* __FILETRANSFER_H__ */
