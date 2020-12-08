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
#include <string.h>
#include <pthread.h>

#include <crystal.h>

#include "carrier_error.h"

#if defined(_WIN32) || defined(_WIN64)
#define __thread        __declspec(thread)
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
static __thread int carrier_error;
#elif defined(__APPLE__)
#include <pthread.h>
static pthread_once_t carrier_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t carrier_error;
static void carrier_setup_error(void)
{
    (void)pthread_key_create(&carrier_error, NULL);
}
#else
#error "Unsupported OS yet"
#endif

int carrier_get_error(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
    return carrier_error;
#elif defined(__APPLE__)
    return (int)pthread_getspecific(carrier_error);
#else
#error "Unsupported OS yet"
#endif
}

void carrier_clear_error(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
    carrier_error = CARRIER_SUCCESS;
#elif defined(__APPLE__)
    (void)pthread_setspecific(carrier_error, 0);
#else
#error "Unsupported OS yet"
#endif
}

void carrier_set_error(int err)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
    carrier_error = err;
#elif defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
    (void)pthread_once(&carrier_key_once, carrier_setup_error);
    (void)pthread_setspecific(carrier_error, (void*)err);
#pragma GCC diagnostic pop
#else
#error "Unsupported OS yet"
#endif
}

typedef struct ErrorDesc {
    int errcode;
    const char *errdesc;
} ErrorDesc;

static
const ErrorDesc error_codes[] = {
    { ERROR_INVALID_ARGS,                "Invalid argument(s)"     },
    { ERROR_OUT_OF_MEMORY,               "Out of memory"           },
    { ERROR_BUFFER_TOO_SMALL,            "Too small buffer size"   },
    { ERROR_BAD_PERSISTENT_DATA,         "Bad persistent data"     },
    { ERROR_INVALID_PERSISTENCE_FILE,    "Invalid persistent file" },
    { ERROR_INVALID_CONTROL_PACKET,      "Invalid control packet"  },
    { ERROR_INVALID_CREDENTIAL,          "Invalid credential"      },
    { ERROR_ALREADY_RUN,                 "Carrier is already being running" },
    { ERROR_NOT_BEING_READY,             "Carrier is not being ready"    },
    { ERROR_NOT_EXIST,                   "Friend does not exist"   },
    { ERROR_ALREADY_EXIST,               "Friend already exists"   },
    { ERROR_NO_MATCHED_REQUEST,          "Unmatched request"       },
    { ERROR_INVALID_USERID,              "Invalid carrier userid"  },
    { ERROR_INVALID_NODEID,              "Invalid carrier nodeid"  },
    { ERROR_WRONG_STATE,                 "Being in wrong state"    },
    { ERROR_BEING_BUSY,                  "Instance is being busy"  },
    { ERROR_LANGUAGE_BINDING,            "Language binding error"  },
    { ERROR_ENCRYPT,                     "Encrypt error"           },
    { ERROR_SDP_TOO_LONG,                "SDP is too long"         },
    { ERROR_INVALID_SDP,                 "Invalid SDP"             },
    { ERROR_NOT_IMPLEMENTED,             "Not implemented yet"     },
    { ERROR_LIMIT_EXCEEDED,              "Exceeding the limit"     },
    { ERROR_PORT_ALLOC,                  "Allocate port error"     },
    { ERROR_BAD_PROXY_TYPE,              "Bad proxy type"          },
    { ERROR_BAD_PROXY_HOST,              "Bad proxy host"          },
    { ERROR_BAD_PROXY_PORT,              "Bad proxy port"          },
    { ERROR_PROXY_NOT_AVAILABLE,         "No proxy available"      },
    { ERROR_ENCRYPTED_PERSISTENT_DATA,   "Load encrypted persistent data error"},
    { ERROR_BAD_BOOTSTRAP_HOST,          "Bad bootstrap host"      },
    { ERROR_BAD_BOOTSTRAP_PORT,          "Bad bootstrap port"      },
    { ERROR_TOO_LONG,                    "Data content too long"   },
    { ERROR_ADD_SELF,                    "Try add myself as friend"},
    { ERROR_BAD_ADDRESS,                 "Bad carrier node address"},
    { ERROR_FRIEND_OFFLINE,              "Friend is being offline" },
    { ERROR_UNKNOWN,                     "Unknown error"           }
};

static int general_error(int errcode, char *buf, size_t len)
{
    int size = sizeof(error_codes)/sizeof(ErrorDesc);
    int i;

    for (i = 0; i < size; i++) {
        if (errcode == error_codes[i].errcode)
            break;
    }

    if (i >= size || len <= strlen(error_codes[i].errdesc))
        return CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS);

    strcpy(buf, error_codes[i].errdesc);
    return 0;
}

static int system_error(int errcode, char *buf, size_t len)
{
    int rc;
#if defined(_WIN32) || defined(_WIN64)
    rc = strerror_s(buf, len, errcode);
#else
    rc = strerror_r(errcode, buf, len);
#endif
    if (rc < 0)
        return CARRIER_SYS_ERROR(ERROR_INVALID_ARGS);

    return 0;
}

static int dht_error(int errcode, char *buf, size_t len)
{
    int size = sizeof(error_codes)/sizeof(ErrorDesc);
    int i;

    for (i = 0; i < size; i++) {
        if (errcode == error_codes[i].errcode)
            break;
    }

    if (i >= size || len <= strlen(error_codes[i].errdesc))
        return CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS);

    strcpy(buf, error_codes[i].errdesc);
    return 0;
}

static int express_error(int errcode, char *buf, size_t len)
{
    int size = sizeof(error_codes)/sizeof(ErrorDesc);
    int i;

    for (i = 0; i < size; i++) {
        if (errcode == error_codes[i].errcode)
            break;
    }

    if (i >= size || len <= strlen(error_codes[i].errdesc))
        return CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS);

    strcpy(buf, error_codes[i].errdesc);
    return 0;
}

typedef struct FacilityDesc {
    const char *desc;
    strerror_t errstring;
} FacilityDesc;

static FacilityDesc facility_codes[] = {
    { "[General] ",         general_error },    //FACILITY_GENERAL
    { "[System] ",          system_error },     //FACILITY_SYS
    { "Reserved facility",  NULL },             //FACILITY_RESERVED1
    { "Reserved facility",  NULL },             //FACILITY_RESERVED2
    { "[ICE] ",             NULL },             //FACILITY_ICE
    { "[DHT] ",             dht_error },        //FACILITY_DHT
    { "[Express] ",         express_error },    //FACILITY_EXPRESS
};

char *carrier_get_strerror(int error, char *buf, size_t len)
{
    FacilityDesc *faci_desc;
    bool negative;
    int facility;
    int errcode;
    int rc = 0;
    size_t desc_len;
    char *p = buf;

    negative = !!(error & 0x80000000);
    facility = (error >> 24) & 0x0F;
    errcode  = error & 0x00FFFFFF;

    if (!buf || !negative || facility <= 0 ||
        facility > sizeof(facility_codes)/sizeof(FacilityDesc)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return NULL;
    }

    faci_desc = (FacilityDesc*)&facility_codes[facility - 1];
    desc_len = strlen(faci_desc->desc);
    if (len < desc_len) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_BUFFER_TOO_SMALL));
        return NULL;
    }

    strcpy(p, faci_desc->desc);
    p += desc_len;
    len -= desc_len;

    if (faci_desc->errstring)
        rc = faci_desc->errstring(errcode, p, len);

    if (rc < 0) {
        carrier_set_error(rc);
        return NULL;
    }

    return buf;
}

int carrier_register_strerror(int facility, strerror_t user_strerr)
{
    FacilityDesc *faci_desc;

    if (facility <= 0 || facility > FACILITY_DHT) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    faci_desc = (FacilityDesc*)&facility_codes[facility - 1];
    if (!faci_desc->errstring)
        faci_desc->errstring = user_strerr;

    return 0;
}
