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

#ifndef __JSONRPC_H__
#define __JSONRPC_H__

#include <cjson/cJSON.h>
#include <stdbool.h>

#define JSONRPC_EINVALID_REQUEST (-32600)
#define JSONRPC_EMETHOD_NOT_FOUND (-32601)
#define JSONRPC_EINVALID_PARAMS (-32602)
#define JSONRPC_EINTERNAL_ERROR (-32603)
#define JSONRPC_EPARSE_ERROR (-32700)

typedef enum {
    JSONRPC_TYPE_REQUEST,
    JSONRPC_TYPE_NOTIFICATION,
    JSONRPC_TYPE_SUCCESS_RESPONSE,
    JSONRPC_TYPE_ERROR_RESPONSE
} JsonRPCType;

int jsonrpc_decode(const void *json, size_t len, cJSON **decoded, JsonRPCType *type);

char *jsonrpc_encode_request(const char *method, const cJSON *params, const cJSON *id);

char *jsonrpc_encode_notification(const char *method, const cJSON *params);

char *jsonrpc_encode_success_response(const cJSON *result, const cJSON *id);

int jsonrpc_get_error_code(const cJSON *json);

char *jsonrpc_encode_error_response(int code, const char *msg,
                                    const cJSON *data, const cJSON *id);

const char *jsonrpc_error_message(int err_code);

const char *jsonrpc_get_method(const cJSON *json);

const cJSON *jsonrpc_get_params(const cJSON *json);

const cJSON *jsonrpc_get_result(const cJSON *json);

const cJSON *jsonrpc_get_id(const cJSON *json);

const char *jsonrpc_get_error_message(const cJSON *json);

#endif // __JSONRPC_H__
