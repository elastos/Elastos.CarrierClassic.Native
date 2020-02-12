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

#include <string.h>

#include "jsonrpc.h"

#define is_structured(json) (cJSON_IsObject((json)) || cJSON_IsArray((json)))

int jsonrpc_decode(const void *json, size_t len, cJSON **decoded, JsonRPCType *type)
{
    cJSON *parsed;
    cJSON *jsonrpc;
    cJSON *method;
    cJSON *result;
    cJSON *error;
    cJSON *id;

    parsed = cJSON_Parse(json);
    if (!parsed)
        return -1;

    jsonrpc = cJSON_GetObjectItemCaseSensitive(parsed, "jsonrpc");
    if (!jsonrpc || !cJSON_IsString(jsonrpc) || strcmp(jsonrpc->valuestring, "2.0")) {
        cJSON_Delete(parsed);
        return -1;
    }

    method = cJSON_GetObjectItemCaseSensitive(parsed, "method");
    result = cJSON_GetObjectItemCaseSensitive(parsed, "result");
    error = cJSON_GetObjectItemCaseSensitive(parsed, "error");
    if (!!method + !!result + !!error != 1) {
        cJSON_Delete(parsed);
        return -1;
    }

    id = cJSON_GetObjectItemCaseSensitive(parsed, "id");
    if (id && !cJSON_IsString(id) && !cJSON_IsNumber(id) && !cJSON_IsNull(id)) {
        cJSON_Delete(parsed);
        return -1;
    }

    if (method) {
        cJSON *params;

        if (!cJSON_IsString(method) || !method->valuestring[0]) {
            cJSON_Delete(parsed);
            return -1;
        }

        params = cJSON_GetObjectItemCaseSensitive(parsed, "params");
        if (params && !is_structured(params)) {
            cJSON_Delete(parsed);
            return -1;
        }

        *decoded = parsed;
        *type = id ? JSONRPC_TYPE_REQUEST : JSONRPC_TYPE_NOTIFICATION;
        return 0;
    } else {
        if (!id) {
            cJSON_Delete(parsed);
            return -1;
        }

        if (result) {
            *decoded = parsed;
            *type = JSONRPC_TYPE_SUCCESS_RESPONSE;
            return 0;
        } else {
            cJSON *code;
            cJSON *message;

            code = cJSON_GetObjectItemCaseSensitive(error, "code");
            if (!code || !cJSON_IsNumber(code)) {
                cJSON_Delete(parsed);
                return -1;
            }

            message = cJSON_GetObjectItemCaseSensitive(error, "message");
            if (!message || !cJSON_IsString(message) || !message->valuestring[0]) {
                cJSON_Delete(parsed);
                return -1;
            }

            *decoded = parsed;
            *type = JSONRPC_TYPE_ERROR_RESPONSE;
            return 0;
        }
    }
}

char *jsonrpc_encode_request(const char *method, const cJSON *params, const cJSON *id)
{
    cJSON *rpc;
    char *encoded;

    rpc = cJSON_CreateObject();
    if (!rpc)
        return NULL;

    if (!cJSON_AddStringToObject(rpc, "jsonrpc", "2.0")) {
        cJSON_Delete(rpc);
        return NULL;
    }

    if (!cJSON_AddStringToObject(rpc, "method", method)) {
        cJSON_Delete(rpc);
        return NULL;
    }

    if (params)
        cJSON_AddItemReferenceToObject(rpc, "params", (cJSON *)params);

    cJSON_AddItemReferenceToObject(rpc, "id", (cJSON *)id);

    encoded = cJSON_PrintUnformatted(rpc);
    cJSON_Delete(rpc);

    return encoded;
}

char *jsonrpc_encode_notification(const char *method, const cJSON *params)
{
    cJSON *rpc;
    char *encoded;

    rpc = cJSON_CreateObject();
    if (!rpc)
        return NULL;

    if (!cJSON_AddStringToObject(rpc, "jsonrpc", "2.0")) {
        cJSON_Delete(rpc);
        return NULL;
    }

    if (!cJSON_AddStringToObject(rpc, "method", method)) {
        cJSON_Delete(rpc);
        return NULL;
    }

    if (params)
        cJSON_AddItemReferenceToObject(rpc, "params", (cJSON *)params);

    encoded = cJSON_PrintUnformatted(rpc);
    cJSON_Delete(rpc);

    return encoded;
}

char *jsonrpc_encode_success_response(const cJSON *result, const cJSON *id)
{
    cJSON *rpc;
    char *encoded;

    rpc = cJSON_CreateObject();
    if (!rpc)
        return NULL;

    if (!cJSON_AddStringToObject(rpc, "jsonrpc", "2.0")) {
        cJSON_Delete(rpc);
        return NULL;
    }

    cJSON_AddItemReferenceToObject(rpc, "result", (cJSON *)result);
    cJSON_AddItemReferenceToObject(rpc, "id", (cJSON *)id);

    encoded = cJSON_PrintUnformatted(rpc);
    cJSON_Delete(rpc);

    return encoded;
}

char *jsonrpc_encode_error_response(int code, const char *msg,
                                    const cJSON *data, const cJSON *id)
{
    cJSON *rpc;
    cJSON *error;
    char *encoded;

    rpc = cJSON_CreateObject();
    if (!rpc)
        return NULL;

    if (!cJSON_AddStringToObject(rpc, "jsonrpc", "2.0")) {
        cJSON_Delete(rpc);
        return NULL;
    }

    error = cJSON_AddObjectToObject(rpc, "error");
    if (!error) {
        cJSON_Delete(rpc);
        return NULL;
    }

    if (!cJSON_AddNumberToObject(error, "code", code)) {
        cJSON_Delete(rpc);
        return NULL;
    }

    if (!cJSON_AddStringToObject(error, "message", msg)) {
        cJSON_Delete(rpc);
        return NULL;
    }

    if (data)
        cJSON_AddItemReferenceToObject(error, "data", (cJSON *)data);

    cJSON_AddItemReferenceToObject(rpc, "id", (cJSON *)id);

    encoded = cJSON_PrintUnformatted(rpc);
    cJSON_Delete(rpc);

    return encoded;
}

static struct {
    int code;
    const char *message;
} err_msgs[] = {
    {JSONRPC_EINVALID_REQUEST , "Invalid Request"   },
    {JSONRPC_EMETHOD_NOT_FOUND, "Method not found"  },
    {JSONRPC_EINVALID_PARAMS  , "Invalid Parameters"},
    {JSONRPC_EINTERNAL_ERROR  , "Internal Error"    },
    {JSONRPC_EPARSE_ERROR     , "Parse Error"       }
};

const char *jsonrpc_error_message(int err_code)
{
    int i;

    for (i = 0; i < sizeof(err_msgs) / sizeof(err_msgs[0]); ++i) {
        if (err_code == err_msgs[i].code)
            return err_msgs[i].message;
    }

    return NULL;
}

const char *jsonrpc_get_method(const cJSON *json)
{
    return cJSON_GetObjectItemCaseSensitive(json, "method")->valuestring;
}

const cJSON *jsonrpc_get_params(const cJSON *json)
{
    return cJSON_GetObjectItemCaseSensitive(json, "params");
}

const cJSON *jsonrpc_get_result(const cJSON *json)
{
    return cJSON_GetObjectItemCaseSensitive(json, "result");
}

const cJSON *jsonrpc_get_id(const cJSON *json)
{
    return cJSON_GetObjectItemCaseSensitive(json, "id");
}

int jsonrpc_get_error_code(const cJSON *json)
{
    return (int)cJSON_GetObjectItemCaseSensitive(
                cJSON_GetObjectItemCaseSensitive(json, "error"),
                "code")->valuedouble;
}

const char *jsonrpc_get_error_message(const cJSON *json)
{
    return cJSON_GetObjectItemCaseSensitive(
               cJSON_GetObjectItemCaseSensitive(json, "error"),
               "message")->valuestring;
}
