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

#ifndef __CARRIER_EXTENSION_APIS_H__
#define __CARRIER_EXTENSION_APIS_H__

#include <assert.h>
#include <string.h>
#include "carrier.h"
#include "carrier_impl.h"
#include "carrier_extension.h"

static
bool extension_is_friend(CarrierExtension *ext, const char *address)
{
    if (!ext || !address || strlen(address) >= ELA_MAX_ID_LEN * 2 + 2) {
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_INVALID_ARGS));
        return false;
    }

    if (!ext->scope) {
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_NOT_EXIST));
        return false;
    }

    if (!ela_id_is_valid(address)) {
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_INVALID_USERID));
        return false;
    }

    return ela_is_friend(ext->carrier, address);
}

static
int extension_invite_friend(CarrierExtension *ext, const char *address,
                            const char *bundle,
                            const char *data, size_t len,
                            ElaFriendInviteResponseCallback *callback,
                            void *context)
{
    ExtensionHolder *holder;
    char addr[ELA_MAX_ID_LEN * 2 + CARRIER_MAX_EXTENSION_NAME_LEN + 8];

    if (!ext || !data || len == 0 ||
        !address || strlen(address) >= ELA_MAX_ID_LEN*2 + 2 ) {
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_INVALID_ARGS));
        return false;
    }

    if (!ext->scope) {
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_NOT_EXIST));
        return -1;
    }

    holder = (ExtensionHolder *)ext->scope;

    strcpy(addr, (const char *)address);
    strcat(addr, ":");
    strcat(addr, holder->name);

    return ela_invite_friend(ext->carrier, addr, bundle, data, len, callback,
                             context);
}

static
int extension_reply_friend_invite(CarrierExtension *ext, const char *address,
                                  const char *bundle,
                                  int status, const char *reason,
                                  const char *data, size_t len)
{
    ExtensionHolder *holder;
    char addr[ELA_MAX_ID_LEN * 2 + CARRIER_MAX_EXTENSION_NAME_LEN + 8];

    if (!ext || (status && !reason) || (!status && (!data || len == 0)) ||
        !address || strlen(address) >= ELA_MAX_ID_LEN*2 + 2 ) {
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_INVALID_ARGS));
        return -1;
    }

    if (!ext->scope) {
        ela_set_error(ELA_GENERAL_ERROR(ELAERR_NOT_EXIST));
        return -1;
    }

    holder = (ExtensionHolder *)ext->scope;

    strcpy(addr, (const char *)address);
    strcat(addr, ":");
    strcat(addr, holder->name);

    return ela_reply_friend_invite(ext->carrier, addr, bundle, status, reason,
                                   data, len);
}

#endif //__CARRIER_EXTENSION_APIS_H__
