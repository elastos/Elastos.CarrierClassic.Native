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

#include "carrier.h"
#include "carrier_error.h"
#include "extensions_helper.h"
#include "hashtable_extensions.h"

int carrier_register_extension(Carrier *w, const char *name,
                               CarrierExtension *ext, CarrierCallbacks *callbacks)
{
    ExtensionHolder *holder;

    if (!w || !name || !*name || strlen(name) > CARRIER_MAX_EXTENSION_NAME_LEN) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return -1;
    }

    if (extensions_exist(w->exts, name)) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_ALREADY_EXIST));
        return -1;
    }

    holder = (ExtensionHolder *)rc_alloc(sizeof(ExtensionHolder), NULL);
    if (!holder) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_OUT_OF_MEMORY));
        return -1;
    }

    strcpy(holder->name, name);
    holder->ext = ext;
    if (callbacks)
        holder->callbacks = *callbacks;

    holder->apis.is_friend = extension_is_friend;
    holder->apis.invite_friend = extension_invite_friend;
    holder->apis.reply_friend_invite = extension_reply_friend_invite;

    ext->scope = holder;
    ext->apis = &holder->apis;
    ext->carrier = w;

    extensions_put(w->exts, holder);
    deref(holder);

    return 0;
}

CarrierExtension *carrier_get_extension(Carrier *w, const char *name)
{
    ExtensionHolder *holder;
    CarrierExtension *ext;

    if (!w || !name || !*name) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_INVALID_ARGS));
        return NULL;
    }

    holder = extensions_get(w->exts, name);
    if (!holder) {
        carrier_set_error(CARRIER_GENERAL_ERROR(ERROR_NOT_EXIST));
        return NULL;
    }

    ext = holder->ext;
    deref(holder);

    return ext;
}

void carrier_unregister_extension(Carrier *w, const char *name)
{
    ExtensionHolder *holder;

    if (!w || !name || !*name) {
        return;
    }

    holder = extensions_remove(w->exts, name);
    if (holder) {
        holder->ext->scope = NULL;
        deref(holder);
    }
}
