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

#ifndef __ELASTOS_CARRIER_EXTENSION_H__
#define __ELASTOS_CARRIER_EXTENSION_H__

#include <stdint.h>
#include "carrier.h"

#if defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdocumentation"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \~English
 * Maximum length of carrier extension name.
 */
#define CARRIER_MAX_EXTENSION_NAME_LEN          31

typedef struct CarrierExtension CarrierExtension;

/**
 * \~English
 * The abstract callback APIs for carrier extensions.
 */
typedef struct ExtensionAPIs {
    /**
     * \~English
     * Check if the user with specific address is friend.
     *
     * @param
     *      extension   [in] A handle to the carrier extension instance.
     * @param
     *      address     [in] The target user address to check.
     *
     * @return
     *      true if the user id is friend, or false if not;
     */
    bool (*is_friend)(CarrierExtension *extension, const char *address);

    /**
     * \~English
     * Send invite request to a friend.
     *
     * Application can attach the application defined data within the invite
     * request, and the data will send to target friend.
     *
     * @param
     *      extension   [in] A handle to the carrier extension instance.
     * @param
     *      address     [in] The target address.
     * @param
     *      data        [in] The application defined data send to target user.
     * @param
     *      bundle      [in] The bundle attached to this invite request.
     * @param
     *      len         [in] The data length in bytes.
     * @param
     *      callback    [in] A pointer to CarrierFriendInviteResponseCallback
     *                       function to receive the invite response.
     * @param
     *      context      [in] The application defined context data.
     *
     * @return
     *      0 if the invite request successfully send to the friend.
     *      Otherwise, return -1, and a specific error code can be
     *      retrieved by calling carrier_get_error().
     */
    int (*invite_friend)(CarrierExtension *extension, const char *address,
                         const char *bundle,
                         const char *data, size_t len,
                         CarrierFriendInviteResponseCallback *callback,
                         void *context);

    /**
     * \~English
     * Reply the friend invite request.
     *
     * This function will send a invite response to friend.
     *
     * @param
     *      extension   [in] A handle to the carrier extension instance.
     * @param
     *      address     [in] The target address where invite request was from.
     * @param
     *      bundle      [in] The bundle attached to this invite request.
     * @param
     *      status      [in] The status code of the response.
     *                       0 is success, otherwise is error.
     * @param
     *      reason      [in] The error message if status is error, or NULL
     *                       if success.
     * @param
     *      data        [in] The application defined data send to target user.
     *                       If the status is error, this will be ignored.
     * @param
     *      len         [in] The data length in bytes.
     *                       If the status is error, this will be ignored.
     *
     * @return
     *      0 if the invite response successfully send to the friend.
     *      Otherwise, return -1, and a specific error code can be
     *      retrieved by calling carrier_get_error().
     */
    int (*reply_friend_invite)(CarrierExtension *extension, const char *address,
                               const char *bundle,
                               int status, const char *reason,
                               const char *data, size_t len);
} ExtensionAPIs;

/**
 * \~English
 * Carrier base extension structure.
 * Application defined extension must inherit from this base extension.
 * Examples:
 * struct ApplicationDefinedExtension {
 *     CarrierExtension base;
 *     ....
 * };
 */
struct CarrierExtension {
    /**
     * \~English
     * Carrier extension private scope object.
     */
    const void *scope;

    /**
     * \~English
     * Carrier client instance.
     */
    Carrier *carrier;

    /*
     * \~English
     * Carrier APIs table exported to extension applications.
     */
    ExtensionAPIs *apis;
};

/**
 * \~English
 * Regisiter a new extension to carrier instance.
 *
 * @param
 *      carrier     [in] A handle to carrier node instance.
 * @param
 *      name        [in] The name of new extension, should not larger than
 *                       CARRIER_MAX_EXTENSION_NAME.
 * @param
 *      ext         [in] The user defined extension object pointer.
 * @param
 *      callbacks   [in] The extension interested callbacks.
 *                       The callback context is the extension object pointer.
 *
 * @return
 *      0 if the extension register successfully. Otherwise, return -1,
 *      and a specific error code can be retrieved by calling
 *      carrier_get_error().
 */
CARRIER_API
int carrier_register_extension(Carrier *carrier, const char *name,
                               CarrierExtension *ext,
                               CarrierCallbacks *callbacks);

/**
 * \~English
 * Retrieve the extension object pointer according to given name.
 *
 * @param
 *      carrier     [in] A handle to carrier node instance.
 * @param
 *      name        [in] The name of new extension.
 *
 * @return
 *      The extension object pointer, or NULL if not exist.
 */
CARRIER_API
CarrierExtension *carrier_get_extension(Carrier *carrier, const char *name);

/**
 * \~English
 * Unregister the extension.
 *
 * @param
 *      carrier     [in] A handle to carrier node instance.
 * @param
 *      name        [in] The name of new extension.
 */
CARRIER_API
void carrier_unregister_extension(Carrier *carrier, const char *name);

#ifdef __cplusplus
}
#endif

#if defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#endif /* __ELASTOS_CARRIER_EXTENSION_H__ */
