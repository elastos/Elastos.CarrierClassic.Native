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

#ifndef __CARRIER_TURNSERVER_H__
#define __CARRIER_TURNSERVER_H__

#include "ela_carrier.h"

/**
 * \~English
 * The max length of TURN server host name.
 */
#define CARRIER_MAX_TURN_SERVER_LEN         63

/**
 * \~English
 * The max length of user name to TURN server.
 */
#define CARRIER_MAX_TURN_USERNAME_LEN       127

/**
 * \~English
 * The max length of user password to TURN server.
 */
#define CARRIER_MAX_TURN_PASSWORD_LEN       63

/**
 * \~English
 * The max length of TURN server realm in ICE protocol.
 */
#define CARRIER_MAX_TURN_REALM_LEN          127

/**
 * \~English
 * A structure representing the Carrier TURN server.
 *
 * The TURN server is essential part to help establish sessions between
 * two carrier nodes. And applications can acquire TURN server from
 * carrier network.
 */
typedef struct CarrierTurnServer {
    /**
     * \~English
     * TURN server host.
     */
    char server[CARRIER_MAX_TURN_SERVER_LEN + 1];
    /**
     * \~English
     * TURN server port.
     *
     * The default port is 3478.
     */
    uint16_t port;
    /**
     * \~English
     * TURN server user name.
     */
    char username[CARRIER_MAX_TURN_USERNAME_LEN + 1];
    /**
     * \~English
     * TURN server password.
     */
    char password[CARRIER_MAX_TURN_PASSWORD_LEN + 1];
    /**
     * \~English
     * TURN server realm.
     */
    char realm[CARRIER_MAX_TURN_REALM_LEN + 1];
} CarrierTurnServer;

CARRIER_API
int carrier_get_turn_server(ElaCarrier *carrier, CarrierTurnServer *turn_server);

#endif // __CARRIER_TURNSERVER_H__
