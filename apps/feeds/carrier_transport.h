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

#ifndef __CARRIER_TRANSPORT_H__
#define __CARRIER_TRANSPORT_H__

#include <stddef.h>
#include <ela_carrier.h>

typedef struct CarrierTransport CarrierTransport;

CarrierTransport *carrier_transport_create(ElaCarrier *c,
                                           void (*on_data)(CarrierTransport *ct,
                                                           const char *from,
                                                           const void *msg,
                                                           size_t len,
                                                           void *context),
                                           void *context);

int carrier_transport_send_message(CarrierTransport *ct, const char *to,
                                   const void *msg, size_t len);

void carrier_transport_friend_disconnected(CarrierTransport *ct, const char *friendid);

void carrier_transport_message_received(CarrierTransport *ct, const char *from,
                                        const void *msg, size_t len);

void carrier_transport_delete(CarrierTransport *ct);

#endif // __CARRIER_TRANSPORT_H__
