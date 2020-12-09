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

#ifndef __ELASTOS_CARRIER_ERROR_H__
#define __ELASTOS_CARRIER_ERROR_H__

#include "carrier.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \~English
 * Set carrier last error code.
 *
 * @param
 *      err         [in] The error code to be set.
 */
CARRIER_API
void carrier_set_error(int error);

typedef int (*strerror_t)(int errnum, char *, size_t);

/**
 * \~Egnlish
 * register an customized error processing routine for specific error facility
 *
 * @param
 *      facility    [in] facility
 *      strerr      [in] the routine to process error.
 * @return
 *      return 0 on success, otherwise return -1.
 */
CARRIER_API
int carrier_register_strerror(int facility, strerror_t strerr);

#ifdef __cplusplus
}
#endif

#endif /* __ELASTOS_CARRIER_ERROR_H__ */
