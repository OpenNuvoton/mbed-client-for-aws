/*
 * AWS IoT Device SDK for Embedded C 202012.01
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef TRANSPORT_MBED_BASE_H
#define TRANSPORT_MBED_BASE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Transport includes. */
#include "transport_interface.h"

/**
 * @brief NetworkContext as base.
 */
struct NetworkContext
{
    NetworkContext() :
        sendTimeoutMs(0),
        recvTimeoutMs(0)
    {
    }

    uint32_t    sendTimeoutMs;
    uint32_t    recvTimeoutMs;
};

/**
 * @brief The format for remote server host and port on this system.
 */
typedef struct {
    const char *hostname;
    uint16_t port;
} ServerInfo_t;

#ifdef __cplusplus
}
#endif

#endif /* ifndef IOT_PLATFORM_TYPES_TEMPLATE_H_ */
