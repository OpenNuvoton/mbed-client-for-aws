/*
 * AWS IoT Over-the-air Update v2.0.0 (Release Candidate)
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

/**
 * @file ota_os_mbed.c
 * @brief Example implementation of the OTA OS Functional Interface for Mbed.
 */

/* Standard Includes.*/
#include <stdlib.h>
#include <string.h>

/* OTA OS Mbed Interface Includes.*/
#include "ota_os_mbed.h"

/* OTA Library include. */
extern "C" {
#include "ota_private.h"
}

/* OTA Event queue size. */
#define MAX_MESSAGES      10

struct OtaEventContext
{
    typedef rtos::Mail<OtaEventMsg_t, MAX_MESSAGES>   mailbox_t;

    OtaEventContext() :
        mailbox(nullptr)
    {
    }

    ~OtaEventContext()
    {
        Mbed_OtaDeinitEvent(this);
    }

    uint64_t        mailbox_block[(sizeof(mailbox_t) + 7) / 8];
    mailbox_t *     mailbox;
};

struct OtaTimerContext
{
    typedef Event<void(OtaTimerId_t)>   event_t;

    OtaTimerContext()
    {
        int32_t i;
        for (i = 0; i < OtaNumOfTimers; i ++) {
            events[i] = nullptr;
        }
    }

    ~OtaTimerContext()
    {
        int32_t i;
        for (i = 0; i < OtaNumOfTimers; i ++) {
            Mbed_OtaDeleteTimer((OtaTimerId_t) i);
        }
    }

    uint64_t        events_blocks[OtaNumOfTimers][(sizeof(event_t) + 7) / 8];
    event_t *       events[OtaNumOfTimers];
};

/* OTA OS porting layer doesn't define or actually use event/timer context (interface
 * design drawback?). Still make code context-aware for future enhancement. */
static OtaEventContext ota_evt_ctx_inst;
static OtaTimerContext ota_tmr_ctx_inst;

OtaOsStatus_t Mbed_OtaInitEvent( OtaEventContext_t * pEventCtx )
{
    MBED_ASSERT(pEventCtx == nullptr);
    pEventCtx = &ota_evt_ctx_inst;

    /* Check parameter validity */
    MBED_ASSERT(pEventCtx != nullptr);

    /* Check un-deinited session */
    if (pEventCtx->mailbox) {
        LogWarn( ("Mailbox control block un-deinited but reused for new session. Deinit for previous session first.") );
        pEventCtx->mailbox->~Mail<OtaEventMsg_t, MAX_MESSAGES>();
        pEventCtx->mailbox = nullptr;
    }

    /* Construct mailbox */
    pEventCtx->mailbox = new (pEventCtx->mailbox_block) OtaEventContext_t::mailbox_t;

    LogDebug( ( "OTA Event Queue created." ) );
    return OtaOsSuccess;
}

OtaOsStatus_t Mbed_OtaSendEvent( OtaEventContext_t * pEventCtx,
                                  const void * pEventMsg,
                                  unsigned int timeout )
{
    MBED_ASSERT(pEventCtx == nullptr);
    pEventCtx = &ota_evt_ctx_inst;

    /* Check parameter validity */
    MBED_ASSERT(pEventCtx != nullptr && pEventCtx->mailbox != nullptr);
    MBED_ASSERT(pEventMsg != nullptr);

    /* Send the event to OTA event queue.*/
    OtaEventMsg_t *mail = pEventCtx->mailbox->try_alloc_for(std::chrono::milliseconds(timeout));
    if (mail == nullptr) {
        LogError( ( "Failed to send event to OTA Event Queue: "
                    "Out of mail pool" ) );                    
        return OtaOsEventQueueSendFailed;
    }

    memcpy(mail, pEventMsg, sizeof(OtaEventMsg_t));

    /* Always succeed. Return value is deprecated. */
    pEventCtx->mailbox->put(mail);

    LogDebug( ( "OTA Event Sent." ) );
    return OtaOsSuccess;
}

OtaOsStatus_t Mbed_OtaReceiveEvent( OtaEventContext_t * pEventCtx,
                                     void * pEventMsg,
                                     uint32_t timeout )
{
    MBED_ASSERT(pEventCtx == nullptr);
    pEventCtx = &ota_evt_ctx_inst;

    /* Check parameter validity */
    MBED_ASSERT(pEventCtx != nullptr && pEventCtx->mailbox != nullptr);
    MBED_ASSERT(pEventMsg != nullptr);

    /* Receive the next event from OTA event queue.*/
    OtaEventMsg_t *mail = pEventCtx->mailbox->try_get_for(std::chrono::milliseconds(timeout));
    if (mail == nullptr) {
        /* LogDebug instead of LogError; otherwise, easily meet annoying log messages with normal log level */
        LogDebug( ( "Failed to receive OTA Event: " 
                    "Possibly mailbox empty ") );
        return OtaOsEventQueueReceiveFailed;
    }

    memcpy(pEventMsg, mail, sizeof(OtaEventMsg_t));

    pEventCtx->mailbox->free(mail);
    mail = nullptr;

    LogDebug( ( "OTA Event received." ) );
    return OtaOsSuccess;
}

OtaOsStatus_t Mbed_OtaDeinitEvent( OtaEventContext_t * pEventCtx )
{
    MBED_ASSERT(pEventCtx == nullptr);
    pEventCtx = &ota_evt_ctx_inst;

    /* Check parameter validity */
    MBED_ASSERT(pEventCtx != nullptr);

    /* Validate mailbox */
    if (pEventCtx->mailbox == nullptr) {
        LogWarn( ("Parameter check failed: mailbox is nullptr.") );
        return OtaOsEventQueueDeleteFailed;
    }

    /* Destruct maiilbox */
    pEventCtx->mailbox->~Mail<OtaEventMsg_t, MAX_MESSAGES>();
    pEventCtx->mailbox = nullptr;

    LogDebug( ( "OTA Event queue deleted." ) );
    return OtaOsSuccess;
}

OtaOsStatus_t Mbed_OtaStartTimer( OtaTimerId_t otaTimerId,
                                   const char * const pTimerName,
                                   const uint32_t timeout,
                                   OtaTimerCallback_t callback )
{
    /* Check parameter validity */
    MBED_ASSERT(otaTimerId >= 0 && otaTimerId < OtaNumOfTimers);

    OtaTimerContext::event_t *pEvent = ota_tmr_ctx_inst.events[otaTimerId];

    /* Dependent on timer constructed or not, go either: */
    if (pEvent != nullptr) {
        /* Following AWS IoT OTA RI, restart = reset + start */
        pEvent->cancel();
    } else {
        /* Create new timer, using the shared event queue */
        pEvent = new (&ota_tmr_ctx_inst.events_blocks[otaTimerId]) OtaTimerContext::event_t(mbed_event_queue(), callback);
        ota_tmr_ctx_inst.events[otaTimerId] = pEvent;
    }

    MBED_ASSERT(pEvent != nullptr);

    /* Set delay */
    pEvent->delay(std::chrono::milliseconds(timeout));

    /* Disable periodic call */
    /* API to disable the periodic call does not exist. Setting to the initial value (-1). */
    pEvent->period(std::chrono::milliseconds(-1));

    auto ret = pEvent->post(otaTimerId);
    if (ret == 0) {
        LogError( ( "Failed to create OTA timer: "
                    "Failed to post to event queue: "
                    "Probably out of memory" ) );
        return OtaOsTimerCreateFailed;
    }

    LogDebug( ( "OTA Timer started." ) );
    return OtaOsSuccess;
}

OtaOsStatus_t Mbed_OtaStopTimer( OtaTimerId_t otaTimerId )
{
    /* Check parameter validity */
    MBED_ASSERT(otaTimerId >= 0 && otaTimerId < OtaNumOfTimers);

    OtaTimerContext::event_t *pEvent = ota_tmr_ctx_inst.events[otaTimerId];
    if (pEvent == nullptr) {
        LogWarn( ("Try to stop un-started timer: %d.", otaTimerId) );
        return OtaOsTimerStopFailed;
    }

    /* Cancel previous timer */
    pEvent->cancel();

    LogDebug( ( "OTA Timer Stopped for Timerid=%i.", otaTimerId ) );
    return OtaOsSuccess;
}

OtaOsStatus_t Mbed_OtaDeleteTimer( OtaTimerId_t otaTimerId )
{
    /* Check parameter validity */
    MBED_ASSERT(otaTimerId >= 0 && otaTimerId < OtaNumOfTimers);

    OtaTimerContext::event_t *pEvent = ota_tmr_ctx_inst.events[otaTimerId];

    /* Validate timer */
    if (pEvent == nullptr) {
        LogWarn( ("Parameter check failed: timer is nullptr.") );
        return OtaOsTimerDeleteFailed;
    }

    MBED_ASSERT(pEvent != nullptr);

    /* Cancel previous timer and destruct it */
    pEvent->cancel();
    pEvent->~Event<void(OtaTimerId_t)>();
    ota_tmr_ctx_inst.events[otaTimerId] = pEvent = nullptr;

    LogDebug( ( "OTA Timer deleted." ) );
    return OtaOsSuccess;
}

void * STDC_Malloc( size_t size )
{
    /* Use standard C malloc.*/

    /* MISRA rule 21.3 prohibits the use of malloc and free from stdlib.h because of undefined
     * behavior. The design for our OTA library is to let user choose whether they want to pass
     * buffers to us or not. Dynamic allocation is used only when they do not provide these buffers.
     * Further, we have unit tests with memory, and address sanitizer enabled to ensure we're not
     * leaking or free memory that's not dynamically allocated.  */
    /* coverity[misra_c_2012_rule_21_3_violation]. */
    return malloc( size );
}

void STDC_Free( void * ptr )
{
    /* Use standard C free.*/

    /* See explanation in STDC_Malloc. */
    /* coverity[misra_c_2012_rule_21_3_violation]. */
    free( ptr );
}
