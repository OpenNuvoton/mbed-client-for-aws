/*
 * FreeRTOS Crypto V1.1.1
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
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

 /* C runtime includes. */
#include <string.h>
#include <stdbool.h>

/* Mbed includes. */
#include "mbed.h"
#include "mbed_trace.h"

/* mbedTLS includes. */

#if !defined( MBEDTLS_CONFIG_FILE )
    #include "mbedtls/config.h"
#else
    #include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha1.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
/* Threading mutex implementations for mbedTLS. */
#include "mbedtls/threading.h"

#include "iot_crypto.h"

#define CRYPTO_PRINT( X )    printf( X )


/**
 * @brief Internal signature verification context structure
 */
typedef struct SignatureVerificationState
{
    uint8_t xAsymmetricAlgorithm;
    uint8_t xHashAlgorithm;
    mbedtls_sha1_context xSHA1Context;
    mbedtls_sha256_context xSHA256Context;
} SignatureVerificationState_t, * SignatureVerificationStatePtr_t;


/*-----------------------------------------------------------*/
/*--------- mbedTLS threading functions for Mbed OS --------*/
/*--------- Set MBEDTLS_THREADING_ALT in PKCS11 module ------*/
/*-----------------------------------------------------------*/

/**
 * @brief Implementation of mbedtls_mutex_init for thread-safety.
 *
 */
void aws_mbedtls_mutex_init( mbedtls_threading_mutex_t * mutex )
{
    // ToDo: mutex->mutex = RTOS mutex create;

    if( mutex->mutex == NULL )
    {
         CRYPTO_PRINT( ( "Failed to initialize mbedTLS mutex.\r\n" ) );
    }
}

/**
 * @brief Implementation of mbedtls_mutex_free for thread-safety.
 *
 */
void aws_mbedtls_mutex_free( mbedtls_threading_mutex_t * mutex )
{
    if( mutex->mutex != NULL )
    {
        //ToDO: RTOS delete mutex
        mutex->mutex = NULL;
    }
}

/**
 * @brief Implementation of mbedtls_mutex_lock for thread-safety.
 *
 * @return 0 if successful, MBEDTLS_ERR_THREADING_MUTEX_ERROR if timeout,
 * MBEDTLS_ERR_THREADING_BAD_INPUT_DATA if the mutex is not valid.
 */
int aws_mbedtls_mutex_lock( mbedtls_threading_mutex_t * mutex )
{
    int ret = MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    if( mutex->mutex != NULL )
    {
        // ToDo: RTOS lock mutex
    }

    return ret;
}

/**
 * @brief Implementation of mbedtls_mutex_unlock for thread-safety.
 *
 * @return 0 if successful, MBEDTLS_ERR_THREADING_MUTEX_ERROR if timeout,
 * MBEDTLS_ERR_THREADING_BAD_INPUT_DATA if the mutex is not valid.
 */
int aws_mbedtls_mutex_unlock( mbedtls_threading_mutex_t * mutex )
{
    int ret = MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    if( mutex->mutex != NULL )
    {
        // ToDo: RTOS unlock mutex
    }

    return ret;
}

/*-----------------------------------------------------------*/

/**
 * @brief Verifies a cryptographic signature based on the signer
 * certificate, hash algorithm, and the data that was signed.
 */
static bool prvVerifySignature( char * pcSignerCertificate,
                                      size_t xSignerCertificateLength,
                                      uint8_t xHashAlgorithm,
                                      uint8_t * pucHash,
                                      size_t xHashLength,
                                      uint8_t * pucSignature,
                                      size_t xSignatureLength )
{
    bool result = true;
    mbedtls_x509_crt xCertCtx;
    mbedtls_md_type_t xMbedHashAlg = MBEDTLS_MD_SHA256;


    memset( &xCertCtx, 0, sizeof( mbedtls_x509_crt ) );

    /*
     * Map the hash algorithm
     */
    if( cryptoHASH_ALGORITHM_SHA1 == xHashAlgorithm )
    {
        xMbedHashAlg = MBEDTLS_MD_SHA1;
    }

    /*
     * Decode and create a certificate context
     */
    mbedtls_x509_crt_init( &xCertCtx );

    if( 0 != mbedtls_x509_crt_parse(
            &xCertCtx, ( const unsigned char * ) pcSignerCertificate, xSignerCertificateLength ) )
    {
        result = false;
    }

    /*
     * Verify the signature using the public key from the decoded certificate
     */
    if( true == result )
    {
        if( 0 != mbedtls_pk_verify(
                &xCertCtx.pk,
                xMbedHashAlg,
                pucHash,
                xHashLength,
                pucSignature,
                xSignatureLength ) )
        {
            result = false;
        }
    }

    /*
     * Clean-up
     */
    mbedtls_x509_crt_free( &xCertCtx );

    return result;
}

void CRYPTO_ConfigureThreading( void )
{
    /* Configure mbedtls to use Mbed-OS mutexes. */
    mbedtls_threading_set_alt( aws_mbedtls_mutex_init,
                               aws_mbedtls_mutex_free,
                               aws_mbedtls_mutex_lock,
                               aws_mbedtls_mutex_unlock );
}

/*
 * Interface routines
 */

void CRYPTO_Init( void )
{
    // Already configure threading in PKCS11 module, so not call mbedtls_threading_set_alt() here
    // CRYPTO_ConfigureThreading();
}


/**
 * @brief Creates signature verification context.
 */
bool CRYPTO_SignatureVerificationStart( void ** ppvContext,
                                              uint8_t xAsymmetricAlgorithm,
                                              uint8_t xHashAlgorithm )
{
    bool result = true;
    SignatureVerificationState_t * pxCtx = NULL;

    /*
     * Allocate the context
     */
    if( NULL == ( pxCtx = ( SignatureVerificationStatePtr_t ) malloc(
                      sizeof( *pxCtx ) ) ) ) /*lint !e9087 Allow casting void* to other types. */
    {
        result = false;
    }

    if( result == true )
    {
        *ppvContext = pxCtx;

        /*
         * Store the algorithm identifiers
         */
        pxCtx->xAsymmetricAlgorithm = xAsymmetricAlgorithm;
        pxCtx->xHashAlgorithm = xHashAlgorithm;

        /*
         * Initialize the requested hash type
         */
        if( cryptoHASH_ALGORITHM_SHA1 == pxCtx->xHashAlgorithm )
        {
            mbedtls_sha1_init( &pxCtx->xSHA1Context );
            ( void ) mbedtls_sha1_starts_ret( &pxCtx->xSHA1Context );
        }
        else
        {
            mbedtls_sha256_init( &pxCtx->xSHA256Context );
            ( void ) mbedtls_sha256_starts_ret( &pxCtx->xSHA256Context, 0 );
        }
    }

    return result;
}

/**
 * @brief Adds bytes to an in-progress hash for subsequent signature
 * verification.
 */
void CRYPTO_SignatureVerificationUpdate( void * pvContext,
                                         const uint8_t * pucData,
                                         size_t xDataLength )
{
    SignatureVerificationState_t * pxCtx = ( SignatureVerificationStatePtr_t ) pvContext; /*lint !e9087 Allow casting void* to other types. */

    /*
     * Add the data to the hash of the requested type
     */
    if( cryptoHASH_ALGORITHM_SHA1 == pxCtx->xHashAlgorithm )
    {
        ( void ) mbedtls_sha1_update_ret( &pxCtx->xSHA1Context, pucData, xDataLength );
    }
    else
    {
        ( void ) mbedtls_sha256_update_ret( &pxCtx->xSHA256Context, pucData, xDataLength );
    }
}

/**
 * @brief Performs signature verification on a cryptographic hash.
 */
bool CRYPTO_SignatureVerificationFinal( void * pvContext,
                                              char * pcSignerCertificate,
                                              size_t xSignerCertificateLength,
                                              uint8_t * pucSignature,
                                              size_t xSignatureLength )
{
    bool result = false;

    if( pvContext != NULL )
    {
        SignatureVerificationStatePtr_t pxCtx = ( SignatureVerificationStatePtr_t ) pvContext; /*lint !e9087 Allow casting void* to other types. */
        uint8_t ucSHA1or256[ cryptoSHA256_DIGEST_BYTES ];                                      /* Reserve enough space for the larger of SHA1 or SHA256 results. */
        uint8_t * pucHash = NULL;
        size_t xHashLength = 0;

        if( ( pcSignerCertificate != NULL ) &&
            ( pucSignature != NULL ) &&
            ( xSignerCertificateLength > 0UL ) &&
            ( xSignatureLength > 0UL ) )
        {
            /*
             * Finish the hash
             */
            if( cryptoHASH_ALGORITHM_SHA1 == pxCtx->xHashAlgorithm )
            {
                ( void ) mbedtls_sha1_finish_ret( &pxCtx->xSHA1Context, ucSHA1or256 );
                pucHash = ucSHA1or256;
                xHashLength = cryptoSHA1_DIGEST_BYTES;
            }
            else
            {
                ( void ) mbedtls_sha256_finish_ret( &pxCtx->xSHA256Context, ucSHA1or256 );
                pucHash = ucSHA1or256;
                xHashLength = cryptoSHA256_DIGEST_BYTES;
            }

            /*
             * Verify the signature
             */
            result = prvVerifySignature( pcSignerCertificate,
                                          xSignerCertificateLength,
                                          pxCtx->xHashAlgorithm,
                                          pucHash,
                                          xHashLength,
                                          pucSignature,
                                          xSignatureLength );
        }
        else
        {
            /* Allow function to be called with only the context pointer for cleanup after a failure. */
        }

        /*
         * Clean-up
         */
        free( pxCtx );
    }

    return result;
}
