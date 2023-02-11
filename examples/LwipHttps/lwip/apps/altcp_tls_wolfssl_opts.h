/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file contains options for an wolfSSL port of the TLS layer.
 */

/*
 * This file is modified from "altcp_tls_mbedtls_opts.h".
 *
 * Author: onelife <onelife.real[at]gmail.com>
 *
 */
#ifndef LWIP_HDR_ALTCP_WOLFSSL_OPTS_H
#define LWIP_HDR_ALTCP_WOLFSSL_OPTS_H

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

/** LWIP_ALTCP_TLS_WOLFSSL==1: use wolfSSL for TLS support for altcp API
 * wolfSSL include directory must be reachable via include search path
 */
#ifndef LWIP_ALTCP_TLS_WOLFSSL
#define LWIP_ALTCP_TLS_WOLFSSL                        0
#endif

/** Configure debug level of this file */
#ifndef ALTCP_WOLFSSL_DEBUG
#define ALTCP_WOLFSSL_DEBUG                           LWIP_DBG_OFF
#endif

/** Set a session timeout in seconds for the basic session cache
 * ATTENTION: Using a session cache can lower security by reusing keys!
 */
#ifndef ALTCP_WOLFSSL_SESSION_CACHE_TIMEOUT_SECONDS
#define ALTCP_WOLFSSL_SESSION_CACHE_TIMEOUT_SECONDS   0
#endif

#endif /* LWIP_ALTCP */

#endif /* LWIP_HDR_ALTCP_WOLFSSL_OPTS_H */
