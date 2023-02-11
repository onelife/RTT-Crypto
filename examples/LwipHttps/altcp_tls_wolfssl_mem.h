/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file contains memory management function prototypes for a TLS layer using wolfSSL.
 *
 * Memory management contains:
 * - allocating/freeing altcp_wolfssl_state_t
 * - allocating/freeing memory used in the wolfSSL library
 */

/*
 * This file is modified from "altcp_tls_mbedtls_mem.h".
 *
 * Author: onelife <onelife.real[at]gmail.com>
 *
 */
#ifndef LWIP_HDR_ALTCP_WOLFSSL_MEM_H
#define LWIP_HDR_ALTCP_WOLFSSL_MEM_H

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/altcp_tls_wolfssl_opts.h"

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL

#include "altcp_tls_wolfssl_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

void altcp_wolfssl_mem_init(void);
altcp_wolfssl_state_t *altcp_wolfssl_alloc(void *conf);
void altcp_wolfssl_free(void *conf, altcp_wolfssl_state_t *state);
void *altcp_wolfssl_alloc_config(void);
void altcp_wolfssl_free_config(void *item);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL */
#endif /* LWIP_ALTCP */
#endif /* LWIP_HDR_ALTCP_WOLFSSL_MEM_H */
