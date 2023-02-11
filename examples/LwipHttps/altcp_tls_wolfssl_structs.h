/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file contains structure definitions for a TLS layer using wolfSSL.
 */

/*
 * This file is modified from "altcp_tls_mbedtls_structs.h".
 *
 * Author: onelife <onelife.real[at]gmail.com>
 *
 */
#ifndef LWIP_HDR_ALTCP_WOLFSSL_STRUCTS_H
#define LWIP_HDR_ALTCP_WOLFSSL_STRUCTS_H

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/altcp_tls_wolfssl_opts.h"

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL

#include "lwip/altcp.h"
#include "lwip/pbuf.h"

#include "wolfssl/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE      0x01
#define ALTCP_WOLFSSL_FLAGS_UPPER_CALLED        0x02
#define ALTCP_WOLFSSL_FLAGS_RX_CLOSE_QUEUED     0x04
#define ALTCP_WOLFSSL_FLAGS_RX_CLOSED           0x08
#define ALTCP_WOLFSSL_FLAGS_APPLDATA_SENT       0x10
#define ALTCP_WOLFSSL_FLAGS_SSL_ERROR           0x20
#define ALTCP_WOLFSSL_FLAGS_APP_ERROR           0x40

/* Global wolfSSL configuration (server-specific, not connection-specific) */
struct altcp_tls_config {
  WOLFSSL_CTX *ctx;
  // void *conf;
};

typedef struct altcp_wolfssl_state_s {
  void *conf;
  WOLFSSL *ssl;
  WOLFSSL_CTX *ssl_context;
  int ssl_err;
  err_t app_err;
  /* chain of rx pbufs (before decryption) */
  struct pbuf *rx;
  struct pbuf *rx_app;
  u8_t flags;
  int rx_passed_unrecved;
  int bio_bytes_read;
  int bio_bytes_appl;
} altcp_wolfssl_state_t;

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL */
#endif /* LWIP_ALTCP */
#endif /* LWIP_HDR_ALTCP_WOLFSSL_STRUCTS_H */
