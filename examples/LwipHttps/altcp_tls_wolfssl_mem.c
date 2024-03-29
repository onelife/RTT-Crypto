/**
 * @file
 * Application layered TCP connection API (to be used from TCPIP thread)
 *
 * This file contains memory management functions for a TLS layer using wolfSSL.
 *
 * ATTENTION: For production usage, you might want to override this file with
 *            your own implementation since this implementation simply uses the
 *            lwIP heap without caring for fragmentation or leaving heap for
 *            other parts of lwIP!
 */

/*
 * This file is modified from "altcp_tls_mbedtls_mem.c".
 *
 * Author: onelife <onelife.real[at]gmail.com>
 *
 * Missing things / @todo:
 * - RX data is acknowledged after receiving (tcp_recved is called when enqueueing
 *   the pbuf for wolfSSL receive, not when processed by wolfSSL or the inner
 *   connection; altcp_recved() from inner connection does nothing)
 * - TX data is marked as 'sent' (i.e. acknowledged; sent callback is called) right
 *   after enqueueing for transmission, not when actually ACKed be the remote host.
 */

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/altcp_tls_wolfssl_opts.h"

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL

#include "altcp_tls_wolfssl_mem.h"
#include "altcp_tls_wolfssl_structs.h"
#include "lwip/mem.h"

#include "wolfssl/wolfcrypt/settings.h"

#include <string.h>

#ifndef ALTCP_WOLFSSL_MEM_DEBUG
#define ALTCP_WOLFSSL_MEM_DEBUG   LWIP_DBG_OFF
#endif

#if defined(XMALLOC_USER) && defined(XMALLOC_LWIP)
#define ALTCP_WOLFSSL_PLATFORM_ALLOC 1
#else
#define ALTCP_WOLFSSL_PLATFORM_ALLOC 0
#endif

#if ALTCP_WOLFSSL_PLATFORM_ALLOC

#ifndef ALTCP_WOLFSSL_PLATFORM_ALLOC_STATS
#define ALTCP_WOLFSSL_PLATFORM_ALLOC_STATS 0
#endif

/* This is an example/debug implementation of alloc/free functions only */
typedef struct altcp_wolfssl_malloc_helper_s {
  size_t c;
  size_t len;
} altcp_wolfssl_malloc_helper_t;

#if ALTCP_WOLFSSL_PLATFORM_ALLOC_STATS
typedef struct altcp_wolfssl_malloc_stats_s {
  size_t allocedBytes;
  size_t allocCnt;
  size_t maxBytes;
  size_t totalBytes;
} altcp_wolfssl_malloc_stats_t;
altcp_wolfssl_malloc_stats_t altcp_wolfssl_malloc_stats;
volatile int altcp_wolfssl_malloc_clear_stats;
#endif

static void *tls_malloc(size_t c, size_t len) {
  altcp_wolfssl_malloc_helper_t *hlpr;
  void *ret;
  size_t alloc_size;
#if ALTCP_WOLFSSL_PLATFORM_ALLOC_STATS
  if (altcp_wolfssl_malloc_clear_stats) {
    altcp_wolfssl_malloc_clear_stats = 0;
    memset(&altcp_wolfssl_malloc_stats, 0, sizeof(altcp_wolfssl_malloc_stats));
  }
#endif
  alloc_size = sizeof(altcp_wolfssl_malloc_helper_t) + (c * len);
  /* check for maximum allocation size, mainly to prevent mem_size_t overflow */
  if (alloc_size > MEM_SIZE) {
    LWIP_DEBUGF(
      ALTCP_WOLFSSL_MEM_DEBUG,
      ("wolfssl allocation too big: %c * %d bytes vs MEM_SIZE=%d",
        (int)c, (int)len, (int)MEM_SIZE));
    return NULL;
  }
  hlpr = (altcp_wolfssl_malloc_helper_t *)mem_malloc((mem_size_t)alloc_size);
  if (hlpr == NULL) {
    LWIP_DEBUGF(
      ALTCP_WOLFSSL_MEM_DEBUG,
      ("wolfssl alloc callback failed for %c * %d bytes", (int)c, (int)len));
    return NULL;
  }
#if ALTCP_WOLFSSL_PLATFORM_ALLOC_STATS
  altcp_wolfssl_malloc_stats.allocCnt++;
  altcp_wolfssl_malloc_stats.allocedBytes += c * len;
  if (altcp_wolfssl_malloc_stats.allocedBytes > altcp_wolfssl_malloc_stats.maxBytes) {
    altcp_wolfssl_malloc_stats.maxBytes = altcp_wolfssl_malloc_stats.allocedBytes;
  }
  altcp_wolfssl_malloc_stats.totalBytes += c * len;
#endif
  hlpr->c = c;
  hlpr->len = len;
  ret = hlpr + 1;
  /* zeroing the allocated chunk is required by wolfSSL? */
  memset(ret, 0, c * len);
  return ret;
}

static void tls_free(void *ptr) {
  altcp_wolfssl_malloc_helper_t *hlpr;
  if (ptr == NULL) {
    /* this obviously happened in wolfssl... */
    return;
  }
  hlpr = ((altcp_wolfssl_malloc_helper_t *)ptr) - 1;
#if ALTCP_WOLFSSL_PLATFORM_ALLOC_STATS
  if (!altcp_wolfssl_malloc_clear_stats) {
    altcp_wolfssl_malloc_stats.allocedBytes -= hlpr->c * hlpr->len;
  }
#endif
  mem_free(hlpr);
}
#endif /* ALTCP_WOLFSSL_PLATFORM_ALLOC*/

void altcp_wolfssl_mem_init(void) {
  /* not much to do here when using the heap */

#if ALTCP_WOLFSSL_PLATFORM_ALLOC
  /* set wolfssl allocation methods */
  wolfSSL_SetAllocators(&tls_malloc, &tls_free, NULL);
#endif
}

altcp_wolfssl_state_t *altcp_wolfssl_alloc(void *conf) {
  altcp_wolfssl_state_t *ret = (altcp_wolfssl_state_t *)mem_calloc(
    1, sizeof(altcp_wolfssl_state_t));
  if (ret != NULL) {
    ret->conf = conf;
  }
  return ret;
}

void altcp_wolfssl_free(void *conf, altcp_wolfssl_state_t *state) {
  LWIP_UNUSED_ARG(conf);
  LWIP_ASSERT("state != NULL", state != NULL);
  mem_free(state);
}

void *altcp_wolfssl_alloc_config(void) {
  return mem_calloc(1, sizeof(struct altcp_tls_config));
}

void altcp_wolfssl_free_config(void *conf) {
  LWIP_ASSERT("conf != NULL", conf != NULL);
  mem_free(conf);
}

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL */
#endif /* LWIP_ALTCP */
