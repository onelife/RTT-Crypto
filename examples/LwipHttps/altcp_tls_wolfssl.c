/**
 * @file
 * Application layered TCP/TLS connection API (to be used from TCPIP thread)
 *
 * This file provides a TLS layer using wolfSSL
 */

/*
 * Copyright (c) 2017 Simon Goldschmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Simon Goldschmidt <goldsimon@gmx.de>, onelife
 *
 * Watch out:
 * - 'sent' is always called with len==0 to the upper layer. This is because keeping
 *   track of the ratio of application data and TLS overhead would be too much.
 *
 * Mandatory security-related configuration:
 * - if defined NO_DEV_RANDOM then define CUSTOM_RAND_GENERATE_SEED too instead of
 *   using the wolfSSL default one
 * - if having hardware TRNG then define CUSTOM_RAND_GENERATE_BLOCK
 *
 * Missing things / @todo:
 * - some unhandled/untested things migh be caught by LWIP_ASSERTs...
 */

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/altcp_tls_wolfssl_opts.h"

#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL

#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/priv/altcp_priv.h"

#include "altcp_tls_wolfssl_structs.h"
#include "altcp_tls_wolfssl_mem.h"

#include "wolfssl/error-ssl.h"
#include "wolfssl/ssl.h"
#include "wolfssl/internal.h"

#include <string.h>


/* Variable prototype, the actual declaration is at the end of this file
   since it contains pointers to static functions declared here */
extern const struct altcp_functions altcp_wolfssl_functions;

static err_t altcp_wolfssl_setup(
  void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn);
static err_t altcp_wolfssl_lower_recv(
  void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err);
static err_t altcp_wolfssl_handle_rx_appldata(
  struct altcp_pcb *conn, altcp_wolfssl_state_t *state);
static err_t altcp_wolfssl_lower_recv_process(
  struct altcp_pcb *conn, altcp_wolfssl_state_t *state);
static int altcp_wolfssl_bio_send(
  WOLFSSL *ssl, char *dataptr, int size, void *ctx);
static int altcp_wolfssl_bio_recv(WOLFSSL *ssl, char *buf, int len, void *ctx);

/* callback functions from inner/lower connection: */

/** Accept callback from lower connection (i.e. TCP)
 * Allocate one of our structures, assign it to the new connection's 'state' and
 * call the new connection's 'accepted' callback. If that succeeds, we wait
 * to receive connection setup handshake bytes from the client.
 */
static err_t altcp_wolfssl_lower_accept(
  void *arg, struct altcp_pcb *accepted_conn, err_t err) {
  struct altcp_pcb *listen_conn = (struct altcp_pcb *)arg;
  if (listen_conn && listen_conn->state && listen_conn->accept) {
    err_t setup_err;
    altcp_wolfssl_state_t *listen_state = (altcp_wolfssl_state_t *)listen_conn->state;
    /* create a new altcp_conn to pass to the next 'accept' callback */
    struct altcp_pcb *new_conn = altcp_alloc();
    if (new_conn == NULL) {
      return ERR_MEM;
    }
    setup_err = altcp_wolfssl_setup(listen_state->conf, new_conn, accepted_conn);
    if (setup_err != ERR_OK) {
      altcp_free(new_conn);
      return setup_err;
    }
    return listen_conn->accept(listen_conn->arg, new_conn, err);
  }
  return ERR_ARG;
}

/** Connected callback from lower connection (i.e. TCP).
 * Not really implemented/tested yet...
 */
static err_t altcp_wolfssl_lower_connected(
  void *arg, struct altcp_pcb *inner_conn, err_t err) {
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  LWIP_UNUSED_ARG(inner_conn); /* for LWIP_NOASSERT */
  if (conn && conn->state) {
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
    /* upper connected is called when handshake is done */
    if (ERR_OK != err) {
      if (conn->connected) {
        return conn->connected(conn->arg, conn, err);
      }
    }
    return altcp_wolfssl_lower_recv_process(
      conn, (altcp_wolfssl_state_t *)conn->state);
  }
  return ERR_VAL;
}

/* Call recved for possibly more than an u16_t */
static void altcp_wolfssl_lower_recved(
  struct altcp_pcb *inner_conn, int recvd_cnt) {
  while (recvd_cnt > 0) {
    u16_t recvd_part = (u16_t)LWIP_MIN(recvd_cnt, 0xFFFF);
    altcp_recved(inner_conn, recvd_part);
    recvd_cnt -= recvd_part;
  }
}

/** Recv callback from lower connection (i.e. TCP)
 * This one mainly differs between connection setup/handshake (data is fed into
 * wolfSSL only) and application phase (data is decoded by wolfSSL and passed
 * on to the application).
 */
static err_t altcp_wolfssl_lower_recv(
  void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err) {
  altcp_wolfssl_state_t *state;
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;

  LWIP_ASSERT("no err expected", err == ERR_OK);
  LWIP_UNUSED_ARG(err);

  if (!conn) {
    /* no connection given as arg? should not happen, but prevent pbuf/conn
       leaks */
    if (p != NULL) {
      pbuf_free(p);
    }
    altcp_close(inner_conn);
    return ERR_CLSD;
  }
  state = (altcp_wolfssl_state_t *)conn->state;
  LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
  if (!state) {
    /* already closed */
    if (p != NULL) {
      pbuf_free(p);
    }
    altcp_close(inner_conn);
    return ERR_CLSD;
  }

  /* handle NULL pbuf (inner connection closed) */
  if (p == NULL) {
    /* remote host sent FIN, remember this (SSL state is destroyed
        when both sides are closed only!) */
    if ((state->flags & \
      (ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE | ALTCP_WOLFSSL_FLAGS_UPPER_CALLED)) ==
      (ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE | ALTCP_WOLFSSL_FLAGS_UPPER_CALLED)) {
      /* need to notify upper layer (e.g. 'accept' called or 'connect'
         succeeded) */
      if ((NULL != state->rx) || (NULL != state->rx_app)) {
        state->flags |= ALTCP_WOLFSSL_FLAGS_RX_CLOSE_QUEUED;
        /* this is a normal close (FIN) but we have unprocessed data, so delay
           the FIN */
        altcp_wolfssl_handle_rx_appldata(conn, state);
        return ERR_OK;
      }
      state->flags |= ALTCP_WOLFSSL_FLAGS_RX_CLOSED;
      if (conn->recv) {
        /* call upper "recv" */
        return conn->recv(conn->arg, conn, NULL, ERR_OK);
      }
    } else {
      /* before connection setup is done: call 'err' */
      if (conn->err) {
        conn->err(conn->arg, ERR_CLSD);
      }
      altcp_close(conn);
    }
    return ERR_OK;
  }

  /* If we come here, the connection is in good state (handshake phase or
     application data phase). Queue up the pbuf for processing as handshake 
     data or application data. */
  if (NULL == state->rx) {
    state->rx = p;
  } else {
    LWIP_ASSERT("rx pbuf overflow", (int)p->tot_len + (int)p->len <= 0xFFFF);
    pbuf_cat(state->rx, p);
  }
  return altcp_wolfssl_lower_recv_process(conn, state);
}

static err_t altcp_wolfssl_lower_recv_process(
  struct altcp_pcb *conn, altcp_wolfssl_state_t *state) {
  if (!(state->flags & ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE)) {
    /* handle connection setup (handshake not done) */
    int ret = wolfSSL_connect(state->ssl);
    if (state->bio_bytes_read) {
      /* acknowledge all bytes read */
      altcp_wolfssl_lower_recved(conn->inner_conn, state->bio_bytes_read);
      state->bio_bytes_read = 0;
    }

    if (WOLFSSL_SUCCESS != ret) {
      int ssl_err = wolfSSL_get_error(state->ssl, ret);
      if ((WOLFSSL_ERROR_WANT_READ == ssl_err) || \
          (WOLFSSL_ERROR_WANT_WRITE == ssl_err)) {
        /* handshake not done, wait for more recv calls */
        LWIP_ASSERT(
          "in this state, the rx chain should be empty", state->rx == NULL);
        return ERR_OK;
      } else {
        LWIP_DEBUGF(
          ALTCP_WOLFSSL_DEBUG, ("wolfSSL_connect failed: %d\n", ssl_err));
        /* handshake failed, connection has to be closed */
        if (conn->err) {
          conn->err(conn->arg, ERR_CLSD);
        }
        if (ERR_OK != altcp_close(conn)) {
          altcp_abort(conn);
        }
        return ERR_OK;
      }
    }

    /* If we come here, handshake succeeded. */
    LWIP_ASSERT("state->bio_bytes_read", state->bio_bytes_read == 0);
    LWIP_ASSERT("state->bio_bytes_appl", state->bio_bytes_appl == 0);
    state->flags |= ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE;
    /* call upper "connected" (this can only happen for active open) */
    if (conn->connected) {
      err_t err = conn->connected(conn->arg, conn, ERR_OK);
      if (ERR_OK != err) {
        return err;
      }
    }
    if (NULL == state->rx) {
      return ERR_OK;
    }
  }

  /* handle application data */
  return altcp_wolfssl_handle_rx_appldata(conn, state);
}

/* Pass queued decoded rx data to application */
static err_t altcp_wolfssl_pass_rx_data(
  struct altcp_pcb *conn, altcp_wolfssl_state_t *state) {
  err_t err;
  struct pbuf *buf;
  LWIP_ASSERT("conn != NULL", conn != NULL);
  LWIP_ASSERT("state != NULL", state != NULL);

  buf = state->rx_app;
  if (buf) {
    state->rx_app = NULL;
    if (conn->recv) {
      /* call upper "recv" */
      u16_t tot_len = buf->tot_len;
      /* this needs to be increased first because the 'recved' call may come
         nested */
      state->rx_passed_unrecved += tot_len;
      state->flags |= ALTCP_WOLFSSL_FLAGS_UPPER_CALLED;
      err = conn->recv(conn->arg, conn, buf, ERR_OK);
      if (err != ERR_OK) {
        if (err == ERR_ABRT) {
          return ERR_ABRT;
        }
         /* not received, leave the pbuf(s) queued (and decrease 'unrecved' again) */
        LWIP_ASSERT("state == conn->state", state == conn->state);
        state->rx_app = buf;
        state->rx_passed_unrecved -= tot_len;
        LWIP_ASSERT(
          "state->rx_passed_unrecved >= 0", state->rx_passed_unrecved >= 0);
        if (state->rx_passed_unrecved < 0) {
          state->rx_passed_unrecved = 0;
        }
        return err;
      }
    } else {
      /* no upper layer then done */
      altcp_wolfssl_lower_recved(conn->inner_conn, buf->tot_len);
      pbuf_free(buf);
    }
  } else if ((state->flags & \
    (ALTCP_WOLFSSL_FLAGS_RX_CLOSE_QUEUED | ALTCP_WOLFSSL_FLAGS_RX_CLOSED)) == \
    ALTCP_WOLFSSL_FLAGS_RX_CLOSE_QUEUED) {
    state->flags |= ALTCP_WOLFSSL_FLAGS_RX_CLOSED;
    if (conn->recv) {
      /* inform application the connection closed */
      return conn->recv(conn->arg, conn, NULL, ERR_OK);
    }
  }

  /* application may have close the connection */
  if (conn->state != state) {
    /* return error code to ensure altcp_wolfssl_handle_rx_appldata() exits the
       loop */
    return ERR_CLSD;
  }
  return ERR_OK;
}

/* Helper function that processes rx application data stored in rx pbuf chain */
static err_t altcp_wolfssl_handle_rx_appldata(
  struct altcp_pcb *conn, altcp_wolfssl_state_t *state) {
  int ret;
  LWIP_ASSERT("state != NULL", state != NULL);

  if (!(state->flags & ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE)) {
    /* handshake not done yet */
    return ERR_VAL;
  }

  do {
    err_t err;
    /* allocate a full-sized unchained PBUF_POOL: this is for RX! */
    struct pbuf *buf = pbuf_alloc(PBUF_RAW, PBUF_POOL_BUFSIZE, PBUF_POOL);
    if (buf == NULL) {
      /* We're short on pbufs, try again later from 'poll' or 'recv'
         callbacks. */
      return ERR_OK;
    }

    /* decrypt application data, this pulls encrypted RX data off state->rx
       pbuf chain */
    ret = wolfSSL_read(state->ssl, buf->payload, PBUF_POOL_BUFSIZE);
    if (0 >= ret) {
      /* process error */
      int ssl_err = wolfSSL_get_error(state->ssl, ret);
      pbuf_free(buf);
      if (WOLFSSL_ERROR_ZERO_RETURN == ssl_err) {
        /* no more data */
        LWIP_DEBUGF(ALTCP_WOLFSSL_DEBUG, ("there is no more data\n"));
      } else if (SOCKET_PEER_CLOSED_E == ssl_err) {
        /* peer reset or closed */
        LWIP_DEBUGF(
          ALTCP_WOLFSSL_DEBUG, ("connection was reset or closed by peer\n"));
      } else if ((WOLFSSL_ERROR_WANT_READ != ssl_err) && \
        (WOLFSSL_ERROR_WANT_WRITE != ssl_err)) {
        /* pass other errors to upper layer */
        state->ssl_err = ssl_err;
        state->flags |= ALTCP_WOLFSSL_FLAGS_SSL_ERROR;
      }
      return ERR_OK;

    } else { /* (0 < ret) */
      /* process application data */
      LWIP_ASSERT("bogus receive length", ret <= (int)PBUF_POOL_BUFSIZE);
      /* trim pool pbuf to actually decoded length */
      pbuf_realloc(buf, (u16_t)ret);
      state->bio_bytes_appl += ret;
      if (wolfSSL_pending(state->ssl) == 0) {
        /* Record is done, now we know the share between application and protocol bytes
           and can adjust the RX window by the protocol bytes.
           The rest is 'recved' by the application calling our 'recved' fn. */
        int overhead_bytes;
        LWIP_ASSERT(
          "bogus byte counts", state->bio_bytes_read > state->bio_bytes_appl);
        overhead_bytes = state->bio_bytes_read - state->bio_bytes_appl;
        altcp_wolfssl_lower_recved(conn->inner_conn, overhead_bytes);
        state->bio_bytes_read = 0;
        state->bio_bytes_appl = 0;
      }
      /* plain text data */
      if (state->rx_app == NULL) {
        state->rx_app = buf;
      } else {
        pbuf_cat(state->rx_app, buf);
      }
    }

    /* pass plain text data to upper layer */
    err = altcp_wolfssl_pass_rx_data(conn, state);
    if (ERR_ABRT == err) {
      /* recv callback needs to return this as the pcb is deallocated */
      return ERR_ABRT;
    } else if (ERR_OK != err) {
      /* we hide all other errors as we retry feeding the pbuf to the app
         later */
      state->app_err = err;
      state->flags |= ALTCP_WOLFSSL_FLAGS_APP_ERROR;
      return ERR_OK;
    }
  } while (0 < ret);

  return ERR_OK;
}

/** Receive callback function called from wolfSSL (set via wolfSSL_CTX_SetIORecv)
 * This function mainly copies data from pbufs and frees the pbufs after copying.
 */
static int altcp_wolfssl_bio_recv(WOLFSSL *ssl, char *buf, int len, void *ctx) {
  struct altcp_pcb *conn = (struct altcp_pcb *)ctx;
  altcp_wolfssl_state_t *state;
  struct pbuf *p;
  u16_t ret;
  u16_t copy_len;
  err_t err;

  LWIP_UNUSED_ARG(ssl);
  LWIP_UNUSED_ARG(err); /* for LWIP_NOASSERT */
  if ((NULL == conn) || (NULL == conn->state)) {
    return BAD_FUNC_ARG;
  }
  state = (altcp_wolfssl_state_t *)conn->state;
  p = state->rx;

  if ((p == NULL) || ((p->len == 0) && (p->next == NULL))) {
    if (p) {
      pbuf_free(p);
    }
    state->rx = NULL;
    if ((state->flags & \
      (ALTCP_WOLFSSL_FLAGS_RX_CLOSE_QUEUED | ALTCP_WOLFSSL_FLAGS_RX_CLOSED)) ==
      ALTCP_WOLFSSL_FLAGS_RX_CLOSE_QUEUED) {
      /* close queued but not passed up yet */
      return 0;
    } else {
      return WOLFSSL_CBIO_ERR_WANT_READ;
    }
  }

  /* limit number of bytes again to copy from first pbuf in a chain only */
  copy_len = (u16_t)LWIP_MIN(len, p->len);
  /* copy the data */
  ret = pbuf_copy_partial(p, buf, copy_len, 0);
  LWIP_ASSERT("ret == copy_len", ret == copy_len);
  /* hide the copied bytes from the pbuf */
  err = pbuf_remove_header(p, ret);
  LWIP_ASSERT("error", err == ERR_OK);
  if (0 == p->len) {
    /* the first pbuf has been fully read, free it */
    state->rx = p->next;
    p->next = NULL;
    pbuf_free(p);
  }

  state->bio_bytes_read += (int)ret;
  return ret;
}

/** Sent callback from lower connection (i.e. TCP)
 * This only informs the upper layer to try to send more, not about
 * the number of ACKed bytes.
 */
static err_t altcp_wolfssl_lower_sent(
  void *arg, struct altcp_pcb *inner_conn, u16_t len) {
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  LWIP_UNUSED_ARG(inner_conn); /* for LWIP_NOASSERT */
  LWIP_UNUSED_ARG(len);

  if (conn) {
    altcp_wolfssl_state_t *state = (altcp_wolfssl_state_t *)conn->state;
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
    if (!state || !(state->flags & ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE)) {
      /* @todo: do something here? */
      return ERR_OK;
    }
    /* call upper "sent" with len==0 if the application already sent data */
    if ((state->flags & ALTCP_WOLFSSL_FLAGS_APPLDATA_SENT) && conn->sent) {
      return conn->sent(conn->arg, conn, 0);
    }
  }
  return ERR_OK;
}

/** Poll callback from lower connection (i.e. TCP)
 * Just pass this on to the application.
 * @todo: retry sending?
 */
static err_t altcp_wolfssl_lower_poll(void *arg, struct altcp_pcb *inner_conn) {
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  LWIP_UNUSED_ARG(inner_conn); /* for LWIP_NOASSERT */

  if (conn) {
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);
    /* check if there's unreceived rx data */
    if (conn->state) {
      altcp_wolfssl_state_t *state = (altcp_wolfssl_state_t *)conn->state;
      if (ERR_ABRT == altcp_wolfssl_handle_rx_appldata(conn, state)) {
        return ERR_ABRT;
      }
    }
    if (conn->poll) {
      /* call upper "poll" */
      return conn->poll(conn->arg, conn);
    }
  }
  return ERR_OK;
}

static void altcp_wolfssl_lower_err(void *arg, err_t err) {
  struct altcp_pcb *conn = (struct altcp_pcb *)arg;
  if (conn) {
    conn->inner_conn = NULL; /* already freed */
    if (conn->err) {
      conn->err(conn->arg, err);
    }
    altcp_free(conn);
  }
}

/* setup functions */

static void altcp_wolfssl_remove_callbacks(struct altcp_pcb *inner_conn) {
  altcp_arg(inner_conn, NULL);
  altcp_recv(inner_conn, NULL);
  altcp_sent(inner_conn, NULL);
  altcp_err(inner_conn, NULL);
  altcp_poll(inner_conn, NULL, inner_conn->pollinterval);
}

static void altcp_wolfssl_setup_callbacks(
  struct altcp_pcb *conn, struct altcp_pcb *inner_conn) {
  altcp_arg(inner_conn, conn);
  altcp_recv(inner_conn, altcp_wolfssl_lower_recv);
  altcp_sent(inner_conn, altcp_wolfssl_lower_sent);
  altcp_err(inner_conn, altcp_wolfssl_lower_err);
  /* tcp_poll is set when interval is set by application */
  /* listen is set totally different :-) */
}

static err_t altcp_wolfssl_setup(
  void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn) {
  struct altcp_tls_config *config = (struct altcp_tls_config *)conf;
  altcp_wolfssl_state_t *state;
  if (!conf) {
    return ERR_ARG;
  }
  LWIP_ASSERT("invalid inner_conn", conn != inner_conn);

  /* allocate wolfssl context */
  state = altcp_wolfssl_alloc(conf);
  if (NULL== state) {
    return ERR_MEM;
  }
  state->ssl_context = config->ctx;

  /* tell wolfSSL about our I/O functions */
  wolfSSL_CTX_SetIOSend(config->ctx, altcp_wolfssl_bio_send);
  wolfSSL_CTX_SetIORecv(config->ctx, altcp_wolfssl_bio_recv);
  /* TODO: config to disable cert check for TLS v1.3 */
  wolfSSL_CTX_set_verify(config->ctx, SSL_VERIFY_NONE, 0);
  /* create SSL after set I/O functions! */
  state->ssl = wolfSSL_new(config->ctx);
  if (NULL == state->ssl) {
    return ERR_MEM;
  }
  wolfSSL_SetIOWriteCtx(state->ssl, conn);
  wolfSSL_SetIOReadCtx(state->ssl, conn);

  altcp_wolfssl_setup_callbacks(conn, inner_conn);
  conn->inner_conn = inner_conn;
  conn->fns = &altcp_wolfssl_functions;
  conn->state = state;
  return ERR_OK;
}

struct altcp_pcb *altcp_tls_wrap(
  struct altcp_tls_config *config, struct altcp_pcb *inner_pcb) {
  struct altcp_pcb *ret;
  rt_kprintf("!!! altcp_tls_wrap ver %x\n", config->ctx->method->version);
  if (inner_pcb == NULL) {
    return NULL;
  }
  ret = altcp_alloc();
  if (ret != NULL) {
    if (altcp_wolfssl_setup(config, ret, inner_pcb) != ERR_OK) {
      altcp_free(ret);
      return NULL;
    }
  }
  return ret;
}

void *altcp_tls_context(struct altcp_pcb *conn) {
  if (conn && conn->state) {
    altcp_wolfssl_state_t *state = (altcp_wolfssl_state_t *)conn->state;
    return &state->ssl_context;
  }
  return NULL;
}

#if ALTCP_WOLFSSL_DEBUG != LWIP_DBG_OFF
// char log_buf[100][256];
// uint32_t log_cnt = 0;
void altcp_wolfssl_logging(const int logLevel, const char *const logMessage) {
    // int idx = (log_cnt++) % 100;
    // sprintf(log_buf[idx], "%d, %s", logLevel, logMessage);
    LWIP_DEBUGF(ALTCP_WOLFSSL_DEBUG, ("%02d: %s\n", logLevel, logMessage));
}
#endif

/** Create new TLS configuration
 * ATTENTION: Server certificate and private key have to be added outside this function!
 * ATTENTION: System time must be match the valid period of CA.
 */
static struct altcp_tls_config *altcp_tls_create_config(
  int is_server, int have_cert, int have_pkey, int have_ca) {
  struct altcp_tls_config *conf;

  if (TCP_WND < MAX_RECORD_SIZE) {
    LWIP_DEBUGF(ALTCP_WOLFSSL_DEBUG|LWIP_DBG_LEVEL_SERIOUS,
      ("altcp_tls: TCP_WND is smaller than the RX decryption buffer, connection RX might stall!\n"));
  }

  altcp_wolfssl_mem_init();

  // TODO
  // if (have_cert) {
  // }
  // if (have_ca) {
  // }
  // if (have_pkey) {
  // }

  conf = (struct altcp_tls_config *)altcp_wolfssl_alloc_config();
  if (conf == NULL) {
    return NULL;
  }

#if ALTCP_WOLFSSL_DEBUG != LWIP_DBG_OFF
  wolfSSL_SetLoggingCb(altcp_wolfssl_logging);
  wolfSSL_Debugging_ON();
#endif

  /* init */
  wolfSSL_Init();

  /* new context */
  conf->ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  if (NULL == conf->ctx) {
    LWIP_DEBUGF(ALTCP_WOLFSSL_DEBUG, ("wolfSSL_CTX_new failed\n"));
    altcp_wolfssl_free_config(conf);
    return NULL;
  }
  /* Uncomment the following line if system time is not calibrated */
  // conf->ctx->verifyNone = 1;

  return conf;
}

/** Create new TLS configuration
 * This is a suboptimal version that gets the encrypted private key and its password,
 * as well as the server certificate.
 */
struct altcp_tls_config *altcp_tls_create_config_server_privkey_cert(
  const u8_t *privkey, size_t privkey_len,
  const u8_t *privkey_pass, size_t privkey_pass_len,
  const u8_t *cert, size_t cert_len) {
  struct altcp_tls_config *conf = altcp_tls_create_config(1, 1, 1, 0);
  if (conf == NULL) {
    return NULL;
  }

  // TODO: cert

  // TODO: pk

  // TODO: ca

  return conf;
}

static struct altcp_tls_config *altcp_tls_create_config_client_common(
  const u8_t *ca, size_t ca_len, int is_2wayauth) {
  int ret;
  struct altcp_tls_config *conf = altcp_tls_create_config(
    0, is_2wayauth, is_2wayauth, ca != NULL);
  if (conf == NULL) {
    return NULL;
  }

  /* Initialize the CA certificate if provided
   * CA certificate is optional (to save memory) but recommended for production environment
   * Without CA certificate, connection will be prone to man-in-the-middle attacks */
  if (ca) {
    ret = wolfSSL_CTX_load_verify_buffer(
      conf->ctx, ca, ca_len, WOLFSSL_FILETYPE_PEM);
    if (SSL_SUCCESS != ret) {
      LWIP_DEBUGF(ALTCP_WOLFSSL_DEBUG,
        ("wolfSSL_CTX_load_verify_buffer ca failed: %d 0x%x", ret, -1*ret));
      altcp_wolfssl_free_config(conf);
      return NULL;
    }
  }
  return conf;
}

struct altcp_tls_config *altcp_tls_create_config_client(
  const u8_t *ca, size_t ca_len) {
  return altcp_tls_create_config_client_common(ca, ca_len, 0);
}

struct altcp_tls_config *altcp_tls_create_config_client_2wayauth(
  const u8_t *ca, size_t ca_len,
  const u8_t *privkey, size_t privkey_len,
  const u8_t *privkey_pass, size_t privkey_pass_len,
  const u8_t *cert, size_t cert_len) {
  int ret;
  struct altcp_tls_config *conf;

  if (!cert || !privkey) {
    LWIP_DEBUGF(ALTCP_WOLFSSL_DEBUG,
      ("altcp_tls_create_config_client_2wayauth: certificate and priv key required"));
    return NULL;
  }

  conf = altcp_tls_create_config_client_common(ca, ca_len, 1);
  if (conf == NULL) {
    return NULL;
  }

  /* Initialize the client certificate and corresponding private key */
  ret = wolfSSL_CTX_use_certificate_buffer(
    conf->ctx, cert, cert_len, SSL_FILETYPE_PEM);
  if (SSL_SUCCESS != ret) {
    LWIP_DEBUGF(ALTCP_WOLFSSL_DEBUG,
      ("wolfSSL_CTX_use_certificate_buffer cert failed: %d 0x%x",
        ret, -1*ret));
    altcp_wolfssl_free_config(conf);
    return NULL;
  }

  ret = wolfSSL_CTX_use_PrivateKey_buffer(
    conf->ctx, privkey, privkey_len, SSL_FILETYPE_PEM);
  if (SSL_SUCCESS != ret) {
    LWIP_DEBUGF(ALTCP_WOLFSSL_DEBUG, 
      ("wolfSSL_CTX_use_PrivateKey_buffer failed: %d 0x%x",
        ret, -1*ret));
    altcp_wolfssl_free_config(conf);
    return NULL;
  }

  // TODO: init cert

  // TODO: init PK

  return conf;
}

void altcp_tls_free_config(struct altcp_tls_config *conf) {
  // wolfSSL_UnloadCertsKeys(conf->ssl);
  wolfSSL_CTX_UnloadCAs(conf->ctx);
  // TODO: PK
  // TODO: cert
  altcp_wolfssl_free_config(conf);
}

/* "virtual" functions */
static void altcp_wolfssl_set_poll(struct altcp_pcb *conn, u8_t interval) {
  if (conn != NULL) {
    altcp_poll(conn->inner_conn, altcp_wolfssl_lower_poll, interval);
  }
}

static void altcp_wolfssl_recved(struct altcp_pcb *conn, u16_t len) {
  u16_t lower_recved;
  altcp_wolfssl_state_t *state;
  if (conn == NULL) {
    return;
  }
  state = (altcp_wolfssl_state_t *)conn->state;
  if (state == NULL) {
    return;
  }
  if (!(state->flags & ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE)) {
    return;
  }

  lower_recved = len;
  if (lower_recved > state->rx_passed_unrecved) {
    LWIP_DEBUGF(ALTCP_WOLFSSL_DEBUG,
      ("bogus recved count (len > state->rx_passed_unrecved / %d / %d)",
        len, state->rx_passed_unrecved));
    lower_recved = (u16_t)state->rx_passed_unrecved;
  }
  state->rx_passed_unrecved -= lower_recved;

  altcp_recved(conn->inner_conn, lower_recved);
}

static err_t altcp_wolfssl_connect(
  struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port,
  altcp_connected_fn connected) {
  if (conn == NULL) {
    return ERR_VAL;
  }
  conn->connected = connected;
  return altcp_connect(
    conn->inner_conn, ipaddr, port, altcp_wolfssl_lower_connected);
}

static struct altcp_pcb *altcp_wolfssl_listen(
  struct altcp_pcb *conn, u8_t backlog, err_t *err) {
  struct altcp_pcb *lpcb;
  if (conn == NULL) {
    return NULL;
  }

  lpcb = altcp_listen_with_backlog_and_err(conn->inner_conn, backlog, err);
  if (lpcb != NULL) {
    conn->inner_conn = lpcb;
    altcp_accept(lpcb, altcp_wolfssl_lower_accept);
    return conn;
  }
  return NULL;
}

static void altcp_wolfssl_abort(struct altcp_pcb *conn) {
  if (conn != NULL) {
    altcp_abort(conn->inner_conn);
  }
}

static err_t altcp_wolfssl_close(struct altcp_pcb *conn) {
  struct altcp_pcb *inner_conn;
  if (conn == NULL) {
    return ERR_VAL;
  }
  inner_conn = conn->inner_conn;
  if (inner_conn) {
    err_t err;
    altcp_poll_fn oldpoll = inner_conn->poll;
    altcp_wolfssl_remove_callbacks(conn->inner_conn);
    err = altcp_close(conn->inner_conn);
    if (err != ERR_OK) {
      /* not closed, set up all callbacks again */
      altcp_wolfssl_setup_callbacks(conn, inner_conn);
      /* poll callback is not included in the above */
      altcp_poll(inner_conn, oldpoll, inner_conn->pollinterval);
      return err;
    }
    conn->inner_conn = NULL;
  }
  altcp_free(conn);
  return ERR_OK;
}

/** Allow caller of altcp_write() to limit to negotiated chunk size
 *  or remaining sndbuf space of inner_conn.
 */
static u16_t altcp_wolfssl_sndbuf(struct altcp_pcb *conn) {
  if (conn) {
    altcp_wolfssl_state_t *state;
    state = (altcp_wolfssl_state_t*)conn->state;
    if (!state || !(state->flags & ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE)) {
      return 0;
    }
    if (conn->inner_conn) {
      u16_t sndbuf = altcp_sndbuf(conn->inner_conn);
      /* Take care of record header, IV, AuthTag */
      int ssl_expan = 0; //TODO: mbedtls_ssl_get_record_expansion(&state->ssl_context);
      if (ssl_expan > 0) {
        size_t ssl_added = (u16_t)LWIP_MIN(ssl_expan, 0xFFFF);
        /* internal sndbuf smaller than our offset */
        if (ssl_added < sndbuf) {
          size_t max_len = 0xFFFF;
          size_t ret;
          /* Adjust sndbuf of inner_conn with what added by SSL */
          ret = LWIP_MIN(sndbuf - ssl_added, max_len);
          LWIP_ASSERT("sndbuf overflow", ret <= 0xFFFF);
          return (u16_t)ret;
        }
      }
    }
  }
  /* fallback: use sendbuf of the inner connection */
  return altcp_default_sndbuf(conn);
}

/** Write data to a TLS connection. Calls into wolfSSL, which in turn calls into
 * @ref altcp_wolfssl_bio_send() to send the encrypted data
 */
static err_t altcp_wolfssl_write(
  struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags) {
  int ret;
  altcp_wolfssl_state_t *state;

  LWIP_UNUSED_ARG(apiflags);
  if (conn == NULL) {
    return ERR_VAL;
  }
  state = (altcp_wolfssl_state_t *)conn->state;
  if (state == NULL) {
    return ERR_CLSD;
  }
  if (!(state->flags & ALTCP_WOLFSSL_FLAGS_HANDSHAKE_DONE)) {
    return ERR_VAL;
  }

  ret = wolfSSL_write(state->ssl, (const unsigned char *)dataptr, len);
  /* try to send data... */
  altcp_output(conn->inner_conn);
  if (0 < ret) {
    if (len == ret) {
      state->flags |= ALTCP_WOLFSSL_FLAGS_APPLDATA_SENT;
      return ERR_OK;
    } else {
      /* assumption: either everything sent or error */
      LWIP_ASSERT("ret <= 0", 0);
      return ERR_MEM;
    }

  } else { /* 0 >= ret */
    int ssl_err = wolfSSL_get_error(state->ssl, ret);
    if (WOLFSSL_ERROR_WANT_WRITE == ssl_err) {
      /* @todo: convert error to err_t */
      return ERR_MEM;
    }
    LWIP_ASSERT("unhandled error", 0);
    return ERR_VAL;
  }
}

/** Send callback function called from wolfssl (set via wolfSSL_CTX_SetIOSend)
 * This function is either called during handshake or when sending application
 * data via @ref altcp_wolfssl_write (or altcp_write)
 */
static int altcp_wolfssl_bio_send(
  WOLFSSL *ssl, char *dataptr, int size, void *ctx) {
  struct altcp_pcb *conn = (struct altcp_pcb *)ctx;
  int written = 0;
  size_t size_left = size;
  u8_t apiflags = TCP_WRITE_FLAG_COPY;
  err_t err;

  LWIP_UNUSED_ARG(ssl);
  LWIP_ASSERT("conn != NULL", conn != NULL);
  if ((conn == NULL) || (conn->inner_conn == NULL)) {
    return BAD_FUNC_ARG;
  }

  while (size_left) {
    u16_t write_len = (u16_t)LWIP_MIN(size_left, 0xFFFF);
    err = altcp_write(conn->inner_conn, (const void *)dataptr, write_len,
                      apiflags);
    if (ERR_OK == err) {
      written += write_len;
      size_left -= write_len;
    } else if (ERR_MEM == err) {
      /* WOLFSSL_CBIO_ERR_WANT_WRITE */
      break;
    } else {
      LWIP_ASSERT("tls_write, tcp_write: err != ERR MEM", 0);
      break;
    }
  }

  if ((ERR_OK == err) || (ERR_MEM == err)) {
    return written;
  } else {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }
}

static u16_t altcp_wolfssl_mss(struct altcp_pcb *conn) {
  if (conn == NULL) {
    return 0;
  }
  return altcp_mss(conn->inner_conn);
}

static void altcp_wolfssl_dealloc(struct altcp_pcb *conn) {
  /* clean up and free tls state */
  if (conn) {
    altcp_wolfssl_state_t *state = (altcp_wolfssl_state_t *)conn->state;
    if (state) {
      wolfSSL_free(state->ssl);
      wolfSSL_CTX_free(state->ssl_context);
      state->flags = 0;
      if (state->rx) {
        /* free leftover (unhandled) rx pbufs */
        pbuf_free(state->rx);
        state->rx = NULL;
      }
        rt_kprintf("altcp_wolfssl_free\n");
      altcp_wolfssl_free(state->conf, state);
        rt_kprintf("altcp_wolfssl_free 0\n");
      conn->state = NULL;
    }
  }
}

const struct altcp_functions altcp_wolfssl_functions = {
  altcp_wolfssl_set_poll,
  altcp_wolfssl_recved,
  altcp_default_bind,
  altcp_wolfssl_connect,
  altcp_wolfssl_listen,
  altcp_wolfssl_abort,
  altcp_wolfssl_close,
  altcp_default_shutdown,
  altcp_wolfssl_write,
  altcp_default_output,
  altcp_wolfssl_mss,
  altcp_wolfssl_sndbuf,
  altcp_default_sndqueuelen,
  altcp_default_nagle_disable,
  altcp_default_nagle_enable,
  altcp_default_nagle_disabled,
  altcp_default_setprio,
  altcp_wolfssl_dealloc,
  altcp_default_get_tcp_addrinfo,
  altcp_default_get_ip,
  altcp_default_get_port
#ifdef LWIP_DEBUG
  , altcp_default_dbg_get_tcp_state
#endif
};

#endif /* LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_WOLFSSL */
#endif /* LWIP_ALTCP */
