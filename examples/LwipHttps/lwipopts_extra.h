/***************************************************************************//**
 * @file    lwipopts_extra.h
 * @brief   LwIP library extra options
 * @author  onelife <onelife.real[at]gmail.com>
 ******************************************************************************/
#ifndef __LWIPOPTS_EXTRA_H__
#define __LWIPOPTS_EXTRA_H__

#undef  TCP_WND
#define TCP_WND                         (12 * TCP_MSS)

#define ALTCP_WOLFSSL_DEBUG             LWIP_DBG_ON
#define HTTPC_DEBUG                     LWIP_DBG_ON
#define HTTPD_DEBUG                     LWIP_DBG_ON

#define LWIP_ALTCP                      1
#define LWIP_ALTCP_TLS                  1
#define LWIP_ALTCP_TLS_WOLFSSL          1

#undef  TCPIP_THREAD_STACKSIZE
#define TCPIP_THREAD_STACKSIZE          (512 * 6)

#define HTTPD_ENABLE_HTTPS              1

#endif /* __LWIPOPTS_EXTRA_H__ */
