/***************************************************************************//**
 * @file    LwipHttps.ino
 * @brief   Arduino wolfSSL library https example
 * @author  onelife <onelife.real[at]gmail.com>
 ******************************************************************************/
#include <rtt.h>
#include <RttCrypto.h>
#include <wolfssl.h>
#include <LwIP.h>
#include <RttEthernet.h>

#include <wolfssl/ssl.h>

#include <lwip/tcpip.h>
#include <lwip/altcp_tls.h>
#include <lwip/apps/httpd.h>
#include <lwip/apps/http_client.h>

#define LOG_TAG "WS_HTTPS"
#include <log.h>


// Comment out the following line to run client
#define HTTPS_SERVER

#ifdef HTTPS_SERVER
const u8_t privkey[] = "-----BEGIN RSA PRIVATE KEY-----\
MIIEpQIBAAKCAQEAwJUI4VdB8nFtt9JFQScBZcZFrvK8JDC4lc4vTtb2HIi8fJ/7\
qGd//lycUXX3isoH5zUvj+G9e8AvfKtkqBf8yl17uuAh5XIuby6G2JVz2qwbU7lf\
P9cZDSVP4WNjUYsLZD+tQ7ilHFw0s64AoGPF9n8LWWh4c6aMGKkCba/DGQEuuBDj\
xsxAtGmjRjNph27Euxem8+jdrXO8ey8htf1mUQy9VLPhbV8cvCNz0QkDiRTSELlk\
wyrQoZZKvOHUGlvHoMDBY3gPRDcwMpaAMiOVoXe6E9KXc+JdJclqDcM5YKS0sGlC\
Qgnp2Ai8MyCzWCKnquvE4eZhg8XSlt/Z0E+t1wIDAQABAoIBAQCa0DQPUmIFUAHv\
n+1kbsLE2hryhNeSEEiSxOlq64t1bMZ5OPLJckqGZFSVd8vDmp231B2kAMieTuTd\
x7pnFsF0vKnWlI8rMBr77d8hBSPZSjm9mGtlmrjcxH3upkMVLj2+HSJgKnMw1T7Y\
oqyGQy7E9WReP4l1DxHYUSVOn9iqo85gs+KK2X4b8GTKmlsFC1uqy+XjP24yIgXz\
0PrvdFKB4l90073/MYNFdfpjepcu1rYZxpIm5CgGUFAOeC6peA0Ul7QS2DFAq6EB\
QcIw+AdfFuRhd9Jg8p+N6PS662PeKpeB70xs5lU0USsoNPRTHMRYCj+7r7X3SoVD\
LTzxWFiBAoGBAPIsVHY5I2PJEDK3k62vvhl1loFk5rW4iUJB0W3QHBv4G6xpyzY8\
ZH3c9Bm4w2CxV0hfUk9ZOlV/MsAZQ1A/rs5vF/MOn0DKTq0VO8l56cBZOHNwnAp8\
yTpIMqfYSXUKhcLC/RVz2pkJKmmanwpxv7AEpox6Wm9IWlQ7xrFTF9/nAoGBAMuT\
3ncVXbdcXHzYkKmYLdZpDmOzo9ymzItqpKISjI57SCyySzfcBhh96v52odSh6T8N\
zRtfr1+elltbD6F8r7ObkNtXczrtsCNErkFPHwdCEyNMy/r0FKTV9542fFufqDzB\
hV900jkt/9CE3/uzIHoumxeu5roLrl9TpFLtG8SRAoGBAOyY2rvV/vlSSn0CVUlv\
VW5SL4SjK7OGYrNU0mNS2uOIdqDvixWl0xgUcndex6MEH54ZYrUbG57D8rUy+UzB\
qusMJn3UX0pRXKRFBnBEp1bA1CIUdp7YY1CJkNPiv4GVkjFBhzkaQwsYpVMfORpf\
H0O8h2rfbtMiAP4imHBOGhkpAoGBAIpBVihRnl/Ungs7mKNU8mxW1KrpaTOFJAza\
1AwtxL9PAmk4fNTm3Ezt1xYRwz4A58MmwFEC3rt1nG9WnHrzju/PisUr0toGakTJ\
c/5umYf4W77xfOZltU9s8MnF/xbKixsX4lg9ojerAby/QM5TjI7t7+5ZneBj5nxe\
9Y5L8TvBAoGATUX5QIzFW/QqGoq08hysa+kMVja3TnKW1eWK0uL/8fEYEz2GCbjY\
dqfJHHFSlDBD4PF4dP1hG0wJzOZoKnGtHN9DvFbbpaS+NXCkXs9P/ABVmTo9I89n\
WvUi+LUp0EQR6zUuRr79jhiyX6i/GTKh9dwD5nyaHwx8qbAOITc78bA=\
-----END RSA PRIVATE KEY-----";
size_t privkey_len = sizeof(privkey);

const u8_t *privkey_pass = NULL;
size_t privkey_pass_len = 0;

const u8_t cert[] = "-----BEGIN CERTIFICATE-----\
MIIE3TCCA8WgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMCVVMx\
EDAOBgNVBAgMB01vbnRhbmExEDAOBgNVBAcMB0JvemVtYW4xETAPBgNVBAoMCFNh\
d3Rvb3RoMRMwEQYDVQQLDApDb25zdWx0aW5nMRgwFgYDVQQDDA93d3cud29sZnNz\
bC5jb20xHzAdBgkqhkiG9w0BCQEWEGluZm9Ad29sZnNzbC5jb20wHhcNMjEwMjEw\
MTk0OTUzWhcNMjMxMTA3MTk0OTUzWjCBkDELMAkGA1UEBhMCVVMxEDAOBgNVBAgM\
B01vbnRhbmExEDAOBgNVBAcMB0JvemVtYW4xEDAOBgNVBAoMB3dvbGZTU0wxEDAO\
BgNVBAsMB1N1cHBvcnQxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqG\
SIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\
ADCCAQoCggEBAMCVCOFXQfJxbbfSRUEnAWXGRa7yvCQwuJXOL07W9hyIvHyf+6hn\
f/5cnFF194rKB+c1L4/hvXvAL3yrZKgX/Mpde7rgIeVyLm8uhtiVc9qsG1O5Xz/X\
GQ0lT+FjY1GLC2Q/rUO4pRxcNLOuAKBjxfZ/C1loeHOmjBipAm2vwxkBLrgQ48bM\
QLRpo0YzaYduxLsXpvPo3a1zvHsvIbX9ZlEMvVSz4W1fHLwjc9EJA4kU0hC5ZMMq\
0KGWSrzh1Bpbx6DAwWN4D0Q3MDKWgDIjlaF3uhPSl3PiXSXJag3DOWCktLBpQkIJ\
6dgIvDMgs1gip6rrxOHmYYPF0pbf2dBPrdcCAwEAAaOCATowggE2MB0GA1UdDgQW\
BBSzETLJkpiE4sn40DtuA0LKHw6OPDCByQYDVR0jBIHBMIG+gBQnjmcRdMMmHT/t\
M2OzpNgdMOXo1aGBmqSBlzCBlDELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB01vbnRh\
bmExEDAOBgNVBAcMB0JvemVtYW4xETAPBgNVBAoMCFNhd3Rvb3RoMRMwEQYDVQQL\
DApDb25zdWx0aW5nMRgwFgYDVQQDDA93d3cud29sZnNzbC5jb20xHzAdBgkqhkiG\
9w0BCQEWEGluZm9Ad29sZnNzbC5jb22CCQCq0z+sGAo3TTAMBgNVHRMEBTADAQH/\
MBwGA1UdEQQVMBOCC2V4YW1wbGUuY29thwR/AAABMB0GA1UdJQQWMBQGCCsGAQUF\
BwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAGw2mRJMNDgw1KCZAMdLr\
JkxHWxn7rf469TA6KNeqaaQV5yZutzNWrI80PfMhL1NYkdA+tDlIv5MRdDbTh0nD\
NA0wMKv0TCcZ1cQMrUm9kfjansgtKqzidY6qCNm/Zf+jsU/wYG9NlcQGf69maiM7\
OqRhtmzKvuGwd/Psg9WMHYV/jXTI7B5J7FdKzP3iOj5UUK5nzRewZ6VTf8MOPqdY\
6N/VDPJk860ScOO5QrwIYHbVDKUxd1DgyPM6PUXPMnXvEN217W7SLVeClTi8fVTE\
hF77foP18S2cmKxz46fSAjDWHwYe0Nw6rPTCwr5yQJrqzzUhO1Zt4VLygNc1g5cH\
zA==\
-----END CERTIFICATE-----";
size_t cert_len = sizeof(cert);
#endif

void rx_result(void *arg, httpc_result_t httpc_result, u32_t rx_content_len,
  u32_t srv_res, err_t err);
err_t rx_header(httpc_state_t *stats, void *arg, struct pbuf *hdr,
  u16_t hdr_len, u32_t content_len);

// Enter a MAC address and IP address for your controller below.
// The IP address will be dependent on your local network.
// gateway and subnet are optional:
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress ip(192, 168, 10, 85);
IPAddress myDns(192, 168, 10, 254);
IPAddress gateway(192, 168, 10, 254);
IPAddress subnet(255, 255, 255, 0);

altcp_allocator_t allocator = {
    .alloc = (altcp_new_fn)altcp_tls_new,
};
const httpc_connection_t config = {
    .altcp_allocator = &allocator,
    .result_fn = rx_result,
    .headers_done_fn = rx_header,
};
u32_t total_len = 0;
u32_t rx_len = 0;

void rx_result(void *arg, httpc_result_t httpc_result, u32_t rx_content_len,
  u32_t srv_res, err_t err) {
  (void)arg;

  if (HTTPC_RESULT_OK == httpc_result) {
    LOG_I("RX done");
  } else {
    LOG_W("RX error, %d, %d", httpc_result, err);
  }
  LOG_I("RX length: %d", rx_content_len);
  LOG_I("RX code: %d", srv_res);
}

err_t rx_header(httpc_state_t *stats, void *arg, struct pbuf *hdr,
  u16_t hdr_len, u32_t content_len) {
  (void)stats;
  (void)arg;
  (void)hdr;

  LOG_I("Header length: %d", hdr_len);
  LOG_I("Content length: %d", content_len);
  rx_len = 0;
  total_len = content_len;
  return ERR_OK;
}

err_t rx_body(void *arg, struct altcp_pcb *conn, struct pbuf *p, err_t err) {
  (void)arg;
  (void)err;
  altcp_recved(conn, p->tot_len);
  rx_len += p->tot_len;
  pbuf_free(p);

  LOG_I("RX %3d%%, %6d/%6d", rx_len * 100 / total_len, rx_len, total_len);

  return ERR_OK;
}

// err_t https_connected(void *arg, struct altcp_pcb *pcb, err_t err) {
//     // connectfinal_err = err;
//     return ERR_OK;
// }


void setup() {
  RT_T.begin();
}

void setup_after_rtt_start() {
  static int init_done = 0;
  if (init_done) {
    return;
  }

  // initialize the Ethernet device
  Ethernet.begin(mac, ip, myDns, gateway, subnet);

  if (Ethernet.linkStatus() == LinkOFF) {
    LOG_I("Ethernet cable is not connected.");
  }

  IPAddress addr = Ethernet.localIP();
  #ifdef HTTPS_SERVER
  LOG_I("HTTPS server address: %u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
  #else
  LOG_I("HTTPS client address: %u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
  #endif

  #ifdef HTTPS_SERVER
    struct altcp_tls_config *conf = altcp_tls_create_config_server_privkey_cert(
      privkey, privkey_len, privkey_pass, privkey_pass_len, cert, cert_len);

    LOCK_TCPIP_CORE();
    httpd_inits(conf);
    UNLOCK_TCPIP_CORE();
  #else
    static char host[] = "www.google.com";
    u16_t port = 443;
    const char uri[] = "/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png";
    err_t ret;

    struct altcp_tls_config *conf = altcp_tls_create_config_client(NULL, 0);
    allocator.arg = conf;

    LOCK_TCPIP_CORE();
    ret = httpc_get_file_dns(host, port, uri, &config, rx_body, NULL, NULL);
    UNLOCK_TCPIP_CORE();
    if (ERR_OK != ret) {
      LOG_W("HTTPS client error, %d", ret);
    } else {
      LOG_I("HTTPS client started");
    }
  #endif

  init_done = 1;
}

void loop() {
  setup_after_rtt_start();
}
