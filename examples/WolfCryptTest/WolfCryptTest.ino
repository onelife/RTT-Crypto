/***************************************************************************//**
 * @file    WolfCryptTest.ino
 * @brief   Arduino wolfSSL library crypto test
 * @author  onelife <onelife.real[at]gmail.com>
 ******************************************************************************/
#include <rtt.h>
#include <wolfssl.h>
#include <RttCrypto.h>

#define LOG_TAG "Test"
#include <log.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfcrypt/test/test.h>

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

static func_args args = { 0, NULL, 0 };


void setup() {
  RT_T.begin();
}

void setup_after_rtt_start() {
  static int init_done = 0;
  if (init_done) {
    return;
  }

  wolfCrypt_Init();

  LOG_I("\nCrypt Test\n");
  wolfcrypt_test(&args);
  LOG_I("Crypt Test: Return code %d\n", args.return_code);

  wolfCrypt_Cleanup();

  init_done = 1;
}

void loop() {
  setup_after_rtt_start();
}
