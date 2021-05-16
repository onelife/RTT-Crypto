/***************************************************************************//**
 * @file    RttCrypto.cpp
 * @brief   RT-Thread crypto library main
 * @author  onelife <onelife.real[at]gmail.com>
 ******************************************************************************/
#include <RttCrypto.h>

// #define LOG_TAG "wolfSSL"
// #include <log.h>


int WolfSslClass::begin() {
      return 1;
}

WolfSslClass WolfSSL;
