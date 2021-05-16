/***************************************************************************//**
 * @file    RttCrypto.h
 * @brief   RT-Thread crypto library header
 * @author  onelife <onelife.real[at]gmail.com>
 ******************************************************************************/
#ifndef __RTTCRYPTO_H__
#define __RTTCRYPTO_H__

#include "hal_conf_extra.h"


class WolfSslClass {
  // private:
  //   char buf[128];

  public:
    int begin();

};

extern WolfSslClass WolfSSL;

#endif /* __RTTCRYPTO_H__ */
