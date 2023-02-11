/***************************************************************************//**
 * @file    user_functions.cpp
 * @brief   User provided functions for wolfssl library
 * @author  onelife <onelife.real[at]gmail.com>
 ******************************************************************************/
#include <time.h>

#ifdef ARDUINO_ARCH_STM32
# include <STM32RTC.h>
#else
# include "components/drivers/include/rtdevice.h"
# include "components/arduino/drv_rtc.h"
#endif

extern "C" {

#ifdef ARDUINO_ARCH_STM32

STM32RTC& rtc = STM32RTC::getInstance();

time_t user_xtime(time_t *timer) {
  time_t seconds = (time_t)rtc.getEpoch();
  if (NULL != timer) {
    *timer = seconds;
  }
  return seconds;
}

#ifndef NO_CRYPT_BENCHMARK
/* This is used by wolfCrypt benchmark tool only */
double current_time(int reset) {
  double seconds;
  uint32_t subSeconds;
  (void)reset;

  seconds = (double)rtc.getEpoch(&subSeconds);
  seconds += (double)subSeconds / 1000;
  return seconds;
}
#endif /* NO_CRYPT_BENCHMARK */

#else /* ARDUINO_ARCH_STM32 */

time_t user_xtime(time_t *timer) {
  rt_device_t rtc = RT_NULL;
  time_t seconds = 0;

  rtc = rt_device_find(RTC_NAME);
  if (RT_NULL != rtc) {
    if (RT_EOK == rt_device_open(rtc, 0)) {
      rt_device_control(rtc, RT_DEVICE_CTRL_RTC_GET_TIME, &seconds);
      rt_device_close(rtc);
      if (RT_NULL != timer) {
        *timer = seconds;
      }
    }
  }
  return seconds;
}

#ifndef NO_CRYPT_BENCHMARK
/* This is used by wolfCrypt benchmark tool only */
double current_time(int reset) {
    (void)reset;
    return (double)user_xtime(0);
}
#endif /* NO_CRYPT_BENCHMARK */

#endif /* ARDUINO_ARCH_STM32 */

}
