/***************************************************************************//**
 * @file    rtconfig_extra.h
 * @brief   RT-Thread library extra config
 * @author  onelife <onelife.real[at]gmail.com>
 ******************************************************************************/
#ifndef __RTCONFIG_EXTRA_H__
#define __RTCONFIG_EXTRA_H__

#ifdef ARDUINO_ARCH_STM32
#undef CONFIG_ARDUINO_STACK_SIZE
#define CONFIG_ARDUINO_STACK_SIZE       (16 * 512)
#endif

#endif /* __RTCONFIG_EXTRA_H__ */
