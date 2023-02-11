/***************************************************************************//**
 * @file    rtconfig_extra.h
 * @brief   RT-Thread library extra config
 * @author  onelife <onelife.real[at]gmail.com>
 ******************************************************************************/
#ifndef __RTCONFIG_EXTRA_H__
#define __RTCONFIG_EXTRA_H__

#ifdef ARDUINO_ARCH_STM32
#undef  CONFIG_HEAP_SIZE
#define CONFIG_HEAP_SIZE                (64 * 1024)
// #define RT_DEBUG                        1
#define RT_DEBUG_MEMHEAP                1
#endif

#endif /* __RTCONFIG_EXTRA_H__ */
