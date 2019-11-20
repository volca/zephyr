/*
 * Copyright (c) 2017 Linaro Limited.
 * Copyright (c) 2019 Christian Taedcke <hacking@taedcke.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ARM_MPU_MEM_CFG_H_
#define _ARM_MPU_MEM_CFG_H_

#include <soc.h>
#include <arch/arm/cortex_m/mpu/arm_mpu.h>

/* Flash Region Definitions */
#if CONFIG_FLASH_SIZE == 64
#define REGION_FLASH_SIZE REGION_64K
#elif CONFIG_FLASH_SIZE == 128
#define REGION_FLASH_SIZE REGION_128K
#elif CONFIG_FLASH_SIZE == 256
#define REGION_FLASH_SIZE REGION_256K
#elif CONFIG_FLASH_SIZE == 512
#define REGION_FLASH_SIZE REGION_512K
#elif CONFIG_FLASH_SIZE == 1024
#define REGION_FLASH_SIZE REGION_1M
#elif CONFIG_FLASH_SIZE == 2048
#define REGION_FLASH_SIZE REGION_2M
#else
#error "Unsupported configuration"
#endif

/* SRAM Region Definitions */
#if CONFIG_SRAM_SIZE == 16
#define REGION_SRAM_0_SIZE REGION_16K
#elif CONFIG_SRAM_SIZE == 32
#define REGION_SRAM_0_SIZE REGION_32K
#elif CONFIG_SRAM_SIZE == 64
#define REGION_SRAM_0_SIZE REGION_64K
#elif CONFIG_SRAM_SIZE == 128
#define REGION_SRAM_0_SIZE REGION_128K
#elif CONFIG_SRAM_SIZE == 192
#define REGION_SRAM_0_SIZE REGION_128K
#define REGION_SRAM_1_START 0x20000
#define REGION_SRAM_1_SIZE REGION_64K
#elif CONFIG_SRAM_SIZE == 256
#define REGION_SRAM_0_SIZE REGION_256K
#elif CONFIG_SRAM_SIZE == 384
#define REGION_SRAM_0_SIZE REGION_256K
#define REGION_SRAM_1_START 0x40000
#define REGION_SRAM_1_SIZE REGION_128K
#elif CONFIG_SRAM_SIZE == 512
#define REGION_SRAM_0_SIZE REGION_512K
#else
#error "Unsupported configuration"
#endif

#endif /* _ARM_MPU_MEM_CFG_H_ */
