#pragma once

#include <stdbool.h>
#include <stdio.h>

#include <sys/unistd.h>
#include <sys/stat.h>


#ifdef __cplusplus
extern "C"
{
#endif

void bsp_sdcard_init(void);
uint64_t bsp_sdcard_get_size(void);
/** True if card is mounted and sector 0 reads successfully (detects removal). */
bool bsp_sdcard_probe(void);
/** Unmount and release card (call when card is removed or before re-init). */
void bsp_sdcard_deinit(void);

#ifdef __cplusplus
}
#endif