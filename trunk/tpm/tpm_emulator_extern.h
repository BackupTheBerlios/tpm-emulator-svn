/* Software-Based Trusted Platform Module (TPM) Emulator for Linux
 * Copyright (C) 2004 Mario Strasser <mast@gmx.net>,
 *
 * This module is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id$
 */

#ifndef _TPM_EMULATOR_EXTERN_H_
#define _TPM_EMULATOR_EXTERN_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* TPM emulator configuration */

#undef  TPM_STRONG_PERSISTENCE
#undef  TPM_GENERATE_EK
#undef  TPM_GENERATE_SEED_DAA
#undef  TPM_USE_INTERNAL_PRNG
#undef  TPM_ENABLE_PRNG_STATE_SETTING

/* log functions */

void tpm_log(int priority, const char *fmt, ...);

#define debug(fmt, ...) tpm_log(LOG_DEBUG, "%s:%d: Debug: " fmt "\n", \
                                __FILE__, __LINE__, ## __VA_ARGS__)
#define info(fmt, ...)  tpm_log(LOG_INFO, "%s:%d: Info: " fmt "\n", \
                                __FILE__, __LINE__, ## __VA_ARGS__)
#define error(fmt, ...) tpm_log(LOG_ERR, "%s:%d: Error: " fmt "\n", \
                                __FILE__, __LINE__, ## __VA_ARGS__)
#define alert(fmt, ...) tpm_log(LOG_ALERT, "%s:%d: Alert: " fmt "\n", \
                                __FILE__, __LINE__, ## __VA_ARGS__)

/* memory allocation */

void *tpm_malloc(size_t size);

void tpm_free(/*const*/ void *ptr);

/* random numbers */

void tpm_get_extern_random_bytes(void *buf, size_t nbytes);

/* usec since last call */

uint64_t tpm_get_ticks(void);

/* file handling */

int tpm_write_to_storage(uint8_t *data, size_t data_length);
int tpm_read_from_storage(uint8_t **data, size_t *data_length);

#endif /* _TPM_EMULATOR_EXTERN_H_ */
