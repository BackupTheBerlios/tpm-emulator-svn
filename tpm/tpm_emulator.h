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

#ifndef _TPM_EMULATOR_H_
#define _TPM_EMULATOR_H_

#include "linux_module.h"

/* TPM configuration */
#define TPM_STORE_TO_FILE       1
#undef  TPM_STRONG_PERSISTENCE
#undef  TPM_GENERATE_EK

/**
 * tpm_emulator_init - initialises and starts the TPM emulator
 * @startup: [in] startup mode
 */
void tpm_emulator_init(uint32_t startup);

/**
 * tpm_emulator_shutdown - shuts the TPM emulator down
 */
void tpm_emulator_shutdown(void);

/**
 * tpm_handle_command - handles (i.e., executes) TPM commands
 * @in: [in] incomming TPM command
 * @in_size: [in] total number of input bytes
 * @out: [out] outgoing TPM result
 * @out_size: [out] total number of output bytes
 * @Returns: 0 on success, -1 otherwise
 *
 * Description: Handles (i.e., executes) TPM commands. If the function
 * returns successfully and out is unequal to NULL, it has to be released 
 * (after usage ;-) by means of kfree. 
 */ 
int tpm_handle_command(const uint8_t *in, uint32_t in_size, uint8_t **out, uint32_t *out_size);

#endif /* _TPM_EMULATOR_H_ */
