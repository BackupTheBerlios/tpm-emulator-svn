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

#ifndef _CONFIG_H_
#define _CONFIG_H_

/* project and build version */
#define VERSION_MAJOR 0
#define VERSION_MINOR 7
#define VERSION_BUILD 144

/* TPM emulator configuration */
/* #undef TPM_STRONG_PERSISTENCE */
/* #undef TPM_GENERATE_EK */
/* #undef TPM_GENERATE_SEED_DAA */
/* #undef TPM_USE_INTERNAL_PRNG */
/* #undef TPM_ENABLE_PRNG_STATE_SETTING */

/* TDDL and LKM configuration */
#define TPM_SOCKET_NAME  "/var/run/tpm/tpmd_socket:0"
#define TPM_STORAGE_NAME "/var/lib/tpm/tpm_emulator-1.2.0.7"
#define TPM_DEVICE_NAME  "/dev/tpm"

#endif /* _CONFIG_H_ */

