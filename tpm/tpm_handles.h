/* Software-Based Trusted Platform Module (TPM) Emulator for Linux
 * Copyright (C) 2004 Mario Strasser <mast@gmx.net>,
 *                    Swiss Federal Institute of Technology (ETH) Zurich
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

#ifndef _TPM_HANDLES_
#define _TPM_HANDLES_

#include "tpm_structures.h"

/*
 * definition of an invalid handle
 */ 
#define TPM_INVALID_HANDLE             0xFFFFFFFF

/*
 * macros to convert array indices to handles
 */
#define INDEX_TO_KEY_HANDLE(i)         (i | (TPM_RT_KEY << 24))
#define INDEX_TO_AUTH_HANDLE(i)        (i | (TPM_RT_AUTH << 24))
#define INDEX_TO_TRANS_HANDLE(i)       (i | (TPM_RT_TRANS << 24))
#define INDEX_TO_COUNTER_HANDLE(i)     (i | (TPM_RT_COUNTERS << 24))

/*
 * marco to convert handles to indices
 */
#define HANDLE_TO_INDEX(h)             (i & 0x00FFFFFF)

/*
 * functions to get the dedicated data for a handle
 */
TPM_KEY_DATA *tpm_get_key_slot(TPM_KEY_HANDLE handle);
TPM_SESSION_DATA *tpm_get_session_slot(TPM_HANDLE handle);

TPM_KEY_DATA *tpm_get_key(TPM_KEY_HANDLE handle);
TPM_SESSION_DATA *tpm_get_auth(TPM_AUTHHANDLE handle);
TPM_SESSION_DATA *tpm_get_transport(TPM_TRANSHANDLE handle);
TPM_COUNTER_VALUE *tpm_get_counter(TPM_COUNT_ID handle);

#endif /* _TPM_HANDLES_ */

