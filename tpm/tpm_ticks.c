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

#include "tpm_emulator.h"
#include "tpm_commands.h"

/*
 * Timing Ticks ([TPM_Part3], Section 23)
 * The TPM timing ticks are always available for use. The association of 
 * timing ticks to actual time is a protocol that occurs outside of the TPM. 
 * See the design document for details. 
 */

TPM_RESULT TPM_SetTickType(  
  TPM_TICKTYPE tickType
)
{
  info("TPM_SetTickType() not implemented yet");
  /* TODO: implement TPM_SetTickType() */
  return TPM_FAIL;
}

TPM_RESULT TPM_GetTicks(  
  TPM_CURRENT_TICKS *currentTime 
)
{
  info("TPM_GetTicks() not implemented yet");
  /* TODO: implement TPM_GetTicks() */
  return TPM_FAIL;
}

TPM_RESULT TPM_TickStampBlob(  
  TPM_KEY_HANDLE keyHandle,
  TPM_NONCE *antiReplay,
  TPM_DIGEST *digestToStamp,
  TPM_AUTH *auth1,  
  TPM_CURRENT_TICKS *currentTicks,
  UINT32 *sigSize,
  BYTE **sig  
)
{
  info("TPM_TickStampBlob() not implemented yet");
  /* TODO: implement TPM_TickStampBlob() */
  return TPM_FAIL;
}

