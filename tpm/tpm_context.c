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
 * Session Management ([TPM_Part3], Section 21)
 */

TPM_RESULT TPM_KeyControlOwner(  
  TPM_KEY_HANDLE keyHandle,
  UINT32 bitName,
  BOOL bitValue,
  TPM_AUTH *auth1
)
{
  info("TPM_KeyControlOwner() not implemented yet");
  /* TODO: implement TPM_KeyControlOwner() */
  return TPM_FAIL;
}

TPM_RESULT TPM_SaveContext(  
  TPM_HANDLE handle,
  TPM_RESOURCE_TYPE resourceType,
  BYTE label[16],  
  UINT32 *contextSize,
  TPM_CONTEXT_BLOB *contextBlob 
)
{
  info("TPM_SaveContext() not implemented yet");
  /* TODO: implement TPM_SaveContext() */
  return TPM_FAIL;
}

TPM_RESULT TPM_LoadContext(  
  BOOL keepHandle,
  TPM_HANDLE hintHandle,
  UINT32 contextSize,
  TPM_CONTEXT_BLOB *contextBlob,  
  TPM_HANDLE *handle 
)
{
  info("TPM_LoadContext() not implemented yet");
  /* TODO: implement TPM_LoadContext() */
  return TPM_FAIL;
}

