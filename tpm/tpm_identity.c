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
 * Identity Creation and Activation ([TPM_Part3], Section 15)
 */

TPM_RESULT TPM_MakeIdentity(  
  TPM_ENCAUTH *identityAuth,
  TPM_CHOSENID_HASH *labelPrivCADigest,
  TPM_KEY *idKeyParams,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,  
  TPM_KEY *idKey,
  UINT32 *identityBindingSize,
  BYTE **identityBinding  
)
{
  info("TPM_MakeIdentity() not implemented yet");
  /* TODO: implement TPM_MakeIdentity() */
  return TPM_FAIL;
}

TPM_RESULT TPM_ActivateIdentity(  
  TPM_KEY_HANDLE idKey,
  UINT32 blobSize,
  BYTE *blob,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,  
  TPM_SYMMETRIC_KEY *symmetricKey 
)
{
  info("TPM_ActivateIdentity() not implemented yet");
  /* TODO: implement TPM_ActivateIdentity() */
  return TPM_FAIL;
}

