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
 * Transport Sessions ([TPM_Part3], Section 24)
 */

TPM_RESULT TPM_EstablishTransport(  
  TPM_KEY_HANDLE encHandle,
  TPM_TRANSPORT_PUBLIC *transPublic,
  UINT32 secretSize,
  BYTE *secret,
  TPM_AUTH *auth1,  
  TPM_TRANSHANDLE *transHandle,
  TPM_CURRENT_TICKS *currentTicks,
  TPM_NONCE *transNonce 
)
{
  info("TPM_EstablishTransport() not implemented yet");
  /* TODO: implement TPM_EstablishTransport() */
  return TPM_FAIL;
}

TPM_RESULT TPM_ExecuteTransport(  
  UINT32 inWrappedCmdSize,
  BYTE *inWrappedCmd,
  TPM_AUTH *auth1,  
  UINT64 *currentTicks,
  UINT32 *outWrappedCmdSize,
  BYTE **outWrappedCmd  
)
{
  info("TPM_ExecuteTransport() not implemented yet");
  /* TODO: implement TPM_ExecuteTransport() */
  return TPM_FAIL;
}

TPM_RESULT TPM_ReleaseTransportSigned(  
  TPM_KEY_HANDLE key,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,  
  TPM_CURRENT_TICKS *currentTicks,
  UINT32 *signSize,
  BYTE **signature  
)
{
  info("TPM_ReleaseTransportSigned() not implemented yet");
  /* TODO: implement TPM_ReleaseTransportSigned() */
  return TPM_FAIL;
}

