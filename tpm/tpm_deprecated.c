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
#include "tpm_data.h"

/*
 * Deprecated commands ([TPM_Part3], Section 28)
 * This section covers the commands that were in version 1.1 but now have 
 * new functionality in other functions. The deprecated commands are still 
 * available in 1.2 but all new software should use the new functionality. 
 * There is no requirement that the deprecated commands work with new 
 * structures.
 */

TPM_RESULT TPM_EvictKey(TPM_KEY_HANDLE evictHandle)
{
  info("TPM_EvictKey()");
  return TPM_FlushSpecific(evictHandle, TPM_RT_KEY);
}

TPM_RESULT TPM_Terminate_Handle(TPM_AUTHHANDLE handle)
{
  info("TPM_Terminate_Handle()");
  return TPM_FlushSpecific(handle, TPM_RT_AUTH);
}

TPM_RESULT TPM_SaveKeyContext(  
  TPM_KEY_HANDLE keyHandle,  
  UINT32 *keyContextSize,
  BYTE **keyContextBlob  
)
{
  info("TPM_SaveKeyContext() not implemented yet");
  /* TODO: implement TPM_SaveKeyContext() */
  return TPM_FAIL;
}

TPM_RESULT TPM_LoadKeyContext(  
  UINT32 keyContextSize,
  BYTE *keyContextBlob,  
  TPM_KEY_HANDLE *keyHandle 
)
{
  info("TPM_LoadKeyContext() not implemented yet");
  /* TODO: implement TPM_LoadKeyContext() */
  return TPM_FAIL;
}

TPM_RESULT TPM_SaveAuthContext(  
  TPM_AUTHHANDLE authandle,  
  UINT32 *authContextSize,
  BYTE **authContextBlob  
)
{
  info("TPM_SaveAuthContext() not implemented yet");
  /* TODO: implement TPM_SaveAuthContext() */
  return TPM_FAIL;
}

TPM_RESULT TPM_LoadAuthContext(  
  UINT32 authContextSize,
  BYTE *authContextBlob,  
  TPM_KEY_HANDLE *authHandle 
)
{
  info("TPM_LoadAuthContext() not implemented yet");
  /* TODO: implement TPM_LoadAuthContext() */
  return TPM_FAIL;
}

TPM_RESULT TPM_DirWriteAuth(  
  TPM_DIRINDEX dirIndex,
  TPM_DIRVALUE *newContents,
  TPM_AUTH *auth1
)
{
  info("TPM_DirWriteAuth() not implemented yet");
  /* TODO: implement TPM_DirWriteAuth() */
  return TPM_FAIL;
}

TPM_RESULT TPM_DirRead(  
  TPM_DIRINDEX dirIndex,  
  TPM_DIRVALUE *dirContents 
)
{
  info("TPM_DirRead() not implemented yet");
  /* TODO: implement TPM_DirRead() */
  return TPM_FAIL;
}

TPM_RESULT TPM_ChangeAuthAsymStart(  
  TPM_KEY_HANDLE idHandle,
  TPM_NONCE *antiReplay,
  TPM_KEY_PARMS *inTempKey,
  TPM_AUTH *auth1,  
  TPM_CERTIFY_INFO *certifyInfo,
  UINT32 *sigSize,
  BYTE **sig ,
  TPM_KEY_HANDLE *ephHandle,
  TPM_KEY *outTempKey 
)
{
  info("TPM_ChangeAuthAsymStart() not implemented yet");
  /* TODO: implement TPM_ChangeAuthAsymStart() */
  return TPM_FAIL;
}

TPM_RESULT TPM_ChangeAuthAsymFinish(  
  TPM_KEY_HANDLE parentHandle,
  TPM_KEY_HANDLE ephHandle,
  TPM_ENTITY_TYPE entityType,
  TPM_HMAC *newAuthLink,
  UINT32 newAuthSize,
  BYTE *encNewAuth,
  UINT32 encDataSize,
  BYTE *encData,
  TPM_AUTH *auth1,  
  UINT32 *outDataSize,
  BYTE **outData ,
  TPM_NONCE *saltNonce,
  TPM_DIGEST *changeProof 
)
{
  info("TPM_ChangeAuthAsymFinish() not implemented yet");
  /* TODO: implement TPM_ChangeAuthAsymFinish() */
  return TPM_FAIL;
}

TPM_RESULT TPM_Reset()
{
  int i;
  info("TPM_Reset()");
  /* invalidate all authorizaion sessions */
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    TPM_SESSION_DATA *session = &tpmData.stany.data.sessions[i]; 
    if (session->type == TPM_ST_OIAP || session->type == TPM_ST_OSAP)
      memset(session, 0, sizeof(*session));
  }
  /* TODO: invalidate AuthContextSave structures */
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CertifySelfTest(  
  TPM_KEY_HANDLE keyHandle,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,  
  UINT32 *sigSize,
  BYTE **sig  
)
{
  info("TPM_CertifySelfTest() not implemented yet");
  /* TODO: implement TPM_CertifySelfTest() */
  return TPM_FAIL;
}

TPM_RESULT TPM_OwnerReadPubek(  
  TPM_AUTH *auth1,  
  TPM_PUBKEY *pubEndorsementKey 
)
{
  info("TPM_OwnerReadPubek() not implemented yet");
  /* TODO: implement TPM_OwnerReadPubek() */
  return TPM_FAIL;
}

