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
#include "tpm_handles.h"
#include "tpm_data.h"
#include "crypto/hmac.h"
#include "crypto/sha1.h"
#include "linux_module.h"

/*
 * Authorization Changing ([TPM_Part3], Section 17)
 */

TPM_RESULT TPM_ChangeAuth(
  TPM_KEY_HANDLE parentHandle,
  TPM_PROTOCOL_ID protocolID,
  TPM_ENCAUTH *newAuth,
  TPM_ENTITY_TYPE entityType,
  UINT32 encDataSize,
  BYTE *encData,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  UINT32 *outDataSize,
  BYTE **outData
)
{
  info("TPM_ChangeAuth() not implemented yet");
  /* TODO: implement TPM_ChangeAuth() */
  return TPM_FAIL;
}

TPM_RESULT TPM_ChangeAuthOwner(
  TPM_PROTOCOL_ID protocolID,
  TPM_ENCAUTH *newAuth,
  TPM_ENTITY_TYPE entityType,
  TPM_AUTH *auth1
)
{
  info("TPM_ChangeAuthOwner() not implemented yet");
  /* TODO: implement TPM_ChangeAuthOwner() */
  return TPM_FAIL;
}

/*
 * Authorization Sessions ([TPM_Part3], Section 18)
 */

static UINT32 get_free_session(BYTE type)
{
  UINT32 i;
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    if (tpmData.stany.data.sessions[i].type == TPM_ST_INVALID) {
      tpmData.stany.data.sessions[i].type = type;
      return INDEX_TO_AUTH_HANDLE(i);
    } 
  }
  return TPM_INVALID_HANDLE;
}

TPM_RESULT TPM_OIAP(TPM_AUTHHANDLE *authHandle, TPM_NONCE *nonceEven)
{
  TPM_SESSION_DATA *session;
  info("TPM_OIAP()");
  /* get a free session if any is left */
  *authHandle = get_free_session(TPM_ST_OIAP); 
  session = tpm_get_auth(*authHandle);
  if (session == NULL) return TPM_RESOURCES;
  /* setup session */
  get_random_bytes(nonceEven->nonce, sizeof(nonceEven->nonce));
  memcpy(&session->nonceEven, nonceEven, sizeof(TPM_NONCE));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_OSAP(TPM_ENTITY_TYPE entityType, UINT32 entityValue, 
                    TPM_NONCE *nonceOddOSAP, TPM_AUTHHANDLE *authHandle,
                    TPM_NONCE *nonceEven, TPM_NONCE *nonceEvenOSAP)
{
  hmac_ctx_t ctx;
  TPM_SESSION_DATA *session;
  TPM_SECRET *secret = NULL;
  info("TPM_OSAP()");
  /* get a free session if any is left */
  *authHandle = get_free_session(TPM_ST_OSAP);
  session = tpm_get_auth(*authHandle);
  if (session == NULL) return TPM_RESOURCES;
  /* get ressource handle and the dedicated secret */
  switch (entityType) {
    case TPM_ET_KEYHANDLE:
      session->handle = entityValue;
      if (session->handle == TPM_KH_OPERATOR) return TPM_INVALID_KEYHANDLE;
      if (tpm_get_key(session->handle) != NULL)
        secret = &tpm_get_key(session->handle)->usageAuth;
      break;
    case TPM_ET_OWNER: 
      session->handle = TPM_KH_OWNER; 
      if (tpmData.permanent.flags.owned)
        secret = &tpmData.permanent.data.ownerAuth;
      break;
    case TPM_ET_SRK: 
      session->handle = TPM_KH_SRK; 
      if (tpmData.permanent.data.srk.valid)
        secret = &tpmData.permanent.data.srk.usageAuth;
      break;
    case TPM_ET_COUNTER: 
      session->handle = entityValue;
      if (tpm_get_counter(session->handle) != NULL)
        secret = &tpm_get_counter(session->handle)->usageAuth; 
      break;
    case TPM_ET_NV:
      /* TODO: session->handle = entityValue;
      if (tpm_get_nvdata(session->handle) != NULL)
        secret = &tpm_get_nvdata(session->handle)->usageAuth;*/
      break;
  }
  if (secret == NULL) {
    memset(session, 0, sizeof(*session));
    return TPM_BAD_PARAMETER;
  }
  /* generate nonces */
  get_random_bytes(nonceEven->nonce, sizeof(nonceEven->nonce));
  memcpy(&session->nonceEven, nonceEven, sizeof(TPM_NONCE));
  get_random_bytes(nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
  /* compute shared secret */
  hmac_init(&ctx, *secret, sizeof(*secret));
  hmac_update(&ctx, nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
  hmac_update(&ctx, nonceOddOSAP->nonce, sizeof(nonceOddOSAP->nonce));
  hmac_final(&ctx, session->sharedSecret);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_DSAP(  
  TPM_KEY_HANDLE KeyHandle,
  UINT32 entityValueSize,
  BYTE *entityValue,
  TPM_NONCE *nonceOddDSAP,  
  TPM_AUTHHANDLE *authHandle,
  TPM_NONCE *nonceEven,
  TPM_NONCE *nonceEvenDSAP 
)
{
  info("TPM_DSAP() not implemented yet");
  /* TODO: implement TPM_DSAP() */
  return TPM_FAIL;
}

TPM_RESULT TPM_SetOwnerPointer(  
  TPM_ENTITY_TYPE entityType,
  UINT32 entityValue
)
{
  info("TPM_SetOwnerPointer() not implemented yet");
  /* TODO: implement TPM_SetOwnerPointer() */
  return TPM_FAIL;
}

TPM_RESULT tpm_verify_auth(TPM_AUTH *auth, TPM_SECRET secret, 
                           TPM_HANDLE handle)
{
  hmac_ctx_t ctx;
  TPM_SESSION_DATA *session;
  UINT32 auth_handle = cpu_to_be32(auth->authHandle);
  
  info("tpm_verify_auth(%08x)", auth->authHandle);
  /* get dedicated authorizaion session */
  session = tpm_get_auth(auth->authHandle);
  if (session == NULL) return TPM_INVALID_AUTHHANDLE;
  /* setup authorization */
  if (session->type == TPM_ST_OIAP) {
    debug("[TPM_ST_OIAP]");
    /* We copy the secret because it might be deleted or invalidated 
       afterwards, but we need it again for authorizing the response. */
    memcpy(session->sharedSecret, secret, sizeof(TPM_SECRET));
  } else if (session->type == TPM_ST_OSAP) {
    debug("[TPM_ST_OSAP]");
    if (session->handle != handle) return TPM_AUTHFAIL;
  } else {
    return TPM_INVALID_AUTHHANDLE;
  }
  auth->secret = &session->sharedSecret;
  /* verify authorization */
  hmac_init(&ctx, *auth->secret, sizeof(*auth->secret));
  hmac_update(&ctx, auth->digest, sizeof(auth->digest));
  if (session->type == TPM_ST_OIAP && FALSE) 
  hmac_update(&ctx, (BYTE*)&auth_handle, 4);
  hmac_update(&ctx, session->nonceEven.nonce, sizeof(session->nonceEven.nonce));
  hmac_update(&ctx, auth->nonceOdd.nonce, sizeof(auth->nonceOdd.nonce));
  hmac_update(&ctx, &auth->continueAuthSession, 1);
  hmac_final(&ctx, auth->digest);
  if (memcmp(auth->digest, auth->auth, sizeof(auth->digest))) return TPM_AUTHFAIL;
  /* generate new nonceEven */
  memcpy(&session->lastNonceEven, &session->nonceEven, sizeof(TPM_NONCE));
  get_random_bytes(auth->nonceEven.nonce, sizeof(auth->nonceEven.nonce));
  memcpy(&session->nonceEven, &auth->nonceEven, sizeof(TPM_NONCE));
  return TPM_SUCCESS;
}

void tpm_decrypt_auth_secret(TPM_ENCAUTH encAuth, TPM_SECRET secret,
                             TPM_NONCE *nonce, TPM_SECRET plainAuth)
{
  int i;
  sha1_ctx_t ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, secret, sizeof(TPM_SECRET));
  sha1_update(&ctx, nonce->nonce, sizeof(nonce->nonce));
  sha1_final(&ctx, plainAuth);
  for (i = 0; i < sizeof(TPM_SECRET); i++)
    plainAuth[i] ^= encAuth[i];
}


