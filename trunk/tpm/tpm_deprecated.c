/* Software-Based Trusted Platform Module (TPM) Emulator for Linux
 * Copyright (C) 2004 Mario Strasser <mast@gmx.net>,
 *                    Swiss Federal Institute of Technology (ETH) Zurich,
 *               2007 Heiko Stamer <stamer@gaos.org>
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
#include "tpm_handles.h"
#include "tpm_marshalling.h"
#include "crypto/rsa.h"

#define SAVE_KEY_CONTEXT_LABEL  ((uint8_t*)"SaveKeyContext..")
#define SAVE_AUTH_CONTEXT_LABEL ((uint8_t*)"SaveAuthContext.")

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

TPM_RESULT TPM_SaveKeyContext(TPM_KEY_HANDLE keyHandle,  
                              UINT32 *keyContextSize, BYTE **keyContextBlob)
{
  TPM_RESULT res;
  TPM_CONTEXT_BLOB contextBlob;
  BYTE *ptr;
  UINT32 len;
  info("TPM_SaveKeyContext()");
  res = TPM_SaveContext(keyHandle, TPM_RT_KEY, SAVE_KEY_CONTEXT_LABEL,
                        keyContextSize, &contextBlob);
  if (res != TPM_SUCCESS) return res;
  len = *keyContextSize;
  *keyContextBlob = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_CONTEXT_BLOB(&ptr, &len, &contextBlob)) res = TPM_FAIL;
  else res = TPM_SUCCESS;
  free_TPM_CONTEXT_BLOB(contextBlob);
  return res;
}

TPM_RESULT TPM_LoadKeyContext(UINT32 keyContextSize,
                              BYTE *keyContextBlob, TPM_KEY_HANDLE *keyHandle)
{
  TPM_CONTEXT_BLOB contextBlob;
  UINT32 len = keyContextSize;
  info("TPM_LoadKeyContext()");
  if (tpm_unmarshal_TPM_CONTEXT_BLOB(&keyContextBlob, 
      &len, &contextBlob)) return TPM_FAIL;
  return TPM_LoadContext(FALSE, TPM_INVALID_HANDLE, keyContextSize, 
                         &contextBlob, keyHandle);
}

TPM_RESULT TPM_SaveAuthContext(TPM_AUTHHANDLE authHandle,  
                               UINT32 *authContextSize, BYTE **authContextBlob)
{
  TPM_RESULT res;
  TPM_CONTEXT_BLOB contextBlob;
  BYTE *ptr;
  UINT32 len;
  info("TPM_SaveAuthContext()");
  res = TPM_SaveContext(authHandle, TPM_RT_KEY, SAVE_AUTH_CONTEXT_LABEL,
                        authContextSize, &contextBlob);
  if (res != TPM_SUCCESS) return res;
  len = *authContextSize;
  *authContextBlob = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_CONTEXT_BLOB(&ptr, &len, &contextBlob)) res = TPM_FAIL;
  else res = TPM_SUCCESS;
  free_TPM_CONTEXT_BLOB(contextBlob);
  return res;
}

TPM_RESULT TPM_LoadAuthContext(UINT32 authContextSize, BYTE *authContextBlob, 
                               TPM_KEY_HANDLE *authHandle)
{
  TPM_CONTEXT_BLOB contextBlob;
  UINT32 len = authContextSize;
  info("TPM_LoadAuthContext()");
  if (tpm_unmarshal_TPM_CONTEXT_BLOB(&authContextBlob, 
      &len, &contextBlob)) return TPM_FAIL;
  return TPM_LoadContext(FALSE, TPM_INVALID_HANDLE, authContextSize, 
                         &contextBlob, authHandle);
}

TPM_RESULT TPM_DirWriteAuth(TPM_DIRINDEX dirIndex, 
                            TPM_DIRVALUE *newContents, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  info("TPM_DirWriteAuth()");
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  if (dirIndex != 1) return TPM_BADINDEX;
  memcpy(&tpmData.permanent.data.DIR, newContents, sizeof(TPM_DIRVALUE));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_DirRead(TPM_DIRINDEX dirIndex, TPM_DIRVALUE *dirContents)
{
  info("TPM_DirRead()");
  if (dirIndex != 1) return TPM_BADINDEX;
  memcpy(dirContents, &tpmData.permanent.data.DIR, sizeof(TPM_DIRVALUE));
  return TPM_SUCCESS;
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
  TPM_RESULT res;
  TPM_KEY_DATA *idKey;
  tpm_rsa_private_key_t rsa;
  UINT32 key_length;
  
  info("TPM_ChangeAuthAsymStart() not implemented yet");
  /* TODO: implement TPM_ChangeAuthAsymStart() */
  return TPM_FAIL;
  
  /* 1. The TPM SHALL verify the AuthData to use the TPM identity key held in
        idHandle. The TPM MUST verify that the key is a TPM identity key. */
    /* get identity key */
    idKey = tpm_get_key(idHandle);
    if (idKey == NULL) return TPM_INVALID_KEYHANDLE;
    /* verify authorization */
    res = tpm_verify_auth(auth1, idKey->usageAuth, idHandle);
    if (res != TPM_SUCCESS) return res;
    /* verify key parameters */
    if (idKey->keyUsage != TPM_KEY_IDENTITY) return TPM_INVALID_KEYUSAGE;
  /* 2. The TPM SHALL validate the algorithm parameters for the key to create
        from the tempKey parameter. */
  /* 3. Recommended key type is RSA */
  /* 4. Minimum RSA key size MUST is 512 bits, recommended RSA key size 
        is 1024 */
  /* 5. For other key types the minimum key size strength MUST be
        comparable to RSA 512 */
  /* 6. If the TPM is not designed to create a key of the requested type,
        return the error code TPM_BAD_KEY_PROPERTY */
  if (inTempKey->algorithmID != TPM_ALG_RSA
      || inTempKey->parmSize == 0
      || inTempKey->parms.rsa.keyLength < 512
      || inTempKey->parms.rsa.numPrimes != 2
      || inTempKey->parms.rsa.exponentSize != 0)
    return TPM_BAD_KEY_PROPERTY;
  /* 7. The TPM SHALL create a new key (k1) in accordance with the
        algorithm parameter.
        The newly created key is pointed to by ephHandle. */
    /* generate key */
    key_length = inTempKey->parms.rsa.keyLength;
    if (tpm_rsa_generate_key(&rsa, key_length)) {
      debug("TPM_ChangeAuthAsymStart(): tpm_rsa_generate_key() failed.");
      return TPM_FAIL;
    }
   

TODO

  /* 8. The TPM SHALL fill in all fields in tempKey using k1 for the
        information. The TPM_KEY->encSize MUST be 0. */

TODO

    /* compute the digest of the wrapped key (without encData) */
    if (tpm_compute_key_digest(outTempKey, &store.pubDataDigest)) {
      debug("TPM_ChangeAuthAsymStart(): tpm_compute_key_digest() failed.");
      return TPM_FAIL;
    }
  /* 9. The TPM SHALL fill in certifyInfo using k1 for the information.
        The certifyInfo->data field is supplied by the antiReplay. */
    /* "Version" field is set according to the deprecated TPM_VERSION
       structure from the old v1.1 specification. */
    memcpy(certifyInfo->tag, tpmData.permanent.data.version[0], 2);
    memcpy(certifyInfo->fill, tpmData.permanent.data.version[2], 1);
    memcpy(certifyInfo->payloadType, tpmData.permanent.data.version[3], 1);
    /* Other fields are filled according to Section 27.4.1 [TPM, Part 3]. */
    certifyInfo->keyUsage = TPM_KEY_AUTHCHANGE;
    certifyInfo->keyFlags = TPM_KEY_FLAG_VOLATILE;
    certifyInfo->authDataUsage = TPM_AUTH_NEVER;
    memcpy(certifyInfo->algorithmParms, inTempKey,
      sizeof_TPM_KEY_PARMS(inTempKey));
    memcpy(certifyInfo->pubkeyDigest, store.pubDataDigest, sizeof(TPM_DIGEST));
    memcpy(certifyInfo->data, antiReplay, sizeof(TPM_NONCE));
    certifyInfo->parentPCRStatus = FALSE;
    certifyInfo->PCRInfoSize = 0;
  
  /* 10. The TPM then signs the certifyInfo parameter using the key
         pointed to by idHandle. The resulting signed blob is returned
         in sig parameter. */

TODO

  return TPM_SUCCESS;
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
  /* invalidate all authorization sessions */
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    TPM_SESSION_DATA *session = &tpmData.stany.data.sessions[i]; 
    if (session->type == TPM_ST_OIAP || session->type == TPM_ST_OSAP)
      memset(session, 0, sizeof(*session));
  }
  /* TODO: invalidate AuthContextSave structures */
  return TPM_SUCCESS;
}

extern TPM_RESULT tpm_sign(TPM_KEY_DATA *key, TPM_AUTH *auth, BOOL isInfo,
  BYTE *areaToSign, UINT32 areaToSignSize, BYTE **sig, UINT32 *sigSize);

TPM_RESULT TPM_CertifySelfTest(TPM_KEY_HANDLE keyHandle, TPM_NONCE *antiReplay,
                               TPM_AUTH *auth1, UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  BYTE buf[35];
  info("TPM_CertifySelfTest()");
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* perform self test */
  res = TPM_SelfTestFull();
  if (res != TPM_SUCCESS) return res;
  /* verify authorization */ 
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
  }
  if (key->keyUsage != TPM_KEY_SIGNING && key->keyUsage != TPM_KEY_LEGACY
      && key->keyUsage != TPM_KEY_IDENTITY) return TPM_INVALID_KEYUSAGE;
  /* not neccessary, because a vendor specific signature is allowed
  if (key->sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1)
    return TPM_BAD_SCHEME;
  */
  /* setup and sign result */
  memcpy(&buf, "Test Passed", 11);
  memcpy(&buf[11], antiReplay->nonce, sizeof(TPM_NONCE));
  memcpy(&buf[31], "\x52\x00\x00\x00", 4);
  return tpm_sign(key, auth1, FALSE, buf, sizeof(buf), sig, sigSize);
}

extern TPM_RESULT tpm_get_pubek(TPM_PUBKEY *pubEndorsementKey);

TPM_RESULT TPM_OwnerReadPubek(TPM_AUTH *auth1, TPM_PUBKEY *pubEndorsementKey)
{
  TPM_RESULT res;
  info("TPM_OwnerReadPubek()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  res = tpm_get_pubek(pubEndorsementKey);
  if (res != TPM_SUCCESS) return res; 
  return TPM_SUCCESS;
}

