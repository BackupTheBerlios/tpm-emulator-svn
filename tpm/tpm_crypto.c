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
#include "tpm_handles.h"
#include "crypto/sha1.h"
#include "linux_module.h"

/*
 * Cryptographic Functions ([TPM_Part3], Section 13)
 */

static sha1_ctx_t sha1_ctx;
static BOOL sha1_ctx_valid = FALSE;

TPM_RESULT TPM_SHA1Start(UINT32 *maxNumBytes)
{
  info("TPM_SHA1Start()");
  sha1_init(&sha1_ctx);
  sha1_ctx_valid = TRUE;
  /* this limit was arbitrarily choosen */
  *maxNumBytes = 2048;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SHA1Update(UINT32 numBytes, BYTE *hashData)
{
  info("TPM_SHA1Update()");
  if (!sha1_ctx_valid) return TPM_SHA_THREAD;
  sha1_update(&sha1_ctx, hashData, numBytes);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SHA1Complete(UINT32 hashDataSize, BYTE *hashData, 
                            TPM_DIGEST *hashValue)
{
  info("TPM_SHA1Complete()");
  if (!sha1_ctx_valid) return TPM_SHA_THREAD;
  sha1_ctx_valid = FALSE;
  sha1_update(&sha1_ctx, hashData, hashDataSize);
  sha1_final(&sha1_ctx, hashValue->digest);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SHA1CompleteExtend(TPM_PCRINDEX pcrNum, UINT32 hashDataSize, 
                                  BYTE *hashData, TPM_DIGEST *hashValue, 
                                  TPM_PCRVALUE *outDigest)
{
  TPM_RESULT res;
  info("TPM_SHA1CompleteExtend()");
  res = TPM_SHA1Complete(hashDataSize, hashData, hashValue);
  if (res != TPM_SUCCESS) return res;
  return TPM_Extend(pcrNum, hashValue, outDigest);
}

TPM_RESULT TPM_Sign(TPM_KEY_HANDLE keyHandle, UINT32 areaToSignSize, 
                    BYTE *areaToSign, TPM_AUTH *auth1,  
                    UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  info("TPM_Sign()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */ 
  res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
  if (res != TPM_SUCCESS) return res;
  if (key->keyUsage != TPM_KEY_SIGNING && key->keyUsage != TPM_KEY_LEGACY) 
    return TPM_INVALID_KEYUSAGE;
  /* sign data */
  if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_SHA1) {
    /* use signature scheme PKCS1_SHA1_RAW */ 
    if (areaToSignSize != 20) return TPM_BAD_PARAMETER;
    *sigSize = key->key.size >> 3;
    *sig = tpm_malloc(*sigSize);
    if (*sig == NULL || rsa_sign(&key->key, RSA_SSA_PKCS1_SHA1_RAW, 
        areaToSign, areaToSignSize, *sig)) {
      tpm_free(*sig);
      return TPM_FAIL;
    }
  } else if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_DER) {
    /* use signature scheme PKCS1_DER */ 
    if (areaToSignSize > ((key->key.size >> 3) - 11)
        || areaToSignSize == 0) return TPM_BAD_PARAMETER;
    *sigSize = key->key.size >> 3;
    *sig = tpm_malloc(*sigSize);
    if (*sig == NULL || rsa_sign(&key->key, RSA_SSA_PKCS1_DER, 
        areaToSign, areaToSignSize, *sig)) {
      tpm_free(*sig);
      return TPM_FAIL;
    }
  } else if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_INFO) {
    /* use signature scheme PKCS1_SHA1 and TPM_SIG_INFO container */
    BYTE buf[areaToSignSize + 30];
    if ((areaToSignSize + 30) > (key->key.size >> 3)
        || areaToSignSize == 0) return TPM_BAD_PARAMETER;    
    *sigSize = key->key.size >> 3;
    *sig = tpm_malloc(*sigSize);
    if (*sig == NULL) return TPM_FAIL; 
    /* setup TPM_SIG_INFO structure */
    memcpy(&buf[0], "\x05\x00SIGN", 6);
    memcpy(&buf[6], auth1->nonceOdd.nonce, 20);
    *(UINT32*)&buf[26] = cpu_to_be32(areaToSignSize);
    memcpy(&buf[30], areaToSign, areaToSignSize);
    if (rsa_sign(&key->key, RSA_SSA_PKCS1_SHA1, 
        buf, areaToSignSize + 30, *sig)) {
      tpm_free(*sig);
      return TPM_FAIL;
    } 
  } else {
    return TPM_INVALID_KEYUSAGE;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_GetRandom(UINT32 bytesRequested, UINT32 *randomBytesSize, 
                         BYTE **randomBytes)
{
  info("TPM_GetRandom()");
  *randomBytesSize = (bytesRequested < 2048) ? bytesRequested : 2048;
  *randomBytes = tpm_malloc(*randomBytesSize);
  if (*randomBytes == NULL) return TPM_SIZE;  
  get_random_bytes(*randomBytes, *randomBytesSize); 
  return TPM_SUCCESS;
}

TPM_RESULT TPM_StirRandom(UINT32 dataSize, BYTE *inData)
{
  info("TPM_StirRandom()");
  /* nothing to do */
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CertifyKey(  
  TPM_KEY_HANDLE certHandle,
  TPM_KEY_HANDLE keyHandle,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,  
  TPM_CERTIFY_INFO *certifyInfo,
  UINT32 *outDataSize,
  BYTE **outData  
)
{
  info("TPM_CertifyKey() not implemented yet");
  /* TODO: implement TPM_CertifyKey() */
  return TPM_FAIL;
}

TPM_RESULT TPM_CertifyKey2(  
  TPM_KEY_HANDLE certHandle,
  TPM_KEY_HANDLE keyHandle,
  TPM_DIGEST *migrationPubDigest,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,  
  TPM_CERTIFY_INFO *certifyInfo,
  UINT32 *outDataSize,
  BYTE **outData  
)
{
  info("TPM_CertifyKey2() not implemented yet");
  /* TODO: implement TPM_CertifyKey2() */
  return TPM_FAIL;
}

