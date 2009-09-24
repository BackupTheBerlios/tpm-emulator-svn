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
#include "tpm_marshalling.h"
#include "tpm_data.h"
#include "crypto/hmac.h"
#include "crypto/rc4.h"

/*
 * Delegation Commands ([TPM_Part3], Section 19)
 */

TPM_FAMILY_TABLE_ENTRY *tpm_get_family_row(TPM_FAMILY_ID id)
{
  UINT32 i;
  for (i = 0; i < TPM_NUM_FAMILY_TABLE_ENTRY; i++) {
    if (tpmData.permanent.data.familyTable.famRow[i].valid
        && tpmData.permanent.data.familyTable.famRow[i].familyID == id)
      return &tpmData.permanent.data.familyTable.famRow[i];
  }
  return NULL;
}

TPM_DELEGATE_TABLE_ROW *tpm_get_delegate_row(UINT32 row)
{
  if (row < TPM_NUM_DELEGATE_TABLE_ENTRY
      && tpmData.permanent.data.delegateTable.delRow[row].valid)
    return &tpmData.permanent.data.delegateTable.delRow[row];
  return NULL;
}

void tpm_compute_owner_blob_digest(TPM_DELEGATE_OWNER_BLOB *blob,
                                   TPM_DIGEST *digest)
{
  tpm_hmac_ctx_t ctx;
  BYTE buf[sizeof_TPM_DELEGATE_OWNER_BLOB((*blob))];
  BYTE *ptr = buf;
  UINT32 length = sizeof(buf);
  tpm_marshal_TPM_DELEGATE_OWNER_BLOB(&ptr, &length, blob);
  memset(&buf[2 + sizeof_TPM_DELEGATE_PUBLIC(blob->pub)], 0, 20);
  tpm_hmac_init(&ctx, tpmData.permanent.data.tpmProof.nonce,
    sizeof(tpmData.permanent.data.tpmProof.nonce));
  tpm_hmac_update(&ctx, buf, sizeof(buf) - length);
  tpm_hmac_final(&ctx, digest->digest);
}

void tpm_compute_key_blob_digest(TPM_DELEGATE_KEY_BLOB *blob,
                                 TPM_DIGEST *digest)
{
  tpm_hmac_ctx_t ctx;
  BYTE buf[sizeof_TPM_DELEGATE_KEY_BLOB((*blob))];
  BYTE *ptr = buf;
  UINT32 length = sizeof(buf);
  tpm_marshal_TPM_DELEGATE_KEY_BLOB(&ptr, &length, blob);
  memset(&buf[2 + sizeof_TPM_DELEGATE_PUBLIC(blob->pub)], 0, 20);
  tpm_hmac_init(&ctx, tpmData.permanent.data.tpmProof.nonce,
    sizeof(tpmData.permanent.data.tpmProof.nonce));
  tpm_hmac_update(&ctx, buf, sizeof(buf) - length);
  tpm_hmac_final(&ctx, digest->digest);
}

int tpm_encrypt_sensitive(BYTE *iv, UINT32 iv_size,
                          TPM_DELEGATE_SENSITIVE *sensitive,
                          BYTE **enc, UINT32 *enc_size)
{
  UINT32 len;
  BYTE *ptr;
  tpm_rc4_ctx_t rc4_ctx;
  BYTE key[TPM_SYM_KEY_SIZE + iv_size];
  /* marshal context */
  *enc_size = len = sizeof_TPM_DELEGATE_SENSITIVE((*sensitive));
  *enc = ptr = tpm_malloc(len);
  if (*enc == NULL) return -1;
  if (tpm_marshal_TPM_DELEGATE_SENSITIVE(&ptr, &len, sensitive)) {
    tpm_free(*enc);
    return -1;
  }
  /* encrypt context */
  memcpy(key, tpmData.permanent.data.delegateKey, TPM_SYM_KEY_SIZE);
  memcpy(&key[TPM_SYM_KEY_SIZE], iv, iv_size);
  tpm_rc4_init(&rc4_ctx, key, sizeof(key));
  tpm_rc4_crypt(&rc4_ctx, *enc, *enc, *enc_size);
  return 0;
}

int tpm_decrypt_sensitive(BYTE *iv, UINT32 iv_size, BYTE *enc, UINT32 enc_size,
                          TPM_DELEGATE_SENSITIVE *sensitive, BYTE **buf)
{
  UINT32 len;
  BYTE *ptr;
  tpm_rc4_ctx_t rc4_ctx;
  BYTE key[TPM_SYM_KEY_SIZE + iv_size];
  len = enc_size;
  *buf = ptr = tpm_malloc(len);
  if (*buf == NULL) return -1;
  /* decrypt context */
  memcpy(key, tpmData.permanent.data.delegateKey, TPM_SYM_KEY_SIZE);
  memcpy(&key[TPM_SYM_KEY_SIZE], iv, iv_size);
  tpm_rc4_init(&rc4_ctx, key, sizeof(key));
  tpm_rc4_crypt(&rc4_ctx, enc, *buf, enc_size);
  /* unmarshal context */
  if (tpm_unmarshal_TPM_DELEGATE_SENSITIVE(&ptr, &len, sensitive)) {
    tpm_free(*buf);
    return -1;
  }
  return 0;
}

TPM_RESULT TPM_Delegate_Manage(  
  TPM_FAMILY_ID familyID,
  TPM_FAMILY_OPERATION opFlag,
  UINT32 opDataSize,
  BYTE *opData,
  TPM_AUTH *auth1,  
  UINT32 *retDataSize,
  BYTE **retData  
)
{
  info("TPM_Delegate_Manage() not implemented yet");
  /* TODO: implement TPM_Delegate_Manage() */
  return TPM_FAIL;
}

TPM_RESULT TPM_Delegate_CreateKeyDelegation(  
  TPM_KEY_HANDLE keyHandle,
  TPM_DELEGATE_PUBLIC *publicInfo,
  TPM_ENCAUTH *delAuth,
  TPM_AUTH *auth1,  
  UINT32 *blobSize,
  TPM_DELEGATE_KEY_BLOB *blob 
)
{
  info("TPM_Delegate_CreateKeyDelegation() not implemented yet");
  /* TODO: implement TPM_Delegate_CreateKeyDelegation() */
  return TPM_FAIL;
}

TPM_RESULT TPM_Delegate_CreateOwnerDelegation(  
  BOOL increment,
  TPM_DELEGATE_PUBLIC *publicInfo,
  TPM_ENCAUTH *delAuth,
  TPM_AUTH *auth1,  
  UINT32 *blobSize,
  TPM_DELEGATE_OWNER_BLOB *blob 
)
{
  info("TPM_Delegate_CreateOwnerDelegation() not implemented yet");
  /* TODO: implement TPM_Delegate_CreateOwnerDelegation() */
  return TPM_FAIL;
}

TPM_RESULT TPM_Delegate_LoadOwnerDelegation(  
  TPM_DELEGATE_INDEX index,
  UINT32 blobSize,
  TPM_DELEGATE_OWNER_BLOB *blob,
  TPM_AUTH *auth1
)
{
  info("TPM_Delegate_LoadOwnerDelegation() not implemented yet");
  /* TODO: implement TPM_Delegate_LoadOwnerDelegation() */
  return TPM_FAIL;
}

TPM_RESULT TPM_Delegate_ReadTable(  
  UINT32 *familyTableSize,
  BYTE **familyTable ,
  UINT32 *delegateTableSize,
  BYTE **delegateTable
)
{
  info("TPM_Delegate_ReadTable() not implemented yet");
  /* TODO: implement TPM_Delegate_ReadTable() */
  return TPM_FAIL;
}

TPM_RESULT TPM_Delegate_UpdateVerification(  
  UINT32 inputSize,
  BYTE *inputData,
  TPM_AUTH *auth1,  
  UINT32 *outputSize,
  BYTE **outputData  
)
{
  info("TPM_Delegate_UpdateVerification() not implemented yet");
  /* TODO: implement TPM_Delegate_UpdateVerification() */
  return TPM_FAIL;
}

TPM_RESULT TPM_Delegate_VerifyDelegation(  
  UINT32 delegateSize,
  BYTE *delegation
)
{
  info("TPM_Delegate_VerifyDelegation() not implemented yet");
  /* TODO: implement TPM_Delegate_VerifyDelegation() */
  return TPM_FAIL;
}

