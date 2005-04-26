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
#include "crypto/sha1.h"
#include "crypto/rsa.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"

/*
 * Integrity Collection and Reporting ([TPM_Part3], Section 16)
 * This section deals with what commands have direct access to the PCR.
 */

#define PCR_ATTRIB     tpmData.permanent.data.pcrAttrib
#define PCR_VALUE      tpmData.permanent.data.pcrValue
#define LOCALITY       tpmData.stany.flags.localityModifier

TPM_RESULT TPM_Extend(TPM_PCRINDEX pcrNum, TPM_DIGEST *inDigest, 
                      TPM_PCRVALUE *outDigest)
{
  sha1_ctx_t ctx;
  UINT32 be_num = cpu_to_be32(pcrNum);

  info("TPM_Extend()");
  if (pcrNum > TPM_NUM_PCR) return TPM_BADINDEX;
  if (!PCR_ATTRIB[pcrNum].pcrExtendLocal[LOCALITY]) return TPM_BAD_LOCALITY;
  /* compute new PCR value as SHA-1(pcrNUM || old PCR value || inDigest) */
  sha1_init(&ctx);
  sha1_update(&ctx, (BYTE*)&be_num, 4);
  sha1_update(&ctx, PCR_VALUE[pcrNum].digest, sizeof(*PCR_VALUE[pcrNum].digest));
  sha1_update(&ctx, inDigest->digest, sizeof(*inDigest->digest));
  sha1_final(&ctx, PCR_VALUE[pcrNum].digest);  
  /* set output digest */
  if (tpmData.permanent.flags.disable) {
    memset(outDigest->digest, 0, sizeof(*outDigest->digest));
  } else {
    memcpy(outDigest, &PCR_VALUE[pcrNum], sizeof(TPM_PCRVALUE));
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_PCRRead(TPM_PCRINDEX pcrIndex, TPM_PCRVALUE *outDigest)
{
  info("TPM_PCRRead()");
  if (pcrIndex > TPM_NUM_PCR) return TPM_BADINDEX;
  memcpy(outDigest, &PCR_VALUE[pcrIndex], sizeof(TPM_PCRVALUE));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Quote(TPM_KEY_HANDLE keyHandle, TPM_NONCE *extrnalData,
                     TPM_PCR_SELECTION *targetPCR, TPM_AUTH *auth1,  
                     TPM_PCR_COMPOSITE *pcrData, 
                     UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_COMPOSITE_HASH hash;
  BYTE buf[48];
  info("TPM_Quote()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || key->authDataUsage != TPM_AUTH_NEVER) {      
    res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;    
  }
  if ((key->keyUsage != TPM_KEY_SIGNING && key->keyUsage != TPM_KEY_LEGACY)
      || key->sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1) 
    return TPM_INVALID_KEYUSAGE;
  /* compute composite hash */
  res = tpm_compute_pcr_digest(targetPCR, &hash, pcrData);
  if (res != TPM_SUCCESS) return res;
  /* setup quote info and sign it */
  memcpy(&buf[ 0], "\x01\x01\x00\x00QUOT", 8);
  memcpy(&buf[ 8], hash.digest, 20);
  memcpy(&buf[28], extrnalData->nonce, 20);
  *sigSize = key->key.size >> 3;
  *sig = tpm_malloc(*sigSize);
  if (*sig == NULL) return TPM_FAIL;
  if (rsa_sign(&key->key, RSA_SSA_PKCS1_SHA1, buf, 48, *sig)) {
    tpm_free(*sig);
    return TPM_FAIL;
  } 
  return TPM_SUCCESS;
}

TPM_RESULT TPM_PCR_Reset(TPM_PCR_SELECTION *pcrSelection)
{
  int i;
  info("TPM_PCR_Reset()");
  if ((pcrSelection->sizeOfSelect * 8) > TPM_NUM_PCR)
    return TPM_INVALID_PCR_INFO;
  /* this command must be atomic, thus we first verify that all 
     registers are resetable ... */ 
  for (i = 0; i < pcrSelection->sizeOfSelect * 8; i++) {
    /* is PCR number i selected ? */
    if (pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7))) {
      if (!PCR_ATTRIB[i].pcrReset) return TPM_NOTRESETABLE;
      if (!PCR_ATTRIB[i].pcrResetLocal[LOCALITY]) return TPM_NOTLOCAL;
    }
  }
  /* ... then we reset all registers at once */
  for (i = 0; i < pcrSelection->sizeOfSelect * 8; i++) {
    /* is PCR number i selected ? */
    if (pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7))) {
      memset(PCR_VALUE[i].digest, 0, sizeof(*PCR_VALUE[i].digest));
    }
  }
  return TPM_SUCCESS;
}

TPM_RESULT tpm_compute_pcr_digest(TPM_PCR_SELECTION *pcrSelection, 
                                  TPM_COMPOSITE_HASH *digest,
                                  TPM_PCR_COMPOSITE *composite)
{
  int i,j;
  TPM_PCR_COMPOSITE comp;
  sha1_ctx_t ctx;
  UINT32 len;
  BYTE *buf, *ptr;
  info("tpm_compute_pcr_digest()");
  /* create PCR composite */
  if ((pcrSelection->sizeOfSelect * 8) > TPM_NUM_PCR
      || pcrSelection->sizeOfSelect == 0) return TPM_INVALID_PCR_INFO;
  for (i = 0, j = 0; i < pcrSelection->sizeOfSelect * 8; i++) {
    /* is PCR number i selected ? */
    if (pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7))) {
      memcpy(&comp.pcrValue[j++], &PCR_VALUE[i], sizeof(TPM_PCRVALUE));
    }
  }
  memcpy(&comp.select, pcrSelection, sizeof(TPM_PCR_SELECTION));
  comp.valueSize = j * sizeof(TPM_PCRVALUE);
  /* marshal composite and compute hash */
  len = sizeof_TPM_PCR_COMPOSITE(comp);
  buf = ptr = tpm_malloc(len);
  if (buf == NULL
      || tpm_marshal_TPM_PCR_COMPOSITE(&ptr, &len, &comp)) {
     tpm_free(buf);
     return TPM_FAIL;
  }
  sha1_init(&ctx);
  sha1_update(&ctx, buf, sizeof_TPM_PCR_COMPOSITE(comp));
  sha1_final(&ctx, digest->digest);
  tpm_free(buf);
  /* copy composite if requested */
  if (composite != NULL) 
    memcpy(composite, &comp, sizeof(TPM_PCR_COMPOSITE));
  return TPM_SUCCESS;
}

