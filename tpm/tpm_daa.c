/* Software-Based Trusted Platform Module (TPM) Emulator for Linux
 * Copyright (C) 2004 Mario Strasser <mast@gmx.net>,
 *                    Swiss Federal Institute of Technology (ETH) Zurich,
 *               2005 Heiko Stamer <stamer@gaos.org>
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
#include "crypto/sha1.h"
#include "crypto/rsa.h"

UINT32 tpm_get_free_daa_session(void)
{
  UINT32 i;
  for (i = 0; i < TPM_MAX_SESSIONS_DAA; i++) {
    if (tpmData.stany.data.sessionsDAA[i].type == TPM_ST_INVALID) {
      tpmData.stany.data.sessionsDAA[i].type = TPM_ST_DAA;
      return INDEX_TO_DAA_HANDLE(i);
    }
  }
  return TPM_INVALID_HANDLE;
}

/*
 * DAA commands ([TPM_Part3], Section 26)
 * Operations that are necessary to setup a TPM for DAA, execute the 
 * JOIN process, and execute the SIGN process.
 */

TPM_RESULT TPM_DAA_Join(  
  TPM_HANDLE handle,
  BYTE stage,
  UINT32 inputSize0,
  BYTE *inputData0,
  UINT32 inputSize1,
  BYTE *inputData1,
  TPM_AUTH *auth1,
  TPM_COMMAND_CODE *ordinal,
  UINT32 *outputSize,
  BYTE **outputData
)
{
  sha1_ctx_t sha1;
  BYTE scratch[256];
  TPM_DAA_SESSION_DATA *session = NULL;
  
  info("TPM_DAA_Join(), execute stage = %d", stage);
  
  /* Initalize internal scratch board */
  memset(scratch, 0, sizeof(scratch));
  
  /* Verify and initalize the session, for all stages greater than zero. */
  if (stage > 0) {
    if (!(HANDLE_TO_INDEX(handle) < TPM_MAX_SESSIONS_DAA))
      return TPM_BADHANDLE;
    if (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].type != 
      TPM_ST_DAA)
        return TPM_BADHANDLE;
    if (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].handle != 
      handle)
        return TPM_BADHANDLE;
    session = &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)];
  }
  
  /* TPM_DAA_JOIN [TPM_Part3], Section 26.1, Rev. 85 */
  switch (stage) {
    case 0:
    {
      UINT32 cnt;
      
      /* Determine that sufficient resources are available to perform a
       * DAA_Join. Assign session handle for this DAA_Join. */
      handle = tpm_get_free_daa_session();
      if (handle == TPM_INVALID_HANDLE)
        return TPM_RESOURCES;
      session = &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)];
//TODO: check resources
      /* Set all fields in DAA_issuerSettings = NULL */
      memset(&session->DAA_issuerSettings, 0, sizeof(TPM_DAA_ISSUER));
      /* Set all fields in DAA_tpmSpecific = NULL */
      memset(&session->DAA_tpmSpecific, 0, sizeof(TPM_DAA_TPM));
      /* Set all fields in DAA_session = NULL */
      memset(&session->DAA_session, 0, sizeof(TPM_DAA_CONTEXT));
      /* Set all fields in DAA_joinSession = NULL */
      memset(&session->DAA_joinSession, 0, sizeof(TPM_DAA_JOINDATA));
      /* Verify that sizeOf(inputData0) == sizeOf(DAA_tpmSpecific->DAA_count)
       * and return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (!(inputSize0 == sizeof(session->DAA_tpmSpecific.DAA_count)))
        return TPM_DAA_INPUT_DATA0;
      /* Verify that inputData0 > 0, and return TPM_DAA_INPUT_DATA0 on
       * mismatch */
      memcpy(&cnt, inputData0, inputSize0);
      if (!(cnt > 0))
        return TPM_DAA_INPUT_DATA0;
      /* Set DAA_tpmSpecific->DAA_count = inputData0 */
      session->DAA_tpmSpecific.DAA_count = cnt;
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific ||
       * DAA_joinSession) */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific, 
        sizeof(TPM_DAA_TPM));
      sha1_update(&sha1, (BYTE*) &session->DAA_joinSession, 
        sizeof(TPM_DAA_JOINDATA));
      sha1_final(&sha1, session->DAA_session.DAA_digestContext.digest);
      /* Set DAA_session->DAA_stage = 1 */
      session->DAA_session.DAA_stage = 1;
      /* Assign session handle for DAA_Join */
// WATCH: this step is already done at the top
      /* Set outputData = new session handle */
      *outputSize = sizeof(TPM_HANDLE);
      memcpy(*outputData, &handle, *outputSize);
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 1:
    {
      TPM_DIGEST dgt;
      rsa_public_key_t key;
      BYTE *signedData, *signatureValue;
      
      /* Verify that DAA_session->DAA_stage == 1. Return TPM_DAA_STAGE
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 1)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(
       * DAA_tpmSpecific || DAA_joinSession) */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific, 
        sizeof(TPM_DAA_TPM));
      sha1_update(&sha1, (BYTE*) &session->DAA_joinSession, 
        sizeof(TPM_DAA_JOINDATA));
      sha1_final(&sha1, dgt.digest);
      if (memcmp(dgt.digest, session->DAA_session.DAA_digestContext.digest, 
        sizeof(TPM_DIGEST)))
          return TPM_DAA_TPM_SETTINGS;
      /* Verify that sizeOf(inputData0) == DAA_SIZE_issuerModulus and
       * return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (!(inputSize0 == DAA_SIZE_issuerModulus))
        return TPM_DAA_INPUT_DATA0;
      /* If DAA_session->DAA_scratch == NULL: */
      if (!memcmp(scratch, session->DAA_session.DAA_scratch, sizeof(scratch))) {
        /* Set DAA_session->DAA_scratch = inputData0 */
        memcpy(session->DAA_session.DAA_scratch, inputData0, inputSize0);
        /* Set DAA_joinSession->DAA_digest_n0 = 
         * SHA-1(DAA_session->DAA_scratch) */
        sha1_init(&sha1);
        sha1_update(&sha1, (BYTE*) session->DAA_session.DAA_scratch, 
          sizeof(session->DAA_session.DAA_scratch));
        sha1_final(&sha1, session->DAA_joinSession.DAA_digest_n0.digest);
        /* Set DAA_tpmSpecific->DAA_rekey = SHA-1(TPM_DAA_TPM_SEED || 
         * DAA_joinSession->DAA_digest_n0) */
        sha1_init(&sha1);
        sha1_update(&sha1, (BYTE*) tpmData.permanent.data.tpmDAASeed.digest, 
          sizeof(tpmData.permanent.data.tpmDAASeed.digest));
        sha1_update(&sha1, 
          (BYTE*) session->DAA_joinSession.DAA_digest_n0.digest, 
          sizeof(session->DAA_joinSession.DAA_digest_n0.digest));
        sha1_final(&sha1, session->DAA_tpmSpecific.DAA_rekey.digest);
      /* Else (If DAA_session->DAA_scratch != NULL): */
      } else {
        /* Set signedData = inputData0 */
        signedData = inputData0;
        /* Verify that sizeOf(inputData1) == DAA_SIZE_issuerModulus and 
         * return error TPM_DAA_INPUT_DATA1 on mismatch */
        if (!(inputSize1 == DAA_SIZE_issuerModulus))
          return TPM_DAA_INPUT_DATA1;
        /* Set signatureValue = inputData1 */
        signatureValue = inputData1;
        /* Use the RSA key == [DAA_session->DAA_scratch] to verify that 
         * signatureValue is a signature on signedData, and return error 
         * TPM_DAA_ISSUER_VALIDITY on mismatch */
//TODO: determine correct endianess and message encoding
        if (rsa_import_public_key(&key, RSA_LSB_FIRST, 
          session->DAA_session.DAA_scratch, DAA_SIZE_issuerModulus, NULL, 0))
            return TPM_DAA_ISSUER_VALIDITY;
        if (rsa_verify(&key, RSA_ES_OAEP_SHA1, signedData, inputSize0, 
          signatureValue))
            return TPM_DAA_ISSUER_VALIDITY;
        rsa_release_public_key(&key);
        /* Set DAA_session->DAA_scratch = signedData */
        memcpy(session->DAA_session.DAA_scratch, inputData0, inputSize0);
      }
      /* Decrement DAA_tpmSpecific->DAA_count by 1 (unity) */
      session->DAA_tpmSpecific.DAA_count--;
      /* If DAA_tpmSpecific->DAA_count == 0: */
      if (session->DAA_tpmSpecific.DAA_count == 0) {
        /* Increment DAA_Session->DAA_Stage by 1 */
        session->DAA_session.DAA_stage++;
      }
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific, 
        sizeof(TPM_DAA_TPM));
      sha1_update(&sha1, (BYTE*) &session->DAA_joinSession, 
        sizeof(TPM_DAA_JOINDATA));
      sha1_final(&sha1, session->DAA_session.DAA_digestContext.digest);
      /* Set outputData = NULL */
      outputData = NULL;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 2:
    {
      TPM_DIGEST dgt;
      rsa_public_key_t key;
      BYTE *signedData, *signatureValue;
      
      /* Verify that DAA_session->DAA_stage == 2. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 2)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error
       * TPM_DAA_TPM_SETTINGS on mismatch */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific, 
        sizeof(TPM_DAA_TPM));
      sha1_update(&sha1, (BYTE*) &session->DAA_joinSession, 
        sizeof(TPM_DAA_JOINDATA));
      sha1_final(&sha1, dgt.digest);
      if (memcmp(dgt.digest, session->DAA_session.DAA_digestContext.digest, 
        sizeof(TPM_DIGEST)))
          return TPM_DAA_TPM_SETTINGS;
      /* Verify that sizeOf(inputData0) == sizeOf(TPM_DAA_ISSUER) and 
       * return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (!(inputSize0 == sizeof(TPM_DAA_ISSUER)))
        return TPM_DAA_INPUT_DATA0;
      /* Set DAA_issuerSettings = inputData0. Verify that all fields in 
       * DAA_issuerSettings are present and return error
       * TPM_DAA_INPUT_DATA0 if not. */
      memcpy(&session->DAA_issuerSettings, inputData0, 
        sizeof(TPM_DAA_ISSUER));
      if (!(session->DAA_issuerSettings.tag == TPM_TAG_DAA_ISSUER))
        return TPM_DAA_INPUT_DATA0;
      /* Verify that sizeOf(inputData1) == DAA_SIZE_issuerModulus and 
       * return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (!(inputSize1 == DAA_SIZE_issuerModulus))
        return TPM_DAA_INPUT_DATA1;
      /* Set signatureValue = inputData1 */
      signatureValue = inputData1;
      /* Set signedData = (DAA_joinSession->DAA_digest_n0 || 
       * DAA_issuerSettings) */
//WATCH: ??? SHA-1(DAA_joinSession->DAA_digest_n0 || DAA_issuerSettings)
      memcpy(scratch, session->DAA_joinSession.DAA_digest_n0.digest, 
        sizeof(TPM_DIGEST));
      memcpy(scratch + sizeof(session->DAA_joinSession.DAA_digest_n0.digest), 
        &session->DAA_issuerSettings, sizeof(TPM_DAA_ISSUER));
      signedData = scratch;
      /* Use the RSA key [DAA_session->DAA_scratch] to verify that 
       * signatureValue is a signature on signedData, and return error 
       * TPM_DAA_ISSUER_VALIDITY on mismatch */
//TODO: determine correct endianess and message encoding
        if (rsa_import_public_key(&key, RSA_LSB_FIRST, 
          session->DAA_session.DAA_scratch, DAA_SIZE_issuerModulus, NULL, 0))
            return TPM_DAA_ISSUER_VALIDITY;
        if (rsa_verify(&key, RSA_ES_OAEP_SHA1, signedData, 
          sizeof(TPM_DIGEST) + sizeof(TPM_DAA_ISSUER), signatureValue))
            return TPM_DAA_ISSUER_VALIDITY;
        rsa_release_public_key(&key);
      /* Set DAA_tpmSpecific->DAA_digestIssuer == SHA-1(DAA_issuerSettings) */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_issuerSettings, 
        sizeof(TPM_DAA_ISSUER));
      sha1_final(&sha1, session->DAA_tpmSpecific.DAA_digestIssuer.digest);
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific, 
        sizeof(TPM_DAA_TPM));
      sha1_update(&sha1, (BYTE*) &session->DAA_joinSession, 
        sizeof(TPM_DAA_JOINDATA));
      sha1_final(&sha1, session->DAA_session.DAA_digestContext.digest);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 3:
      break;
    case 4:
      break;
    case 5:
      break;
    case 6:
      break;
    case 7:
      break;
    case 8:
      break;
    case 9:
      break;
    case 10:
      break;
    case 11:
      break;
    case 12:
      break;
    case 13:
      break;
    case 14:
      break;
    case 15:
      break;
    case 16:
      break;
    case 17:
      break;
    case 18:
      break;
    case 19:
      break;
    case 20:
      break;
    case 21:
      break;
    case 22:
      break;
    case 23:
      break;
    case 24:
      break;
    default:
      return TPM_DAA_STAGE;
  }
  
  info("TPM_DAA_Join() not implemented yet");
  return TPM_FAIL;
}

TPM_RESULT TPM_DAA_Sign(  
  TPM_HANDLE handle,
  BYTE stage,
  UINT32 inputSize0,
  BYTE *inputData0,
  UINT32 inputSize1,
  BYTE *inputData1,
  TPM_AUTH *auth1,
  TPM_COMMAND_CODE *ordinal,
  UINT32 *outputSize,
  BYTE **outputData
)
{
  info("TPM_DAA_Sign() not implemented yet");
  /* TODO: implement TPM_DAA_Sign() */
  return TPM_FAIL;
}
