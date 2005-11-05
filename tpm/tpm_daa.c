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
#include "crypto/rc4.h"
#include "crypto/hmac.h"
#include "linux_module.h"

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

/* Verify that DAA_session->DAA_digestContext == 
 * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error on mismatch */
TPM_RESULT tpm_daa_verify_digestContext(  
  TPM_DAA_SESSION_DATA *session
)
{
  sha1_ctx_t sha1;
  TPM_DIGEST dgt;
  
  sha1_init(&sha1);
  sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific, sizeof(TPM_DAA_TPM));
  sha1_update(&sha1, (BYTE*) &session->DAA_joinSession, 
    sizeof(TPM_DAA_JOINDATA));
  sha1_final(&sha1, dgt.digest);
  return memcmp(dgt.digest, session->DAA_session.DAA_digestContext.digest, 
    sizeof(TPM_DIGEST));
}

/* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
 * DAA_joinSession) */
void tpm_daa_update_digestContext(  
  TPM_DAA_SESSION_DATA *session
)
{
  sha1_ctx_t sha1;
  
  sha1_init(&sha1);
  sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific, sizeof(TPM_DAA_TPM));
  sha1_update(&sha1, (BYTE*) &session->DAA_joinSession, 
    sizeof(TPM_DAA_JOINDATA));
  sha1_final(&sha1, session->DAA_session.DAA_digestContext.digest);
}

/* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
 * SHA-1(DAA_issuerSettings) and return error on mismatch */
TPM_RESULT tpm_daa_verify_digestIssuer(  
  TPM_DAA_SESSION_DATA *session
)
{
  sha1_ctx_t sha1;
  TPM_DIGEST dgt;
  
  sha1_init(&sha1);
  sha1_update(&sha1, (BYTE*) &session->DAA_issuerSettings, 
    sizeof(TPM_DAA_ISSUER));
  sha1_final(&sha1, dgt.digest);
  return memcmp(dgt.digest, session->DAA_tpmSpecific.DAA_digestIssuer.digest, 
    sizeof(TPM_DIGEST));
}

/* Set DAA_tpmSpecific->DAA_digestIssuer == SHA-1(DAA_issuerSettings) */
void tpm_daa_update_digestIssuer(  
  TPM_DAA_SESSION_DATA *session
)
{
  sha1_ctx_t sha1;
  
  sha1_init(&sha1);
  sha1_update(&sha1, (BYTE*) &session->DAA_issuerSettings, 
    sizeof(TPM_DAA_ISSUER));
  sha1_final(&sha1, session->DAA_tpmSpecific.DAA_digestIssuer.digest);
}

/* Verify that SHA-1(input) == digest and return error !TPM_SUCCESS 
 * on mismatch */
TPM_RESULT tpm_daa_verify_generic(  
  TPM_DIGEST digest,
  BYTE *input,
  UINT32 inputSize
)
{
  sha1_ctx_t sha1;
  TPM_DIGEST dgt;
  
  sha1_init(&sha1);
  sha1_update(&sha1, input, inputSize);
  sha1_final(&sha1, dgt.digest);
  return memcmp(dgt.digest, digest.digest, sizeof(TPM_DIGEST));
}

/* Encryption and decryption of TPM_DAA_SENSITIVE like TPM_CONTEXT_SENSITIVE */
int encrypt_daa(BYTE *iv, UINT32 iv_size, TPM_DAA_SENSITIVE *sensitive, 
                BYTE **enc, UINT32 *enc_size)
{
  UINT32 len;
  BYTE *ptr;
  rc4_ctx_t rc4_ctx;
  BYTE key[TPM_CONTEXT_KEY_SIZE + iv_size];
  /* marshal sensitive */
  *enc_size = len = sizeof_TPM_DAA_SENSITIVE((*sensitive));
  *enc = ptr = tpm_malloc(len);
  if (*enc == NULL || tpm_marshal_TPM_DAA_SENSITIVE(&ptr, &len, sensitive)) {
    tpm_free(*enc);
    return -1;
  }
  /* encrypt sensitive */
  memcpy(key, tpmData.permanent.data.contextKey, TPM_CONTEXT_KEY_SIZE);
  memcpy(&key[TPM_CONTEXT_KEY_SIZE], iv, iv_size);
  rc4_init(&rc4_ctx, key, sizeof(key));
  rc4_crypt(&rc4_ctx, *enc, *enc, *enc_size);
  return 0;
}

int decrypt_daa(BYTE *iv, UINT32 iv_size, BYTE *enc, UINT32 enc_size, 
                TPM_DAA_SENSITIVE *sensitive, BYTE **buf) 
{
  UINT32 len;
  BYTE *ptr;
  rc4_ctx_t rc4_ctx;
  BYTE key[TPM_CONTEXT_KEY_SIZE + iv_size];
  len = enc_size;
  *buf = ptr = tpm_malloc(len);
  if (*buf == NULL) return -1;
  /* decrypt sensitive */
  memcpy(key, tpmData.permanent.data.contextKey, TPM_CONTEXT_KEY_SIZE);
  memcpy(&key[TPM_CONTEXT_KEY_SIZE], iv, iv_size);
  rc4_init(&rc4_ctx, key, sizeof(key));  
  rc4_crypt(&rc4_ctx, enc, *buf, enc_size);
  /* unmarshal sensitive */
  if (tpm_unmarshal_TPM_DAA_SENSITIVE(&ptr, &len, sensitive)) {
    tpm_free(*buf);
    return -1;
  }
  return 0;
}

/* Computation of the HMAC which protects the integrity of the TPM_DAA_BLOB */
int compute_daa_digest(TPM_DAA_BLOB *daaBlob, TPM_DIGEST *digest)
{
  BYTE *buf, *ptr;
  UINT32 len;
  hmac_ctx_t hmac_ctx;
  len = sizeof_TPM_DAA_BLOB((*daaBlob));
  buf = ptr = tpm_malloc(len);
  if (buf == NULL
      || tpm_marshal_TPM_DAA_BLOB(&ptr, &len, daaBlob)) {
    tpm_free(buf);
    return -1;
  }
  memset(&buf[30], 0, 20);
  hmac_init(&hmac_ctx, tpmData.permanent.data.tpmProof.nonce, 
    sizeof(tpmData.permanent.data.tpmProof.nonce));
  hmac_update(&hmac_ctx, buf, sizeof_TPM_DAA_BLOB((*daaBlob)));
  hmac_final(&hmac_ctx, digest->digest);
  tpm_free(buf);
  return 0;
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
  BYTE scratch[256];
  TPM_DAA_SESSION_DATA *session = NULL;
  
  info("TPM_DAA_Join(), handle = %d, execute stage = %d", handle, stage);
  
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
      tpm_daa_update_digestContext(session);
      /* Set DAA_session->DAA_stage = 1 */
      session->DAA_session.DAA_stage = 1;
      /* Assign session handle for DAA_Join */
// WATCH: this step is already done at the top
      /* Set outputData = new session handle */
      *outputSize = sizeof(TPM_HANDLE);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, &handle, *outputSize);
      else
        return TPM_NOSPACE;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 1:
    {
      sha1_ctx_t sha1;
      rsa_public_key_t key;
      BYTE *signedData, *signatureValue;
      
      /* Verify that DAA_session->DAA_stage == 1. Return TPM_DAA_STAGE
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 1)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
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
      tpm_daa_update_digestContext(session);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 2:
    {
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
      if (tpm_daa_verify_digestContext(session))
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
      tpm_daa_update_digestIssuer(session);
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      tpm_daa_update_digestContext(session);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 3:
      /* Verify that DAA_session->DAA_stage == 3. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 3)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Verify that sizeOf(inputData0) == sizeOf(DAA_tpmSpecific->DAA_count)
       * and return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (!(inputSize0 == sizeof(session->DAA_tpmSpecific.DAA_count)))
        return TPM_DAA_INPUT_DATA0;
      /* Set DAA_tpmSpecific->DAA_count = inputData0 */
      memcpy(&session->DAA_tpmSpecific.DAA_count, inputData0, inputSize0);
      /* Obtain random data from the RNG and store it as 
       * DAA_joinSession->DAA_join_u0 */
      tpm_get_random_bytes(session->DAA_joinSession.DAA_join_u0, 
        sizeof(session->DAA_joinSession.DAA_join_u0));
      /* Obtain random data from the RNG and store it as 
       * DAA_joinSession->DAA_join_u1 */
      tpm_get_random_bytes(session->DAA_joinSession.DAA_join_u1, 
        sizeof(session->DAA_joinSession.DAA_join_u1));
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      tpm_daa_update_digestContext(session);
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    case 4:
    {
      BYTE *DAA_generic_R0 = NULL, *DAA_generic_n = NULL;
      sha1_ctx_t sha1;
      mpz_t X, n, f, q, f0, tmp;
      
      /* Verify that DAA_session->DAA_stage == 4. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 4)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_R0 = inputData0 */
      DAA_generic_R0 = inputData0;
      /* Verify that SHA-1(DAA_generic_R0) == 
       * DAA_issuerSettings->DAA_digest_R0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R0, 
        DAA_generic_R0, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1))
          return TPM_DAA_INPUT_DATA1;
      /* Set X = DAA_generic_R0 */
      mpz_init(X);
      mpz_import(X, inputSize0, 1, 1, 0, 0, DAA_generic_R0);
      /* Set n = DAA_generic_n */
      mpz_init(n);
      mpz_import(n, inputSize1, 1, 1, 0, 0, DAA_generic_n);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x00", 1);
      sha1_final(&sha1, scratch);
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x01", 1);
      sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      mpz_init(f), mpz_init(q);
      mpz_import(f, 2 * SHA1_DIGEST_LENGTH, 1, 1, 0, 0, scratch);
      mpz_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, 1, 0, 0, session->DAA_issuerSettings.DAA_generic_q);
      mpz_mod(f, f, q);
      /* Set f0  = f mod 2^DAA_power0 (erase all but the lowest DAA_power0 
       * bits of f) */
      mpz_init(f0), mpz_init(tmp);
      mpz_ui_pow_ui(tmp, 2, DAA_power0);
      mpz_mod(f0, f, tmp);
      /* Set DAA_session->DAA_scratch = (X^f0) mod n */
      mpz_powm(tmp, X, f0, n);
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, tmp);
      mpz_clear(f), mpz_clear(q), mpz_clear(f0), mpz_clear(tmp);
      mpz_clear(X), mpz_clear(n);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 5:
    {
      BYTE *DAA_generic_R1 = NULL, *DAA_generic_n = NULL;
      sha1_ctx_t sha1;
      mpz_t X, Z, n, f, q, f1, tmp;
      
      /* Verify that DAA_session->DAA_stage == 5. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 5)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_R1 = inputData0 */
      DAA_generic_R1 = inputData0;
      /* Verify that SHA-1(DAA_generic_R1) == 
       * DAA_issuerSettings->DAA_digest_R1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R1, 
        DAA_generic_R1, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1))
          return TPM_DAA_INPUT_DATA1;
      /* Set X = DAA_generic_R1 */
      mpz_init(X);
      mpz_import(X, inputSize0, 1, 1, 0, 0, DAA_generic_R1);
      /* Set n = DAA_generic_n */
      mpz_init(n);
      mpz_import(n, inputSize1, 1, 1, 0, 0, DAA_generic_n);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x00", 1);
      sha1_final(&sha1, scratch);
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x01", 1);
      sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      mpz_init(f), mpz_init(q);
      mpz_import(f, 2 * SHA1_DIGEST_LENGTH, 1, 1, 0, 0, scratch);
      mpz_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, 1, 0, 0, session->DAA_issuerSettings.DAA_generic_q);
      mpz_mod(f, f, q);
      /* Shift f right by DAA_power0 bits (discard the lowest DAA_power0 
       * bits) and label the result f1 */
      mpz_init(f1);
      mpz_fdiv_q_2exp(f1, f, DAA_power0);
      /* Set Z = DAA_session->DAA_scratch */
      mpz_init(Z);
      mpz_import(Z, sizeof(session->DAA_session.DAA_scratch), 1, 1, 0, 0, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^f1) mod n */
      mpz_init(tmp);
      mpz_powm(tmp, X, f1, n);
      mpz_mul(tmp, tmp, Z);
      mpz_mod(tmp, tmp, n);
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, tmp);
      mpz_clear(f), mpz_clear(q), mpz_clear(f1), mpz_clear(tmp);
      mpz_clear(X), mpz_clear(n), mpz_clear(Z);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 6:
    {
      BYTE *DAA_generic_S0 = NULL, *DAA_generic_n = NULL;
      mpz_t X, Y, Z, n, tmp;
      
      /* Verify that DAA_session->DAA_stage == 6. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 6)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_S0 = inputData0 */
      DAA_generic_S0 = inputData0;
      /* Verify that SHA-1(DAA_generic_S0) == 
       * DAA_issuerSettings->DAA_digest_S0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S0, 
        DAA_generic_S0, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1))
          return TPM_DAA_INPUT_DATA1;
      /* Set X = DAA_generic_S0 */
      mpz_init(X);
      mpz_import(X, inputSize0, 1, 1, 0, 0, DAA_generic_S0);
      /* Set n = DAA_generic_n */
      mpz_init(n);
      mpz_import(n, inputSize1, 1, 1, 0, 0, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      mpz_init(Z);
      mpz_import(Z, sizeof(session->DAA_session.DAA_scratch), 1, 1, 0, 0, 
        session->DAA_session.DAA_scratch);
      /* Set Y = DAA_joinSession->DAA_join_u0 */
      mpz_init(Y);
      mpz_import(Y, sizeof(session->DAA_joinSession.DAA_join_u0), 1, 1, 0, 0, 
        session->DAA_joinSession.DAA_join_u0);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      mpz_init(tmp);
      mpz_powm(tmp, X, Y, n);
      mpz_mul(tmp, tmp, Z);
      mpz_mod(tmp, tmp, n);
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, tmp);
      mpz_clear(X), mpz_clear(Y), mpz_clear(Z), mpz_clear(n), mpz_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 7:
    {
      BYTE *DAA_generic_S1 = NULL, *DAA_generic_n = NULL;
      sha1_ctx_t sha1;
      mpz_t X, Y, Z, n, tmp;
      
      /* Verify that DAA_session->DAA_stage == 7. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 7)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_S1 = inputData0 */
      DAA_generic_S1 = inputData0;
      /* Verify that SHA-1(DAA_generic_S1) == 
       * DAA_issuerSettings->DAA_digest_S1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S1, 
        DAA_generic_S1, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1))
          return TPM_DAA_INPUT_DATA1;
      /* Set X = DAA_generic_S1 */
      mpz_init(X);
      mpz_import(X, inputSize0, 1, 1, 0, 0, DAA_generic_S1);
      /* Set n = DAA_generic_n */
      mpz_init(n);
      mpz_import(n, inputSize1, 1, 1, 0, 0, DAA_generic_n);
      /* Set Y = DAA_joinSession->DAA_join_u1 */
      mpz_init(Y);
      mpz_import(Y, sizeof(session->DAA_joinSession.DAA_join_u1), 1, 1, 0, 0, 
        session->DAA_joinSession.DAA_join_u1);
      /* Set Z = DAA_session->DAA_scratch */
      mpz_init(Z);
      mpz_import(Z, sizeof(session->DAA_session.DAA_scratch), 1, 1, 0, 0, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      mpz_init(tmp);
      mpz_powm(tmp, X, Y, n);
      mpz_mul(tmp, tmp, Z);
      mpz_mod(tmp, tmp, n);
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, tmp);
      mpz_clear(X), mpz_clear(Y), mpz_clear(Z), mpz_clear(n), mpz_clear(tmp);
      /* Set DAA_session->DAA_digest to the SHA-1(DAA_session->DAA_scratch || 
       * DAA_tpmSpecific->DAA_count || DAA_joinSession->DAA_digest_n0) */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) session->DAA_session.DAA_scratch, 
        sizeof(session->DAA_session.DAA_scratch));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
        sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, 
        (BYTE*) session->DAA_joinSession.DAA_digest_n0.digest, 
        sizeof(session->DAA_joinSession.DAA_digest_n0.digest));
      sha1_final(&sha1, session->DAA_session.DAA_digest.digest);
      /* Set outputData = DAA_session->DAA_scratch */
      *outputSize = sizeof(session->DAA_session.DAA_scratch);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, session->DAA_session.DAA_scratch, *outputSize);
      else
        return TPM_NOSPACE;
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 8:
    {
      size_t sizeNE = 0;
      sha1_ctx_t sha1;
      
      /* Verify that DAA_session->DAA_stage == 8. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 8)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Verify inputSize0 == DAA_SIZE_NE and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (!(inputSize0 == DAA_SIZE_NE))
        return TPM_DAA_INPUT_DATA0;
      /* Set NE = decrypt(inputData0, privEK) */
      if (rsa_decrypt(&tpmData.permanent.data.endorsementKey, RSA_ES_PKCSV15, 
        inputData0, inputSize0, scratch, &sizeNE))
          return TPM_DAA_INPUT_DATA0;
      /* Set outputData = SHA-1(DAA_session->DAA_digest || NE) */
      *outputSize = SHA1_DIGEST_LENGTH;
      if ((*outputData = tpm_malloc(*outputSize)) == NULL)
        return TPM_NOSPACE;
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) session->DAA_session.DAA_digest.digest, 
        sizeof(session->DAA_session.DAA_digest.digest));
      sha1_update(&sha1, (BYTE*) scratch, sizeNE);
      sha1_final(&sha1, *outputData);
      /* Set DAA_session->DAA_digest = NULL */
      memset(session->DAA_session.DAA_digest.digest, 0, 
        sizeof(session->DAA_session.DAA_digest.digest));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 9:
    {
      BYTE *DAA_generic_R0 = NULL, *DAA_generic_n = NULL;
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t X, Y, n, tmp;
      
      /* Verify that DAA_session->DAA_stage == 9. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 9)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_R0 = inputData0 */
      DAA_generic_R0 = inputData0;
      /* Verify that SHA-1(DAA_generic_R0) == 
       * DAA_issuerSettings->DAA_digest_R0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R0, 
        DAA_generic_R0, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1))
          return TPM_DAA_INPUT_DATA1;
      /* Obtain random data from the RNG and store it as 
       * DAA_session->DAA_contextSeed */
      tpm_get_random_bytes(session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      /* Obtain DAA_SIZE_r0 bits from MGF1("r0", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memcpy(mgf1_seed, "r0", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r0);
      mpz_init(Y);
      mpz_import(Y, DAA_SIZE_r0, 1, 1, 0, 0, scratch);
      /* Set X = DAA_generic_R0 */
      mpz_init(X);
      mpz_import(X, inputSize0, 1, 1, 0, 0, DAA_generic_R0);
      /* Set n = DAA_generic_n */
      mpz_init(n);
      mpz_import(n, inputSize1, 1, 1, 0, 0, DAA_generic_n);
      /* Set DAA_session->DAA_scratch = (X^Y) mod n */
      mpz_init(tmp);
      mpz_powm(tmp, X, Y, n);
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, tmp);
      mpz_clear(X), mpz_clear(Y), mpz_clear(n), mpz_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 10:
    {
      BYTE *DAA_generic_R1 = NULL, *DAA_generic_n = NULL;
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t X, Y, Z, n, tmp;
      
      /* Verify that DAA_session->DAA_stage == 10. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 10)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_R1 = inputData0 */
      DAA_generic_R1 = inputData0;
      /* Verify that SHA-1(DAA_generic_R1) == 
       * DAA_issuerSettings->DAA_digest_R1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R1, 
        DAA_generic_R1, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1))
          return TPM_DAA_INPUT_DATA1;
      /* Obtain random data from the RNG and store it as 
       * DAA_session->DAA_contextSeed */
      tpm_get_random_bytes(session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      /* Obtain DAA_SIZE_r1 bits from MGF1("r1", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memcpy(mgf1_seed, "r1", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r1);
      mpz_init(Y);
      mpz_import(Y, DAA_SIZE_r1, 1, 1, 0, 0, scratch);
      /* Set X = DAA_generic_R1 */
      mpz_init(X);
      mpz_import(X, inputSize0, 1, 1, 0, 0, DAA_generic_R1);
      /* Set n = DAA_generic_n */
      mpz_init(n);
      mpz_import(n, inputSize1, 1, 1, 0, 0, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      mpz_init(Z);
      mpz_import(Z, sizeof(session->DAA_session.DAA_scratch), 1, 1, 0, 0, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      mpz_init(tmp);
      mpz_powm(tmp, X, Y, n);
      mpz_mul(tmp, tmp, Z);
      mpz_mod(tmp, tmp, n);
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, tmp);
      mpz_clear(X), mpz_clear(Y), mpz_clear(Z), mpz_clear(n), mpz_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 11:
    {
      BYTE *DAA_generic_S0 = NULL, *DAA_generic_n = NULL;
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t X, Y, Z, n, tmp;
      
      /* Verify that DAA_session->DAA_stage == 11. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 11)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_S0 = inputData0 */
      DAA_generic_S0 = inputData0;
      /* Verify that SHA-1(DAA_generic_S0) == 
       * DAA_issuerSettings->DAA_digest_S0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S0, 
        DAA_generic_S0, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1))
          return TPM_DAA_INPUT_DATA1;
      /* Obtain random data from the RNG and store it as 
       * DAA_session->DAA_contextSeed */
      tpm_get_random_bytes(session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      /* Obtain DAA_SIZE_r2 bits from MGF1("r2", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memcpy(mgf1_seed, "r2", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r2);
      mpz_init(Y);
      mpz_import(Y, DAA_SIZE_r2, 1, 1, 0, 0, scratch);
      /* Set X = DAA_generic_S0 */
      mpz_init(X);
      mpz_import(X, inputSize0, 1, 1, 0, 0, DAA_generic_S0);
      /* Set n = DAA_generic_n */
      mpz_init(n);
      mpz_import(n, inputSize1, 1, 1, 0, 0, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      mpz_init(Z);
      mpz_import(Z, sizeof(session->DAA_session.DAA_scratch), 1, 1, 0, 0, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      mpz_init(tmp);
      mpz_powm(tmp, X, Y, n);
      mpz_mul(tmp, tmp, Z);
      mpz_mod(tmp, tmp, n);
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, tmp);
      mpz_clear(X), mpz_clear(Y), mpz_clear(Z), mpz_clear(n), mpz_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 12:
    {
      BYTE *DAA_generic_S1 = NULL, *DAA_generic_n = NULL;
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t X, Y, Z, n, tmp;
      
      /* Verify that DAA_session->DAA_stage == 12. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 12)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_S1 = inputData0 */
      DAA_generic_S1 = inputData0;
      /* Verify that SHA-1(DAA_generic_S1) == 
       * DAA_issuerSettings->DAA_digest_S1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S1, 
        DAA_generic_S1, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1))
          return TPM_DAA_INPUT_DATA1;
      /* Obtain random data from the RNG and store it as 
       * DAA_session->DAA_contextSeed */
      tpm_get_random_bytes(session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      /* Obtain DAA_SIZE_r3 bits from MGF1("r3", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memcpy(mgf1_seed, "r3", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r3);
      mpz_init(Y);
      mpz_import(Y, DAA_SIZE_r3, 1, 1, 0, 0, scratch);
      /* Set X = DAA_generic_S1 */
      mpz_init(X);
      mpz_import(X, inputSize0, 1, 1, 0, 0, DAA_generic_S1);
      /* Set n = DAA_generic_n */
      mpz_init(n);
      mpz_import(n, inputSize1, 1, 1, 0, 0, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      mpz_init(Z);
      mpz_import(Z, sizeof(session->DAA_session.DAA_scratch), 1, 1, 0, 0, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      mpz_init(tmp);
      mpz_powm(tmp, X, Y, n);
      mpz_mul(tmp, tmp, Z);
      mpz_mod(tmp, tmp, n);
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, tmp);
      mpz_clear(X), mpz_clear(Y), mpz_clear(Z), mpz_clear(n), mpz_clear(tmp);
      /* Set outputData = DAA_session->DAA_scratch */
      *outputSize = sizeof(session->DAA_session.DAA_scratch);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, session->DAA_session.DAA_scratch, *outputSize);
      else
        return TPM_NOSPACE;
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 13:
    {
      BYTE *DAA_generic_gamma = NULL;
      mpz_t w1, w, gamma, q;
      
      /* Verify that DAA_session->DAA_stage == 13. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 13)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_gamma = inputData0 */
      DAA_generic_gamma = inputData0;
      /* Verify that SHA-1(DAA_generic_gamma) == 
       * DAA_issuerSettings->DAA_digest_gamma and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_gamma, 
        DAA_generic_gamma, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Verify that inputSize1 == DAA_SIZE_w and return error 
       * TPM_DAA_INPUT_DATA1 on mismatch */
      if (!(inputSize1 == DAA_SIZE_w))
        return TPM_DAA_INPUT_DATA1;
      /* Set w = inputData1 */
      mpz_init(w);
      mpz_import(w, inputSize1, 1, 1, 0, 0, inputData1);
      /* Set w1 = w^(DAA_issuerSettings->DAA_generic_q) mod 
       * (DAA_generic_gamma) */
      mpz_init(gamma);
      mpz_import(gamma, inputSize0, 1, 1, 0, 0, DAA_generic_gamma);
      mpz_init(q);
      mpz_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, 1, 0, 0, session->DAA_issuerSettings.DAA_generic_q);
      mpz_init(w1);
      mpz_powm(w1, w, q, gamma);
      /* If w1 != 1 (unity), return error TPM_DAA_WRONG_W */
      if (mpz_cmp_ui(w1, 1))
        return TPM_DAA_WRONG_W;
      /* Set DAA_session->DAA_scratch = w */
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, w);
      mpz_clear(w), mpz_clear(gamma), mpz_clear(w1), mpz_clear(q);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 14:
    {
      BYTE *DAA_generic_gamma = NULL;
      sha1_ctx_t sha1;
      mpz_t f, q, E, gamma, w;
      
      /* Verify that DAA_session->DAA_stage == 14. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 14)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_gamma = inputData0 */
      DAA_generic_gamma = inputData0;
      /* Verify that SHA-1(DAA_generic_gamma) == 
       * DAA_issuerSettings->DAA_digest_gamma and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_gamma, 
        DAA_generic_gamma, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Set f = SHA-1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0) || SHA-1(DAA_tpmSpecific->DAA_rekey 
       * || DAA_tpmSpecific->DAA_count || 1) mod 
       * DAA_issuerSettings->DAA_generic_q. */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x00", 1);
      sha1_final(&sha1, scratch);
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x01", 1);
      sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      mpz_init(f), mpz_init(q);
      mpz_import(f, 2 * SHA1_DIGEST_LENGTH, 1, 1, 0, 0, scratch);
      mpz_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, 1, 0, 0, session->DAA_issuerSettings.DAA_generic_q);
      mpz_mod(f, f, q);
      /* Set E = ((DAA_session->DAA_scratch)^f) mod (DAA_generic_gamma).*/
      mpz_init(gamma);
      mpz_import(gamma, inputSize0, 1, 1, 0, 0, DAA_generic_gamma);
      mpz_init(w);
      mpz_import(w, sizeof(session->DAA_session.DAA_scratch), 1, 1, 0, 0, 
        session->DAA_session.DAA_scratch);
      mpz_init(E);
      mpz_powm(E, w, f, gamma);
      /* Set outputData = E */
      mpz_export(scratch, outputSize, 1, 1, 0, 0, E);
      mpz_clear(f), mpz_clear(q), mpz_clear(gamma), mpz_clear(w), mpz_clear(E);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else
        return TPM_NOSPACE;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 15:
    {
      BYTE *DAA_generic_gamma = NULL;
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t r0, r1, r, q, E1, w, gamma;
      
      /* Verify that DAA_session->DAA_stage == 15. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 15)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set DAA_generic_gamma = inputData0 */
      DAA_generic_gamma = inputData0;
      /* Verify that SHA-1(DAA_generic_gamma) == 
       * DAA_issuerSettings->DAA_digest_gamma and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_gamma, 
        DAA_generic_gamma, inputSize0))
          return TPM_DAA_INPUT_DATA0;
      /* Obtain DAA_SIZE_r0 bits from MGF1("r0", 
       * DAA_session->DAA_contextSeed), and label them r0 */
      memcpy(mgf1_seed, "r0", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r0);
      mpz_init(r0);
      mpz_import(r0, DAA_SIZE_r0, 1, 1, 0, 0, scratch);
      /* Obtain DAA_SIZE_r1 bits from MGF1("r1", 
       * DAA_session->DAA_contextSeed), and label them r1 */
      memcpy(mgf1_seed, "r1", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r1);
      mpz_init(r1);
      mpz_import(r1, DAA_SIZE_r1, 1, 1, 0, 0, scratch);
      /* Set r = r0 + 2^DAA_power0 * r1 mod 
       * (DAA_issuerSettings->DAA_generic_q). */
      mpz_init(q);
      mpz_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, 1, 0, 0, session->DAA_issuerSettings.DAA_generic_q);
      mpz_init(r);
      mpz_ui_pow_ui(r, 2, DAA_power0);
      mpz_mul(r, r, r1);
      mpz_mod(r, r, q);
      mpz_add(r, r, r0);
      mpz_mod(r, r, q);
      /* Set E1 = ((DAA_session->DAA_scratch)^r) mod (DAA_generic_gamma). */
      mpz_init(gamma);
      mpz_import(gamma, inputSize0, 1, 1, 0, 0, DAA_generic_gamma);
      mpz_init(w);
      mpz_import(w, sizeof(session->DAA_session.DAA_scratch), 1, 1, 0, 0, 
        session->DAA_session.DAA_scratch);
      mpz_init(E1);
      mpz_powm(E1, w, r, gamma);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Set outputData = E1 */
      mpz_export(scratch, outputSize, 1, 1, 0, 0, E1);
      mpz_clear(r0), mpz_clear(r1), mpz_clear(q), mpz_clear(r);
      mpz_clear(gamma), mpz_clear(w), mpz_clear(E1);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else
        return TPM_NOSPACE;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 16:
    {
      BYTE NT[DAA_SIZE_NT];
      sha1_ctx_t sha1;
      
      /* Verify that DAA_session->DAA_stage == 16. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 16)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Verify that inputSize0 == sizeOf(TPM_DIGEST) and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (!(inputSize0 == sizeof(TPM_DIGEST)))
        return TPM_DAA_INPUT_DATA0;
      /* Set DAA_session->DAA_digest = inputData0 */
      memcpy(session->DAA_session.DAA_digest.digest, inputData0, inputSize0);
      /* Obtain DAA_SIZE_NT bits from the RNG and label them NT */
      tpm_get_random_bytes(&NT, DAA_SIZE_NT);
      /* Set DAA_session->DAA_digest to the SHA-1(DAA_session->DAA_digest || 
       * NT)*/
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) session->DAA_session.DAA_digest.digest, 
          sizeof( session->DAA_session.DAA_digest.digest));
      sha1_update(&sha1, (BYTE*) NT, sizeof(NT));
      sha1_final(&sha1, session->DAA_session.DAA_digest.digest);
      /* Set outputData = NT */
      *outputSize = sizeof(NT);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, NT, *outputSize);
      else
        return TPM_NOSPACE;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 17:
    {
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t r0, f, q, f0, s0, tmp;
      sha1_ctx_t sha1;
      
      /* Verify that DAA_session->DAA_stage == 17. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 17)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Obtain DAA_SIZE_r0 bits from MGF1("r0", 
       * DAA_session->DAA_contextSeed), and label them r0 */
      memcpy(mgf1_seed, "r0", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r0);
      mpz_init(r0);
      mpz_import(r0, DAA_SIZE_r0, 1, 1, 0, 0, scratch);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x00", 1);
      sha1_final(&sha1, scratch);
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x01", 1);
      sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      mpz_init(f), mpz_init(q);
      mpz_import(f, 2 * SHA1_DIGEST_LENGTH, 1, 1, 0, 0, scratch);
      mpz_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, 1, 0, 0, session->DAA_issuerSettings.DAA_generic_q);
      mpz_mod(f, f, q);
      /* Set f0 = f mod 2^DAA_power0 (erase all but the lowest DAA_power0 
       * bits of f) */
      mpz_init(f0);
      mpz_init(tmp);
      mpz_ui_pow_ui(tmp, 2, DAA_power0);
      mpz_mod(f0, f, tmp);
      /* Set s0 = r0 + (DAA_session->DAA_digest) * f0 in Z */
      mpz_init(s0);
      mpz_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, 1, 0, 0, session->DAA_session.DAA_digest.digest);
      mpz_mul(s0, tmp, f0);
      mpz_add(s0, r0, s0);
      /* Set outputData = s0 */
      mpz_export(scratch, outputSize, 1, 1, 0, 0, s0);
      mpz_clear(r0), mpz_clear(f), mpz_clear(q), mpz_clear(f0);
      mpz_clear(s0), mpz_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else
        return TPM_NOSPACE;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 18:
    {
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t r1, f, q, f1, s1, tmp;
      sha1_ctx_t sha1;
      
      /* Verify that DAA_session->DAA_stage == 18. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 18)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Obtain DAA_SIZE_r1 bits from MGF1("r1", 
       * DAA_session->DAA_contextSeed), and label them r1 */
      memcpy(mgf1_seed, "r1", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r1);
      mpz_init(r1);
      mpz_import(r1, DAA_SIZE_r1, 1, 1, 0, 0, scratch);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x00", 1);
      sha1_final(&sha1, scratch);
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      sha1_update(&sha1, "\x01", 1);
      sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      mpz_init(f), mpz_init(q);
      mpz_import(f, 2 * SHA1_DIGEST_LENGTH, 1, 1, 0, 0, scratch);
      mpz_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, 1, 0, 0, session->DAA_issuerSettings.DAA_generic_q);
      mpz_mod(f, f, q);
      /* Shift f right by DAA_power0 bits (discard the lowest DAA_power0 
       * bits) and label the result f1 */
      mpz_init(f1);
      mpz_fdiv_q_2exp(f1, f, DAA_power0);
      /* Set s1 = r1 + (DAA_session->DAA_digest) * f1 in Z */
      mpz_init(s1);
      mpz_init(tmp);
      mpz_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, 1, 0, 0, session->DAA_session.DAA_digest.digest);
      mpz_mul(s1, tmp, f1);
      mpz_add(s1, r1, s1);
      /* Set outputData = s1 */
      mpz_export(scratch, outputSize, 1, 1, 0, 0, s1);
      mpz_clear(r1), mpz_clear(f), mpz_clear(q), mpz_clear(f1);
      mpz_clear(s1), mpz_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else
        return TPM_NOSPACE;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 19:
    {
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t r2, s2, tmp;
      
      /* Verify that DAA_session->DAA_stage == 19. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 19)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Obtain DAA_SIZE_r2 bits from MGF1("r2", 
       * DAA_session->DAA_contextSeed), and label them r2 */
      memcpy(mgf1_seed, "r2", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r2);
      mpz_init(r2);
      mpz_import(r2, DAA_SIZE_r2, 1, 1, 0, 0, scratch);
      /* Set s2 = r2 + (DAA_session->DAA_digest) * 
       * (DAA_joinSession->DAA_join_u0) mod 2^DAA_power1 
       * (Erase all but the lowest DAA_power1 bits of s2) */
      mpz_init(s2);
      mpz_import(s2, sizeof(session->DAA_joinSession.DAA_join_u0), 
        1, 1, 0, 0, session->DAA_joinSession.DAA_join_u0);
      mpz_init(tmp);
      mpz_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, 1, 0, 0, session->DAA_session.DAA_digest.digest);
      mpz_mul(s2, tmp, s2);
      mpz_add(s2, r2, s2);
      mpz_ui_pow_ui(tmp, 2, DAA_power1);
      mpz_mod(s2, s2, tmp);
      /* Set DAA_session->DAA_scratch = s2 */
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, s2);
      /* Set outputData = s2 */
      mpz_export(scratch, outputSize, 1, 1, 0, 0, s2);
      mpz_clear(r2), mpz_clear(s2), mpz_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else
        return TPM_NOSPACE;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 20:
    {
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t r2, s12, tmp;
      
      /* Verify that DAA_session->DAA_stage == 20. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 20)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Obtain DAA_SIZE_r2 bits from MGF1("r2", 
       * DAA_session->DAA_contextSeed), and label them r2 */
      memcpy(mgf1_seed, "r2", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r2);
      mpz_init(r2);
      mpz_import(r2, DAA_SIZE_r2, 1, 1, 0, 0, scratch);
      /* Set s12 = r2 + (DAA_session->DAA_digest) * 
       * (DAA_joinSession->DAA_join_u0) */
      mpz_init(s12);
      mpz_import(s12, sizeof(session->DAA_joinSession.DAA_join_u0), 
        1, 1, 0, 0, session->DAA_joinSession.DAA_join_u0);
      mpz_init(tmp);
      mpz_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, 1, 0, 0, session->DAA_session.DAA_digest.digest);
      mpz_mul(s12, tmp, s12);
      mpz_add(s12, r2, s12);
      /* Shift s12 right by DAA_power1 bit (discard the lowest DAA_power1 
       * bits). */
      mpz_fdiv_q_2exp(s12, s12, DAA_power1);
      /* Set DAA_session->DAA_scratch = s12 */
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, s12);
      /* Set outputData = DAA_session->DAA_digest */
      *outputSize = sizeof(session->DAA_session.DAA_digest.digest);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, session->DAA_session.DAA_digest.digest, 
          *outputSize);
      else
        return TPM_NOSPACE;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 21:
    {
      BYTE mgf1_seed[2 + sizeof(session->DAA_session.DAA_contextSeed.digest)];
      mpz_t r3, s3, tmp;
      
      /* Verify that DAA_session->DAA_stage == 21. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 21)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Obtain DAA_SIZE_r3 bits from MGF1("r3", 
       * DAA_session->DAA_contextSeed), and label them r3 */
      memcpy(mgf1_seed, "r3", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.digest, 
        sizeof(session->DAA_session.DAA_contextSeed.digest));
      mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r3);
      mpz_init(r3);
      mpz_import(r3, DAA_SIZE_r3, 1, 1, 0, 0, scratch);
      /* Set s3 = r3 + (DAA_session->DAA_digest) * 
       * (DAA_joinSession->DAA_join_u1) + (DAA_session->DAA_scratch). */
      mpz_init(s3);
      mpz_import(s3, sizeof(session->DAA_joinSession.DAA_join_u1), 
        1, 1, 0, 0, session->DAA_joinSession.DAA_join_u1);
      mpz_init(tmp);
      mpz_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, 1, 0, 0, session->DAA_session.DAA_digest.digest);
      mpz_mul(s3, tmp, s3);
      mpz_add(s3, r3, s3);
      mpz_import(tmp, sizeof(session->DAA_session.DAA_scratch), 
        1, 1, 0, 0, session->DAA_session.DAA_scratch);
      mpz_add(s3, s3, tmp);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Set outputData = s3 */
      mpz_export(scratch, outputSize, 1, 1, 0, 0, s3);
      mpz_clear(r3), mpz_clear(s3), mpz_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else
        return TPM_NOSPACE;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 22:
    {
      mpz_t u2, v0, v10, tmp;
      UINT32 size;
      sha1_ctx_t sha1;
      TPM_DAA_BLOB blob;
      TPM_DAA_SENSITIVE sensitive;
      BYTE iv[TPM_CONTEXT_KEY_SIZE];
      
      /* Verify that DAA_session->DAA_stage == 22. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 22)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Verify inputSize0 == DAA_SIZE_v0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (!(inputSize0 == DAA_SIZE_v0))
        return TPM_DAA_INPUT_DATA0;
      /* Set u2 = inputData0 */
      mpz_init(u2);
      mpz_import(u2, DAA_SIZE_v0, 1, 1, 0, 0, inputData0);
      /* Set v0 = u2 + (DAA_joinSession->DAA_join_u0) mod 2^DAA_power1 
       * (Erase all but the lowest DAA_power1 bits of v0). */
      mpz_init(v0);
      mpz_import(v0, sizeof(session->DAA_joinSession.DAA_join_u0), 
        1, 1, 0, 0, session->DAA_joinSession.DAA_join_u0);
      mpz_add(v0, u2, v0);
      mpz_init(tmp);
      mpz_ui_pow_ui(tmp, 2, DAA_power1);
      mpz_mod(v0, v0, tmp);
      /* Set DAA_tpmSpecific->DAA_digest_v0 = SHA-1(v0) */
      mpz_export(scratch, &size, 1, 1, 0, 0, v0);
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) scratch, size);
      sha1_final(&sha1, session->DAA_tpmSpecific.DAA_digest_v0.digest);
      /* Set v10 = u2 + (DAA_joinSession->DAA_join_u0) in Z */
      mpz_init(v10);
      mpz_import(v10, sizeof(session->DAA_joinSession.DAA_join_u0), 
        1, 1, 0, 0, session->DAA_joinSession.DAA_join_u0);
      mpz_add(v10, u2, v10);
      /* Shift v10 right by DAA_power1 bits (erase the lowest DAA_power1 
       * bits). */
      mpz_fdiv_q_2exp(v10, v10, DAA_power1);
      /* Set DAA_session->DAA_scratch = v10 */
      mpz_export(session->DAA_session.DAA_scratch, NULL, 1, 1, 0, 0, v10);
      /* Set outputData */
        /* Fill in TPM_DAA_BLOB with a type of TPM_RT_DAA_V0 and encrypt 
         * the v0 parameters */
        blob.tag = TPM_TAG_DAA_BLOB;
        blob.resourceType = TPM_RT_DAA_V0;
        memcpy(blob.label, "v0", 2);
        memset(&blob.blobIntegrity, 0, sizeof(TPM_DIGEST));
        blob.additionalSize = TPM_CONTEXT_KEY_SIZE;
        blob.additionalData = iv;
        tpm_get_random_bytes(blob.additionalData, blob.additionalSize);
        mpz_export(scratch, &size, 1, 1, 0, 0, v0);
        sensitive.tag = TPM_TAG_DAA_SENSITIVE;
        sensitive.internalSize = size;
        sensitive.internalData = scratch;
        if (encrypt_daa(blob.additionalData, blob.additionalSize,
          &sensitive, &blob.sensitiveData, &blob.sensitiveSize))
            return TPM_ENCRYPT_ERROR;
        if (compute_daa_digest(&blob, &blob.blobIntegrity))
          return TPM_FAIL;
        /* Set outputData to the encrypted TPM_DAA_BLOB */
        *outputSize = sizeof_TPM_DAA_BLOB(blob);
        size = *outputSize;
        if ((*outputData = tpm_malloc(*outputSize)) != NULL) {
          if (tpm_marshal_TPM_DAA_BLOB(outputData, &size, &blob)) {
            tpm_free(*outputData);
            return TPM_FAIL;
          }
        }
        else
          return TPM_NOSPACE;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific, 
        sizeof(TPM_DAA_TPM));
      sha1_update(&sha1, (BYTE*) &session->DAA_joinSession, 
        sizeof(TPM_DAA_JOINDATA));
      sha1_final(&sha1, session->DAA_session.DAA_digestContext.digest);
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 23:
    {
      mpz_t u3, v1, tmp;
      UINT32 size;
      sha1_ctx_t sha1;
      TPM_DAA_BLOB blob;
      TPM_DAA_SENSITIVE sensitive;
      BYTE iv[TPM_CONTEXT_KEY_SIZE];
      
      /* Verify that DAA_session->DAA_stage == 23. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 23)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Verify inputSize0 == DAA_SIZE_v1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (!(inputSize0 == DAA_SIZE_v1))
        return TPM_DAA_INPUT_DATA0;
      /* Set u3 = inputData0 */
      mpz_init(u3);
      mpz_import(u3, DAA_SIZE_v1, 1, 1, 0, 0, inputData0);
      /* Set v1 = u3 + DAA_joinSession->DAA_join_u1 + 
       * DAA_session->DAA_scratch */
      mpz_init(v1);
      mpz_import(v1, sizeof(session->DAA_joinSession.DAA_join_u1), 
        1, 1, 0, 0, session->DAA_joinSession.DAA_join_u1);
      mpz_init(tmp);
      mpz_import(tmp, sizeof(session->DAA_session.DAA_scratch), 
        1, 1, 0, 0, session->DAA_session.DAA_scratch);
      mpz_add(v1, v1, tmp);
      mpz_add(v1, u3, v1);
      /* Set DAA_tpmSpecific->DAA_digest_v1 = SHA-1(v1) */
      mpz_export(scratch, &size, 1, 1, 0, 0, v1);
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) scratch, size);
      sha1_final(&sha1, session->DAA_tpmSpecific.DAA_digest_v1.digest);
      /* Set outputData */
        /* Fill in TPM_DAA_BLOB with a type of TPM_RT_DAA_V1 and encrypt 
         * the v1 parameters */
        blob.tag = TPM_TAG_DAA_BLOB;
        blob.resourceType = TPM_RT_DAA_V1;
        memcpy(blob.label, "v1", 2);
        memset(&blob.blobIntegrity, 0, sizeof(TPM_DIGEST));
        blob.additionalSize = TPM_CONTEXT_KEY_SIZE;
        blob.additionalData = iv;
        tpm_get_random_bytes(blob.additionalData, blob.additionalSize);
        mpz_export(scratch, &size, 1, 1, 0, 0, v1);
        sensitive.tag = TPM_TAG_DAA_SENSITIVE;
        sensitive.internalSize = size;
        sensitive.internalData = scratch;
        if (encrypt_daa(blob.additionalData, blob.additionalSize,
          &sensitive, &blob.sensitiveData, &blob.sensitiveSize))
            return TPM_ENCRYPT_ERROR;
        if (compute_daa_digest(&blob, &blob.blobIntegrity))
          return TPM_FAIL;
        /* Set outputData to the encrypted TPM_DAA_BLOB */
        *outputSize = sizeof_TPM_DAA_BLOB(blob);
        size = *outputSize;
        if ((*outputData = tpm_malloc(*outputSize)) != NULL) {
          if (tpm_marshal_TPM_DAA_BLOB(outputData, &size, &blob)) {
            tpm_free(*outputData);
            return TPM_FAIL;
          }
        }
        else
          return TPM_NOSPACE;
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      sha1_init(&sha1);
      sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific, 
        sizeof(TPM_DAA_TPM));
      sha1_update(&sha1, (BYTE*) &session->DAA_joinSession, 
        sizeof(TPM_DAA_JOINDATA));
      sha1_final(&sha1, session->DAA_session.DAA_digestContext.digest);
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 24:
    {
      UINT32 size;
      TPM_DAA_BLOB blob;
      TPM_DAA_SENSITIVE sensitive;
      BYTE iv[TPM_CONTEXT_KEY_SIZE];
      
      /* Verify that DAA_session->DAA_stage == 24. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (!(session->DAA_session.DAA_stage == 24)) {
        session->type = TPM_ST_INVALID;
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session))
        return TPM_DAA_ISSUER_SETTINGS;
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session))
        return TPM_DAA_TPM_SETTINGS;
      /* Set outputData = enc(DAA_tpmSpecific) */
      blob.tag = TPM_TAG_DAA_BLOB;
      blob.resourceType = TPM_RT_DAA_TPM;
      memcpy(blob.label, "DAA_tpmSpecific", 15);
      memset(&blob.blobIntegrity, 0, sizeof(TPM_DIGEST));
      blob.additionalSize = TPM_CONTEXT_KEY_SIZE;
      blob.additionalData = iv;
      tpm_get_random_bytes(blob.additionalData, blob.additionalSize);
      sensitive.tag = TPM_TAG_DAA_SENSITIVE;
      sensitive.internalSize = sizeof(session->DAA_tpmSpecific);
      sensitive.internalData = (BYTE*) &session->DAA_tpmSpecific;
      if (encrypt_daa(blob.additionalData, blob.additionalSize,
        &sensitive, &blob.sensitiveData, &blob.sensitiveSize))
          return TPM_ENCRYPT_ERROR;
      if (compute_daa_digest(&blob, &blob.blobIntegrity))
        return TPM_FAIL;
      *outputSize = sizeof_TPM_DAA_BLOB(blob);
      size = *outputSize;
      if ((*outputData = tpm_malloc(*outputSize)) != NULL) {
        if (tpm_marshal_TPM_DAA_BLOB(outputData, &size, &blob)) {
          tpm_free(*outputData);
          return TPM_FAIL;
        }
      }
      else
        return TPM_NOSPACE;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
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
