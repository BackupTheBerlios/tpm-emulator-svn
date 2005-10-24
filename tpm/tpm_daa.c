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
  UINT32 cnt;
  TPM_HANDLE hdl;
  sha1_ctx_t sha1;
  
  info("TPM_DAA_Join(), execute stage = %d", stage);
  switch (stage) {
    case 0:
      /* Determine that sufficient resources are available to perform a
       * DAA_Join. Assign session handle for this DAA_Join. */
      hdl = tpm_get_free_daa_session();
      if (hdl == TPM_INVALID_HANDLE)
        return TPM_RESOURCES;
//TODO
      /* Set all fields in DAA_issuerSettings = NULL */
      memset(&tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_issuerSettings, 
        0, sizeof(TPM_DAA_ISSUER));
      /* Set all fields in DAA_tpmSpecific = NULL */
      memset(&tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_tpmSpecific, 
        0, sizeof(TPM_DAA_TPM));
      /* Set all fields in DAA_session = NULL */
      memset(&tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_session, 
        0, sizeof(TPM_DAA_CONTEXT));
      /* Set all fields in DAA_joinSession = NULL */
      memset(&tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_joinSession, 
        0, sizeof(TPM_DAA_JOINDATA));
      /* Verify that sizeOf(inputData0) == sizeOf(DAA_tpmSpecific->DAA_count)
       * and return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (!(inputSize0 == sizeof(tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_tpmSpecific.DAA_count)))
        return TPM_DAA_INPUT_DATA0;
      /* Verify that inputData0 > 0, and return TPM_DAA_INPUT_DATA0 on
       * mismatch */
      memcpy(&cnt, inputData0, sizeof(tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_tpmSpecific.DAA_count));
      if (!(cnt > 0))
        return TPM_DAA_INPUT_DATA0;
      /* Set DAA_tpmSpecific->DAA_count = inputData0 */
      tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_tpmSpecific.DAA_count = cnt;
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific ||
       * DAA_joinSession) */
      sha1_init(&sha1);
      sha1_update(&sha1, 
        (BYTE*) &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_tpmSpecific, 
        sizeof(TPM_DAA_TPM));
      sha1_update(&sha1, 
        (BYTE*) &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_joinSession, 
        sizeof(TPM_DAA_JOINDATA));
      sha1_final(&sha1, 
        tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_session.DAA_digestContext.digest);
      /* Set DAA_session->DAA_stage = 1 */
      tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(hdl)].DAA_session.DAA_stage = 1;
      /* Assign session handle for DAA_Join */
      // WATCH: this was done in the first step
      /* Set outputData = new session handle */
      *outputSize = sizeof(TPM_HANDLE);
      memcpy(*outputData, &hdl, *outputSize);
      /* return TPM_SUCCESS */
      return TPM_SUCCESS;
    case 1:
      break;
    case 2:
      break;
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
