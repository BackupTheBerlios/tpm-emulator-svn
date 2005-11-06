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
#include "tpm_handles.h"

/*
 * The GetCapability Commands ([TPM_Part3], Section 7)
 * The GetCapability command allows the TPM to report back to the requester 
 * what type of TPM it is dealing with. The request for information requires 
 * the requester to specify which piece of information that is required. 
 */

inline TPM_RESULT return_UINT32(UINT32 *respSize, BYTE **resp, UINT32 value)
{
  UINT32 len = *respSize = 4;
  BYTE *ptr = *resp = tpm_malloc(*respSize);
  if (ptr == NULL || tpm_marshal_UINT32(&ptr, &len, value)) {
    tpm_free(*resp);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

inline TPM_RESULT return_BOOL(UINT32 *respSize, BYTE **resp, BOOL value)
{
  UINT32 len = *respSize = 1;
  BYTE *ptr = *resp = tpm_malloc(*respSize);
  if (ptr == NULL || tpm_marshal_BOOL(&ptr, &len, value)) {
    tpm_free(*resp);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

static TPM_RESULT cap_property(UINT32 subCapSize, BYTE *subCap, 
                               UINT32 *respSize, BYTE **resp)
{
  UINT32 i, j, property;

  if (tpm_unmarshal_UINT32(&subCap, &subCapSize, &property)) 
    return TPM_BAD_MODE;
  switch (property) {
    case TPM_CAP_PROP_PCR:
      debug("[TPM_CAP_PROP_PCR]");
      return return_UINT32(respSize, resp, TPM_NUM_PCR);

    case TPM_CAP_PROP_DIR:
      debug("[TPM_CAP_PROP_DIR]");
      return return_UINT32(respSize, resp, 1);

    case TPM_CAP_PROP_MANUFACTURER:
      debug("[TPM_CAP_PROP_MANUFACTURER]");
      return return_UINT32(respSize, resp, TPM_MANUFACTURER);

    case TPM_CAP_PROP_KEYS:
      debug("[TPM_CAP_PROP_KEYS]");
      for (i = 0, j = TPM_MAX_KEYS; i < TPM_MAX_KEYS; i++)
        if (tpmData.permanent.data.keys[i].valid) j--;
      return return_UINT32(respSize, resp, j); 

    case TPM_CAP_MIN_COUNTER:
      debug("[TPM_CAP_MIN_COUNTER]");
      return return_UINT32(respSize, resp, 1);

    case TPM_CAP_PROP_AUTHSESS:
      debug("[TPM_CAP_PROP_AUTHSESS]");
      for (i = 0, j = TPM_MAX_SESSIONS; i < TPM_MAX_SESSIONS; i++)
        if (tpmData.stany.data.sessions[i].type != TPM_ST_INVALID) j--;

    case TPM_CAP_PROP_TRANSESS:
      debug("[TPM_CAP_PROP_TRANSESS]");
      for (i = 0, j = TPM_MAX_SESSIONS; i < TPM_MAX_SESSIONS; i++)
        if (tpmData.stany.data.sessions[i].type != TPM_ST_INVALID) j--;
      return return_UINT32(respSize, resp, j);

    case TPM_CAP_PROP_COUNTERS:
      debug("[TPM_CAP_PROP_COUNTERS]");
      for (i = 0, j = TPM_MAX_COUNTERS; i < TPM_MAX_COUNTERS; i++)
        if (tpmData.permanent.data.counters[i].valid) j--;
      return return_UINT32(respSize, resp, j);

    case TPM_CAP_PROP_MAX_AUTHSESS:
      debug("[TPM_CAP_PROP_MAX_AUTHSESS]");
      return return_UINT32(respSize, resp, TPM_MAX_SESSIONS);

    case TPM_CAP_PROP_MAX_TRANSESS:
      debug("[TPM_CAP_PROP_MAX_TRANSESS]");
      return return_UINT32(respSize, resp, TPM_MAX_SESSIONS);

    case TPM_CAP_PROP_MAX_COUNTERS:
      debug("[TPM_CAP_PROP_MAX_COUNTERS]");
      return return_UINT32(respSize, resp, TPM_MAX_COUNTERS);

    case TPM_CAP_PROP_MAX_KEYS:
      debug("[TPM_CAP_PROP_MAX_KEYS]");
      return return_UINT32(respSize, resp, TPM_MAX_KEYS);

    case TPM_CAP_PROP_OWNER:
      debug("[TPM_CAP_PROP_OWNER]");
      return return_BOOL(respSize, resp, tpmData.permanent.flags.owned);

    case TPM_CAP_PROP_CONTEXT:
      debug("[TPM_CAP_PROP_CONTEXT]");
      for (i = 0, j = 0; i < TPM_MAX_SESSION_LIST; i++)
        if (tpmData.stany.data.contextList[i] == 0) j++;
      return return_UINT32(respSize, resp, j);

    case TPM_CAP_PROP_MAX_CONTEXT:
      debug("[TPM_CAP_PROP_MAX_CONTEXT]");
      return return_UINT32(respSize, resp, TPM_MAX_SESSION_LIST);

    case TPM_CAP_PROP_FAMILYROWS:
      debug("[TPM_CAP_PROP_FAMILYROWS]");
      /* TODO: TPM_CAP_PROP_FAMILYROWS */
      return TPM_FAIL;

    case TPM_CAP_PROP_TIS:
      debug("[TPM_CAP_PROP_TIS]");
      /* TODO: TPM_CAP_PROP_TIS */
      return TPM_FAIL;

    case TPM_CAP_PROP_STARTUP_EFFECT:
      debug("[TPM_CAP_PROP_STARTUP_EFFECT]");
      /* TODO: TPM_CAP_PROP_STARTUP_EFFECT */
      return TPM_FAIL;

    case TPM_CAP_PROP_DELEGATE_ENTRIES:
      debug("[TPM_CAP_PROP_DELEGATE_ENTRIES]");
      /* TODO: TPM_CAP_PROP_DELEGATE_ENTRIES */
      return TPM_FAIL;

    case TPM_CAP_PROP_NV_MAXBUF:
      debug("[TPM_CAP_PROP_NV_MAXBUF]");
      /* TODO: TPM_CAP_PROP_NV_MAXBUF */
      return TPM_FAIL;

    case TPM_CAP_PROP_DAA_MAX:
      debug("[TPM_CAP_PROP_DAA_MAX]");
      return return_UINT32(respSize, resp, TPM_MAX_SESSIONS_DAA);

    case TPM_CAP_PROP_SESSION_DAA:
      debug("[TPM_CAP_PROP_SESSION_DAA]");
      for (i = 0, j = TPM_MAX_SESSIONS_DAA; i < TPM_MAX_SESSIONS_DAA; i++)
        if (tpmData.stany.data.sessionsDAA[i].type != TPM_ST_INVALID) j--;
      return return_UINT32(respSize, resp, j);

    case TPM_CAP_PROP_GLOBALLOCK:
      debug("[TPM_CAP_PROP_GLOBALLOCK]");
      /* TODO: TPM_CAP_PROP_GLOBALLOCK */
      return TPM_FAIL;

    case TPM_CAP_PROP_CONTEXT_DIST:
      debug("[TPM_CAP_PROP_CONTEXT_DIST]");
      /* TODO: TPM_CAP_PROP_CONTEXT_DIST */
      return TPM_FAIL;

    case TPM_CAP_PROP_DAA_INTERRUPT:
      debug("[TPM_CAP_PROP_DAA_INTERRUPT]");
      /* A value of TRUE indicates that the TPM will accept ANY command 
       * while executing a DAA Join or Sign. A value of FALSE indicates 
       * that the TPM will invalidate the DAA Join or Sign upon the 
       * receipt of any command other than the next join/sign in the 
       * session or a TPM_SaveContext. */
      return return_BOOL(respSize, resp, TRUE);

    case TPM_CAP_GPIO_CHANNEL:
      debug("[TPM_CAP_GPIO_CHANNEL]");
      /* TODO: TPM_CAP_GPIO_CHANNEL */
      return TPM_FAIL;

    case TPM_CAP_PROP_CMK_RESTRICTION:
      debug("[TPM_CAP_PROP_CMK_RESTRICTION]");
      /* TODO: TPM_CAP_PROP_CMK_RESTRICTION */
      return TPM_FAIL;

    default:
      return TPM_BAD_MODE;
  }
}

static TPM_RESULT cap_version(UINT32 *respSize, BYTE **resp)
{
  UINT32 len = *respSize = 4;
  BYTE *ptr = *resp = tpm_malloc(*respSize);
  TPM_VERSION version = tpmData.permanent.data.version;
  version.revMajor = version.revMinor = 0;
  if (ptr == NULL || tpm_marshal_TPM_VERSION(&ptr, &len, &version)) {
    tpm_free(*resp);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

static TPM_RESULT cap_mfr(UINT32 *respSize, BYTE **resp)
{
  UINT32 len = *respSize = 4;
  BYTE *ptr = *resp = tpm_malloc(*respSize);
  if (ptr == NULL || tpm_marshal_TPM_VERSION(&ptr, &len, 
      &tpmData.permanent.data.version)) {
    tpm_free(*resp);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

static TPM_RESULT cap_handle(UINT32 subCapSize, BYTE *subCap,
                               UINT32 *respSize, BYTE **resp)
{
  UINT32 i, len, type;
  BYTE *ptr; 
  /* maximum of { TPM_MAX_KEYS, TPM_MAX_SESSIONS } */
  UINT32 handles[TPM_MAX_KEYS];
  TPM_KEY_HANDLE_LIST list = { 0, handles };

  if (tpm_unmarshal_UINT32(&subCap, &subCapSize, &type))
    return TPM_BAD_MODE;
  switch (type) {
    case TPM_RT_KEY:
      debug("[TPM_RT_KEY]");
      for (i = 0; i < TPM_MAX_KEYS; i++) 
        if (tpmData.permanent.data.keys[i].valid) {
          list.loaded++;
          list.handle[i] = INDEX_TO_KEY_HANDLE(i);
        }
      break;
    case TPM_RT_AUTH:
      debug("[TPM_RT_AUTH]");
      for (i = 0; i < TPM_MAX_SESSIONS; i++)
        if (tpmData.stany.data.sessions[i].type == TPM_ST_OIAP
            || tpmData.stany.data.sessions[i].type == TPM_ST_OSAP) {
          list.loaded++;
          list.handle[i] = INDEX_TO_AUTH_HANDLE(i);
        }
      break;
    case TPM_RT_TRANS:
      debug("[TPM_RT_TRANS]");
      for (i = 0; i < TPM_MAX_SESSIONS; i++)
        if (tpmData.stany.data.sessions[i].type == TPM_ST_TRANSPORT) {
          list.loaded++;
          list.handle[i] = INDEX_TO_TRANS_HANDLE(i);
        }
      break;
    case TPM_RT_DELEGATE:
      debug("[TPM_RT_DELEGATE]");
      /* TODO: return all current delegate handles */
      break;
    default:
      return TPM_BAD_MODE;
  }
  /* marshal handle list */
  len = *respSize = 2 + list.loaded * 4;
  ptr = *resp = tpm_malloc(len);
  if (ptr == NULL || tpm_marshal_TPM_KEY_HANDLE_LIST(&ptr, &len, &list)) {
    tpm_free(*resp);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

TPM_RESULT cap_ord(UINT32 subCapSize, BYTE *subCap,
                   UINT32 *respSize, BYTE **resp)
{
  TPM_COMMAND_CODE ord;
  if (tpm_unmarshal_TPM_COMMAND_CODE(&subCap, &subCapSize, &ord))
    return TPM_BAD_MODE;
  switch (ord) {
    case TPM_ORD_Startup:
      return return_BOOL(respSize, resp, TRUE);
    default:
      return return_BOOL(respSize, resp, FALSE);
  }
}

TPM_RESULT cap_alg(UINT32 subCapSize, BYTE *subCap,
                   UINT32 *respSize, BYTE **resp)
{
  TPM_ALGORITHM_ID id;
  if (tpm_unmarshal_TPM_ALGORITHM_ID(&subCap, &subCapSize, &id))
    return TPM_BAD_MODE;
  return return_BOOL(respSize, resp, id == TPM_ALG_RSA);
}

TPM_RESULT cap_pid(UINT32 subCapSize, BYTE *subCap,
                   UINT32 *respSize, BYTE **resp)
{
  TPM_PROTOCOL_ID id;
  if (tpm_unmarshal_TPM_PROTOCOL_ID(&subCap, &subCapSize, &id))
    return TPM_BAD_MODE;
  switch (id) {
    case TPM_PID_OIAP:
    case TPM_PID_OSAP:
    case TPM_PID_ADIP:
    case TPM_PID_ADCP:
    case TPM_PID_OWNER:
    case TPM_PID_DSAP:
      return return_BOOL(respSize, resp, TRUE);
    default:
      return return_BOOL(respSize, resp, FALSE);
  }
}

TPM_RESULT cap_flag(UINT32 subCapSize, BYTE *subCap,
                    UINT32 *respSize, BYTE **resp)
{
  UINT32 type, len;
  BYTE *ptr;
  if (tpm_unmarshal_UINT32(&subCap, &subCapSize, &type)) return TPM_BAD_MODE;
  switch (type) {
    case TPM_CAP_FLAG_PERMANENT:
      debug("[TPM_CAP_FLAG_PERMANENT");
      *respSize = len = sizeof_TPM_PERMANENT_FLAGS(tpmData.permanent.flags);
      *resp = ptr = tpm_malloc(len);
      if (tpm_marshal_TPM_PERMANENT_FLAGS(&ptr, &len, &tpmData.permanent.flags)) {
        tpm_free(*resp);
        return TPM_FAIL;
      }
      return TPM_SUCCESS;
    case TPM_CAP_FLAG_STCLEAR:
      debug("[TPM_CAP_FLAG_STCLEAR]");
      *respSize = len = sizeof_TPM_STCLEAR_FLAGS(tpmData.stclear.flags);
      *resp = ptr = tpm_malloc(len);
      if (tpm_marshal_TPM_STCLEAR_FLAGS(&ptr, &len, &tpmData.stclear.flags)) {
        tpm_free(*resp);
        return TPM_FAIL;
      }
      return TPM_SUCCESS;
    case TPM_CAP_FLAG_STANY:
      debug("[TPM_CAP_FLAG_STANY]");
      *respSize = len = sizeof_TPM_STANY_FLAGS(tpmData.stany.flags);
      *resp = ptr = tpm_malloc(len);
      if (tpm_marshal_TPM_STANY_FLAGS(&ptr, &len, &tpmData.stany.flags)) {
        tpm_free(*resp);
        return TPM_FAIL;
      }
      return TPM_SUCCESS;
    default:
      return TPM_BAD_MODE;
  }
}

TPM_RESULT cap_loaded(UINT32 subCapSize, BYTE *subCap,
                     UINT32 *respSize, BYTE **resp)
{
  int i;
  BOOL free_space = FALSE;
  TPM_KEY_PARMS parms;
  if (tpm_unmarshal_TPM_KEY_PARMS(&subCap, &subCapSize, &parms)) 
    return TPM_BAD_MODE;
  for (i = 0; i < TPM_MAX_KEYS; i++) 
    if (!tpmData.permanent.data.keys[i].valid) free_space = TRUE;
  if (free_space
      && parms.algorithmID == TPM_ALG_RSA
      && parms.parms.rsa.keyLength <= 2048
      && parms.parms.rsa.numPrimes == 2) 
    return return_BOOL(respSize, resp, TRUE);
  return return_BOOL(respSize, resp, FALSE);
}

TPM_RESULT TPM_GetCapability(TPM_CAPABILITY_AREA capArea, UINT32 subCapSize, 
                             BYTE *subCap, UINT32 *respSize, BYTE **resp)
{
  info("TPM_GetCapability() (not fully implemented yet)");
  switch (capArea) {

    case TPM_CAP_ORD:
      debug("[TPM_CAP_ORD]"); 
      return cap_ord(subCapSize, subCap, respSize, resp);

    case TPM_CAP_ALG:
      debug("[TPM_CAP_ALG]"); 
      return cap_alg(subCapSize, subCap, respSize, resp);

    case TPM_CAP_PID:
      debug("[TPM_CAP_PID]"); 
      return cap_pid(subCapSize, subCap, respSize, resp);

    case TPM_CAP_FLAG:
      debug("[TPM_CAP_FLAG]");
      return cap_flag(subCapSize, subCap, respSize, resp); 

    case TPM_CAP_PROPERTY:
      debug("[TPM_CAP_PROPERTY]");
      return cap_property(subCapSize, subCap, respSize, resp);

    case TPM_CAP_VERSION:
      debug("[TPM_CAP_VERSION]"); 
      return cap_version(respSize, resp);

    case TPM_CAP_KEY_HANDLE:
      debug("[TPM_CAP_KEY_HANDLE]");
      subCapSize = cpu_to_be32(TPM_RT_KEY);
      return cap_handle(4, (BYTE*)&subCapSize, respSize, resp);

    case TPM_CAP_CHECK_LOADED:
      debug("[TPM_CAP_CHECK_LOADED]");
      return cap_loaded(subCapSize, subCap, respSize, resp); 

    case TPM_CAP_BIT_OWNER:
      debug("[TPM_CAP_BIT_OWNER]");
      /* TODO: TPM_CAP_BIT_OWNER */
      return TPM_FAIL;

    case TPM_CAP_BIT_LOCAL:
      debug("[TPM_CAP_BIT_LOCAL]");
      /* TODO: TPM_CAP_BIT_LOCAL */  
      return TPM_FAIL;

    case TPM_CAP_DELEGATIONS:
      debug("[TPM_CAP_DELEGATIONS]"); 
      /* TODO: TPM_CAP_DELEGATIONS */
      return TPM_FAIL;

    case TPM_CAP_KEY_STATUS:
      debug("[TPM_CAP_KEY_STATUS]");
      /* TODO: TPM_CAP_KEY_STATUS */   
      return TPM_FAIL;

    case TPM_CAP_NV_LIST:
      debug("[TPM_CAP_NV_LIST]");
      /* TODO: TPM_CAP_NV_LIST */ 
      return TPM_FAIL;

    case TPM_CAP_TABLE_ADMIN:
      debug("[TPM_CAP_TABLE_ADMIN]");
      /* TODO: TPM_CAP_TABLE_ADMIN */ 
      return TPM_FAIL;

    case TPM_CAP_TABLE_ENABLE:
      debug("[TPM_CAP_TABLE_ENABLE]");
      /* TODO: TPM_CAP_TABLE_ENABLE */ 
      return TPM_FAIL;

    case TPM_CAP_MFR:
      debug("[TPM_CAP_MFR]"); 
      return cap_mfr(respSize, resp);

    case TPM_CAP_NV_INDEX:
      debug("[TPM_CAP_NV_INDEX]");
      /* TODO: TPM_CAP_NV_INDEX */  
      return TPM_FAIL;

    case TPM_CAP_TRANS_ALG:
      debug("[TPM_CAP_TRANS_ALG]"); 
      /* TODO: TPM_CAP_TRANS_ALG */
      return TPM_FAIL;

    case TPM_CAP_GPIO_CHANNEL:
      debug("[TPM_CAP_GPIO_CHANNEL]"); 
      /* TODO: TPM_CAP_GPIO_CHANNEL */
      return TPM_FAIL;

    case TPM_CAP_HANDLE:
      debug("[TPM_CAP_HANDLE]"); 
      return cap_handle(subCapSize, subCap, respSize, resp);

    case TPM_CAP_TRANS_ES:
      debug("[TPM_CAP_TRANS_ES]");
      /* TODO: TPM_CAP_TRANS_ES */
      return TPM_FAIL;

    default:
      return TPM_BAD_MODE;
  }
}

