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

/*
 * Auditing ([TPM_Part3], Section 8)
 * The TPM generates an audit event in response to the TPM executing a 
 * function that has the audit flag set to TRUE for that function. The 
 * TPM maintains an extended value for all audited operations. 
 */

TPM_RESULT TPM_GetAuditDigest(  
  UINT32 startOrdinal,  
  TPM_COUNTER_VALUE *counterValue,
  TPM_DIGEST *auditDigest,
  BOOL *more,
  UINT32 *ordSize,
  UINT32 **ordList  
)
{
  info("TPM_GetAuditDigest() not implemented yet");
  /* TODO: implement TPM_GetAuditDigest() */
  return TPM_FAIL;
}

TPM_RESULT TPM_GetAuditDigestSigned(  
  TPM_KEY_HANDLE keyHandle,
  UINT32 startOrdinal,
  BOOL closeAudit,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,  
  TPM_COUNTER_VALUE *counterValue,
  TPM_DIGEST *auditDigest,
  BOOL *more,
  UINT32 *ordSize,
  UINT32 **ordinalList ,
  UINT32 *sigSize,
  BYTE **sig  
)
{
  info("TPM_GetAuditDigestSigned() not implemented yet");
  /* TODO: implement TPM_GetAuditDigestSigned() */
  return TPM_FAIL;
}

TPM_RESULT TPM_SetOrdinalAuditStatus(  
  TPM_COMMAND_CODE ordinalToAudit,
  BOOL auditState,
  TPM_AUTH *auth1
)
{
  info("TPM_SetOrdinalAuditStatus() not implemented yet");
  /* TODO: implement TPM_SetOrdinalAuditStatus() */
  return TPM_FAIL;
}

