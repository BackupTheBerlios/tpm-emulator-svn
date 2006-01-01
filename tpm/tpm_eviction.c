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
#include "crypto/rsa.h"

/*
 * Eviction ([TPM_Part3], Section 22)
 * The TPM has numerous resources held inside of the TPM that may need 
 * eviction. The need for eviction occurs when the number or resources 
 * in use by the TPM exceed the available space. In version 1.1 there were 
 * separate commands to evict separate resource types. This new command 
 * set uses the resource types defined for context saving and creates a 
 * generic command that will evict all resource types.
 */

TPM_RESULT TPM_FlushSpecific(TPM_HANDLE handle, 
                             TPM_RESOURCE_TYPE resourceType)
{
  TPM_SESSION_DATA *session;
  TPM_DAA_SESSION_DATA *sessionDAA;
  TPM_KEY_DATA *key;
  int i;
  
  info("TPM_FlushSpecific()");
  switch (resourceType) {
    case TPM_RT_AUTH:
      session = tpm_get_auth(handle);
      if (session == NULL) return TPM_INVALID_AUTHHANDLE;
      memset(session, 0, sizeof(*session));
      return TPM_SUCCESS;
    
    case TPM_RT_TRANS:
      session = tpm_get_transport(handle);
      if (session == NULL) return TPM_INVALID_AUTHHANDLE;
      memset(session, 0, sizeof(*session));
      return TPM_SUCCESS;
    
    case TPM_RT_DAA_TPM:
      sessionDAA = tpm_get_daa(handle);
      if (sessionDAA == NULL) return TPM_INVALID_RESOURCE;
      memset(sessionDAA, 0, sizeof(*sessionDAA));
      return TPM_SUCCESS;
    
    case TPM_RT_KEY:
      key = tpm_get_key(handle);
      if (key == NULL) return TPM_INVALID_KEYHANDLE;
      if (key->keyControl & TPM_KEY_CONTROL_OWNER_EVICT) 
        return TPM_KEY_OWNER_CONTROL;
      rsa_release_private_key(&key->key);
      memset(key, 0, sizeof(*key));
      /* invalidate all associated authorization and transport sessions */
      for (i = 0; i < TPM_MAX_SESSIONS; i++) {
        session = &tpmData.stany.data.sessions[i];
        if ((session->type == TPM_ST_OSAP && session->handle == handle)
            || (session->type == TPM_ST_TRANSPORT && session->handle == handle))
          memset(session, 0, sizeof(*session));
      }
      return TPM_SUCCESS;
  }
  return TPM_INVALID_RESOURCE;
}

