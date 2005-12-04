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

/*
 * Identity Creation and Activation ([TPM_Part3], Section 15)
 */

TPM_RESULT TPM_MakeIdentity(  
  TPM_ENCAUTH *identityAuth,
  TPM_CHOSENID_HASH *labelPrivCADigest,
  TPM_KEY *idKeyParams,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  TPM_KEY *idKey,
  UINT32 *identityBindingSize,
  BYTE **identityBinding
)
{
  
  /* 1. Validate the idKeyParams parameters for the key description */
    /* a. If the algorithm type is RSA the key length MUST be a minimum of 2048.
     * For interoperability the key length SHOULD be 2048 */
    /* b. If the algorithm type is other than RSA the strength provided by the 
     * key MUST be comparable to RSA 2048 */
    /* c. If the TPM is not designed to create a key of the requested type, 
     * return the error code TPM_BAD_KEY_PROPERTY */
    switch (idKeyParams->algorithmParms.algorithmID) {
      case TPM_ALG_RSA:
        if (idKeyParams->algorithmParms.parms.rsa.keyLength != 2048)
          return TPM_BAD_KEY_PROPERTY;
        break;
      default:
        return TPM_BAD_KEY_PROPERTY;
    }
    /* d. If TPM_PERMANENT_FLAGS->FIPS is TRUE then */
    if (tpmData.permanent.flags.FIPS == TRUE) {
      /* i. If authDataUsage specifies TPM_AUTH_NEVER return TPM_NOTFIPS */
      if (idKeyParams->authDataUsage == TPM_AUTH_NEVER)
        return TPM_NOTFIPS;
    }
  /* 2. Use authHandle to verify that the Owner authorized all TPM_MakeIdentity 
   * input parameters. */
//TODO
  /* 3. Use srkAuthHandle to verify that the SRK owner authorized all 
   * TPM_MakeIdentity input parameters. */
//TODO
  /* 4. Verify that idKeyParams->keyUsage is TPM_KEY_IDENTITY. If it is not, 
   * return TPM_INVALID_KEYUSAGE */
  if (idKeyParams->keyUsage != TPM_KEY_IDENTITY)
    return TPM_INVALID_KEYUSAGE;
  /* 5. Verify that idKeyParams->keyFlags->migratable is FALSE. If it is not,
   * return TPM_INVALID_KEYUSAGE */
  if ((idKeyParams->keyFlags & TPM_KEY_FLAG_MIGRATABLE) == 
    TPM_KEY_FLAG_MIGRATABLE)
      return TPM_INVALID_KEYUSAGE;
  
  /* 6. If ownerAuth indicates XOR encryption for the AuthData secrets */
    /* a. Create X1 the SHA-1 of the concatenation of (ownerAuth->sharedSecret 
     * || authLastNonceEven) */
    
    /* b. Create A1 by XOR X1 and identityAuth */
    
  /* 7. Else */
    /* a. Create A1 by decrypting identityAuth using the algorithm indicated 
     * in the OSAP session */
    
    /* b. Key is from ownerAuth->sharedSecret */
    
    /* c. IV is SHA-1 of (authLastNonceEven || nonceOdd) */
    
  /* 8. Set continueAuthSession and continueSRKSession to FALSE. */
  
  /* 9. Determine the structure version */
    /* a. If idKeyParms->tag is TPM_TAG_KEY12 */
      /* i. Set V1 to 2 */
      
      /* ii. Create idKey a TPM_KEY12 structure using idKeyParams as the 
       * default values for the structure */
    
    /* b. If idKeyParms->ver is 1.1 */
      /* i. Set V1 to 1 */
      
      /* ii. Create idKey a TPM_KEY structure using idKeyParams as the 
       * default values for the structure */
      
  /* 10. Set the digestAtCreation values for pcrInfo */
    /* a. For PCR_INFO_LONG include the locality of the current command */
    
  /* 11. Create an asymmetric key pair (identityPubKey and tpm_signature_key) 
   * using a TPM-protected capability, in accordance with the algorithm 
   * specified in idKeyParams */
  
  /* 12. Ensure that the AuthData information in A1 is properly stored in the 
   * idKey as usageAuth. */
  
  /* 13. Attach identityPubKey and tpm_signature_key to idKey */
  
  /* 14. Set idKey->migrationAuth to TPM_PERMANENT_DATA->tpmProof */
//  memcpy(idKey->migrationAuth, tpmData.permanent.data.tpmProof,
//    sizeof(TPM_SECRET));
  
  /* 15. Ensure that all TPM_PAYLOAD_TYPE structures identify this key as 
   * TPM_PT_ASYM */
  
  /* 16. Encrypt the private portion of idKey using the SRK as the parent key */
  
  /* 17. Create a TPM_IDENTITY_CONTENTS structure named idContents using 
   * labelPrivCADigest and the information from idKey */
  
  /* 18. Sign idContents using tpm_signature_key and 
   * TPM_SS_RSASSAPKCS1v15_SHA1. Store the result in identityBinding. */

info("TPM_MakeIdentity() not implemented yet");
/* TODO: implement TPM_MakeIdentity() */
return TPM_FAIL;
}

TPM_RESULT TPM_ActivateIdentity(  
  TPM_KEY_HANDLE idKey,
  UINT32 blobSize,
  BYTE *blob,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  TPM_SYMMETRIC_KEY *symmetricKey
)
{
  info("TPM_ActivateIdentity() not implemented yet");
  /* TODO: implement TPM_ActivateIdentity() */
  return TPM_FAIL;
  
  /* 1. Using the authHandle field, validate the owner's AuthData to execute 
   * the command and all of the incoming parameters. */
  
  /* 2. Using the idKeyAuthHandle, validate the AuthData to execute command 
   * and all of the incoming parameters */
  
  /* 3. Validate that the idKey is the public key of a valid TPM identity by 
   * checking that idKeyHandle->keyUsage is TPM_KEY_IDENTITY. 
   * Return TPM_BAD_PARAMETER on mismatch */
  
  /* 4. Create H1 the digest of a TPM_PUBKEY derived from idKey */
  
  /* 5. Decrypt blob creating B1 using PRIVEK as the decryption key */
  
  /* 6. Determine the type and version of B1 */
    /* a. If B1->tag is TPM_TAG_EK_BLOB then */
      /* i. B1 is a TPM_EK_BLOB */
      
    /* b. Else */
      /* i. B1 is a TPM_ASYM_CA_CONTENTS. As there is no tag for this 
       * structure it is possible for the TPM to make a mistake here but 
       * other sections of the structure undergo validation */
      
  /* 7. If B1 is a version 1.1 TPM_ASYM_CA_CONTENTS then */
    /* a. Compare H1 to B1->idDigest on mismatch return TPM_BAD_PARAMETER */
    
    /* b. Set K1 to B1->sessionKey */
    
  /* 8. If B1 is a TPM_EK_BLOB then */
    /* a. Validate that B1->ekType is TPM_EK_BLOB_ACTIVATE, return 
     * TPM_BAD_TYPE if not. */
    
    /* b. Assign A1 as a TPM_EK_TYPE_ACTIVATE structure from B1->blob */
    
    /* c. Compare H1 to A1->idDigest on mismatch return TPM_BAD_PARAMETER */
    
    /* d. If A1->pcrSelection is not NULL */
      /* i. Compute a composite hash C1 using the PCR selection 
       * A1->pcrSelection */
      
      /* ii. Compare C1 to A1->pcrInfo->digestAtRelease and return 
       * TPM_WRONGPCRVAL on a mismatch */
      
      /* iii. If A1->pcrInfo specifies a locality ensure that the 
       * appropriate locality has been asserted, return TPM_BAD_LOCALITY 
       * on error */
      
    /* e. Set K1 to A1->symmetricKey */
    
  /* 9. Return K1 */
  
}
