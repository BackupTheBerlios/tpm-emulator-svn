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
#include "crypto/sha1.h"
#include "crypto/rsa.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"

/* import functions from tpm_storage.c */
extern int compute_key_digest(TPM_KEY *key, TPM_DIGEST *digest);
extern int encrypt_private_key(TPM_KEY_DATA *key, TPM_STORE_ASYMKEY *store,
  BYTE *enc, UINT32 *enc_size);

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
  TPM_RESULT res;
  TPM_SESSION_DATA *ownerAuth_sessionData;
  TPM_SECRET A1;
  rsa_private_key_t tpm_signature_key;
  UINT32 key_length;
  TPM_STORE_ASYMKEY store;
  TPM_IDENTITY_CONTENTS idContents;
  UINT32 len;
  BYTE *buf, *ptr;
  
  /* 1. Validate the idKeyParams parameters for the key description */
    /* a. If the algorithm type is RSA the key length MUST be a minimum of 2048.
     * For interoperability the key length SHOULD be 2048 */
    /* b. If the algorithm type is other than RSA the strength provided by the 
     * key MUST be comparable to RSA 2048 */
    /* c. If the TPM is not designed to create a key of the requested type, 
     * return the error code TPM_BAD_KEY_PROPERTY */
    switch (idKeyParams->algorithmParms.algorithmID) {
      case TPM_ALG_RSA:
        if (idKeyParams->algorithmParms.encScheme != TPM_ES_NONE
          || idKeyParams->algorithmParms.parmSize == 0
          || idKeyParams->algorithmParms.parms.rsa.keyLength != 2048
          || idKeyParams->algorithmParms.parms.rsa.numPrimes != 2
          || idKeyParams->algorithmParms.parms.rsa.exponentSize != 0)
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
  res = tpm_verify_auth(auth2, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  /* 3. Use srkAuthHandle to verify that the SRK owner authorized all 
   * TPM_MakeIdentity input parameters. */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.srk.usageAuth, TPM_KH_SRK);
  if (res != TPM_SUCCESS) return res;
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
  ownerAuth_sessionData = tpm_get_auth(auth2->authHandle);
  if (ownerAuth_sessionData == NULL) return TPM_INVALID_AUTHHANDLE;
    /* a. Create X1 the SHA-1 of the concatenation of (ownerAuth->sharedSecret 
     * || authLastNonceEven) */
    /* b. Create A1 by XOR X1 and identityAuth */
    tpm_decrypt_auth_secret(*identityAuth, ownerAuth_sessionData->sharedSecret, 
      &auth2->nonceEven, A1);
  /* 7. Else */
    /* a. Create A1 by decrypting identityAuth using the algorithm indicated 
     * in the OSAP session */
    /* b. Key is from ownerAuth->sharedSecret */
    /* c. IV is SHA-1 of (authLastNonceEven || nonceOdd) */
  /* 8. Set continueAuthSession and continueSRKSession to FALSE. */
  auth2->continueAuthSession = FALSE, auth1->continueAuthSession = FALSE;
  /* 9. Determine the structure version */
    /* a. If idKeyParms->tag is TPM_TAG_KEY12 */
    if (idKeyParams->tag == TPM_TAG_KEY12) {
      /* i. Set V1 to 2 */
      /* ii. Create idKey a TPM_KEY12 structure using idKeyParams as the 
       * default values for the structure */
      idKey->tag = TPM_TAG_KEY12;
      idKey->fill = 0;
      idKey->keyUsage = TPM_KEY_IDENTITY;
      idKey->keyFlags = idKeyParams->keyFlags;
      idKey->authDataUsage = idKeyParams->authDataUsage;
      idKey->algorithmParms.algorithmID = idKeyParams->algorithmParms.algorithmID;
      idKey->algorithmParms.encScheme = idKeyParams->algorithmParms.encScheme;
      idKey->algorithmParms.sigScheme = idKeyParams->algorithmParms.sigScheme;
      idKey->algorithmParms.parmSize = idKeyParams->algorithmParms.parmSize;
      memcpy(idKey->algorithmParms.parms.raw,
        idKeyParams->algorithmParms.parms.raw, idKey->algorithmParms.parmSize);
    } else {
    /* b. If idKeyParms->ver is 1.1 */
      /* i. Set V1 to 1 */
      /* ii. Create idKey a TPM_KEY structure using idKeyParams as the 
       * default values for the structure */
      info("TPM_MakeIdentity() does not support the obsolete TPM_KEY v1.1 structure");
      return TPM_FAIL;
    }
  /* 10. Set the digestAtCreation values for pcrInfo */
  res = tpm_compute_pcr_digest(&idKey->PCRInfo.creationPCRSelection,
    &idKey->PCRInfo.digestAtCreation, NULL);
  if (res != TPM_SUCCESS) return res;
    /* a. For PCR_INFO_LONG include the locality of the current command */
    if (idKey->PCRInfo.tag == TPM_TAG_PCR_INFO_LONG)
      idKey->PCRInfo.localityAtCreation = tpmData.stany.flags.localityModifier;
  /* 11. Create an asymmetric key pair (identityPubKey and tpm_signature_key) 
   * using a TPM-protected capability, in accordance with the algorithm 
   * specified in idKeyParams */
  key_length = idKeyParams->algorithmParms.parms.rsa.keyLength;
  if (rsa_generate_key(&tpm_signature_key, key_length)) return TPM_FAIL;
  /* 12. Ensure that the AuthData information in A1 is properly stored in the 
   * idKey as usageAuth. */
  memcpy(&store.usageAuth, &A1, sizeof(TPM_SECRET));
  /* 13. Attach identityPubKey and tpm_signature_key to idKey */
  idKey->pubKey.keyLength = key_length >> 3;
  idKey->pubKey.key = tpm_malloc(idKey->pubKey.keyLength);
  if (idKey->pubKey.key == NULL) {
    rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  store.privKey.keyLength = key_length >> 4;
  store.privKey.key = tpm_malloc(store.privKey.keyLength);
  if (store.privKey.key == NULL) {
    tpm_free(idKey->pubKey.key);
    rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  idKey->encDataSize = tpmData.permanent.data.srk.key.size >> 3;
  idKey->encData = tpm_malloc(idKey->encDataSize);
  if (idKey->encData == NULL) {
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  rsa_export_modulus(&tpm_signature_key, idKey->pubKey.key, 
    &idKey->pubKey.keyLength);
  rsa_export_prime1(&tpm_signature_key, store.privKey.key, 
    &store.privKey.keyLength);
  /* 14. Set idKey->migrationAuth to TPM_PERMANENT_DATA->tpmProof */
  memcpy(&store.migrationAuth, &tpmData.permanent.data.tpmProof, 
    sizeof(TPM_SECRET));
  /* 15. Ensure that all TPM_PAYLOAD_TYPE structures identify this key as 
   * TPM_PT_ASYM */
  store.payload = TPM_PT_ASYM;
  if (compute_key_digest(idKey, &store.pubDataDigest)) {
    tpm_free(idKey->encData);
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    rsa_release_private_key(&tpm_signature_key);
    return TPM_FAIL;
  }
  /* 16. Encrypt the private portion of idKey using the SRK as the parent key */
  if (encrypt_private_key(&tpmData.permanent.data.srk, &store, idKey->encData, 
    &idKey->encDataSize)) {
    tpm_free(idKey->encData);
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    rsa_release_private_key(&tpm_signature_key);
    return TPM_ENCRYPT_ERROR;
  }
  /* 17. Create a TPM_IDENTITY_CONTENTS structure named idContents using 
   * labelPrivCADigest and the information from idKey */
  idContents.ver.major = 1, idContents.ver.minor = 1;
  idContents.ver.revMajor = 0, idContents.ver.revMinor = 0;
  idContents.ordinal = TPM_ORD_MakeIdentity;
  memcpy(&idContents.labelPrivCADigest, labelPrivCADigest, 
    sizeof(TPM_CHOSENID_HASH));
  idContents.identityPubKey.algorithmParms.algorithmID = 
    idKey->algorithmParms.algorithmID;
  idContents.identityPubKey.algorithmParms.encScheme = 
    idKey->algorithmParms.encScheme;
  idContents.identityPubKey.algorithmParms.sigScheme = 
    idKey->algorithmParms.sigScheme;
  idContents.identityPubKey.algorithmParms.parmSize = 
    idKey->algorithmParms.parmSize;
  memcpy(idContents.identityPubKey.algorithmParms.parms.raw,
    idKey->algorithmParms.parms.raw, idKey->algorithmParms.parmSize);
  idContents.identityPubKey.pubKey.keyLength = key_length >> 3;
  idContents.identityPubKey.pubKey.key = 
    tpm_malloc(idContents.identityPubKey.pubKey.keyLength);
  if (idContents.identityPubKey.pubKey.key == NULL) {
    tpm_free(idKey->encData);
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  rsa_export_modulus(&tpm_signature_key, idContents.identityPubKey.pubKey.key, 
    &idContents.identityPubKey.pubKey.keyLength);
  len = sizeof_TPM_IDENTITY_CONTENTS((idContents));
  buf = ptr = tpm_malloc(len);
  if (buf == NULL) {
    tpm_free(idContents.identityPubKey.pubKey.key);
    tpm_free(idKey->encData);
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  if (tpm_marshal_TPM_IDENTITY_CONTENTS(&ptr, &len, &idContents)) {
    tpm_free(buf);
    tpm_free(idContents.identityPubKey.pubKey.key);
    tpm_free(idKey->encData);
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    rsa_release_private_key(&tpm_signature_key);
    return TPM_FAIL;
  }
  /* 18. Sign idContents using tpm_signature_key and 
   * TPM_SS_RSASSAPKCS1v15_SHA1. Store the result in identityBinding. */
  *identityBindingSize = tpm_signature_key.size >> 3;
  *identityBinding = tpm_malloc(*identityBindingSize);
  if (*identityBinding == NULL) {
    tpm_free(buf);
    tpm_free(idContents.identityPubKey.pubKey.key);
    tpm_free(idKey->encData);
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  if (rsa_sign(&tpm_signature_key, RSA_SSA_PKCS1_SHA1, buf, len, *identityBinding)) {
    tpm_free(*identityBinding);
    tpm_free(buf);
    tpm_free(idContents.identityPubKey.pubKey.key);
    tpm_free(idKey->encData);
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    rsa_release_private_key(&tpm_signature_key);
    return TPM_FAIL;
  }
  tpm_free(buf);
  tpm_free(idContents.identityPubKey.pubKey.key);
  tpm_free(store.privKey.key);
  rsa_release_private_key(&tpm_signature_key);
  
  return TPM_SUCCESS;
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
