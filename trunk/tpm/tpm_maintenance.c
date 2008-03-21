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
#include "crypto/sha1.h"

/*
 * Maintenance Functions ([TPM_Part3], Section 12)
 */

extern int tpm_compute_key_digest(TPM_KEY *key, TPM_DIGEST *digest);

extern int tpm_setup_key_parms(TPM_KEY_DATA *key, TPM_KEY_PARMS *parms);

int tpm_setup_privkey(TPM_KEY_DATA *key, TPM_KEY *privkey)
{
  size_t key_length;
  
  privkey->tag = TPM_TAG_KEY12;
  privkey->fill = 0;
  privkey->keyUsage = key->keyUsage;
  privkey->keyFlags = key->keyFlags;
  privkey->authDataUsage = key->authDataUsage;
  if (tpm_setup_key_parms(key, &privkey->algorithmParms) != 0) return -1;
  memcpy(&privkey->PCRInfo, &key->pcrInfo, sizeof(TPM_PCR_INFO)); 
  privkey->PCRInfoSize = sizeof_TPM_PCR_INFO(privkey->PCRInfo);
  privkey->encDataSize = 0;
  privkey->encData = NULL;
  key_length = key->key.size >> 3;
  privkey->pubKey.key = tpm_malloc(key_length);
  if (privkey->pubKey.key == NULL) {
    free_TPM_KEY((*privkey));
    return -1;
  }
  tpm_rsa_export_modulus(&key->key, privkey->pubKey.key, &key_length);
  privkey->pubKey.keyLength = key_length;
  return 0;
}

TPM_RESULT TPM_CreateMaintenanceArchive(BOOL generateRandom, TPM_AUTH *auth1,
                                        UINT32 *randomSize, BYTE **random,
                                        UINT32 *archiveSize, BYTE **archive)
{
  TPM_RESULT res;
  TPM_KEY key;
  TPM_DIGEST key_digest;
  BYTE *buf, *ptr;
  UINT32 len;
  size_t buf_len, p_len;
  
  info("TPM_CreateMaintenanceArchive()");
  if (!tpmData.permanent.flags.allowMaintenance) return TPM_DISABLED_CMD;
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  if (!tpmData.permanent.data.manuMaintPub.valid) return TPM_KEYNOTFOUND;
  /* set up a TPM_KEY structure for the SRK */
  if (tpm_setup_privkey(&tpmData.permanent.data.srk, &key) != 0) {
    debug("tpm_setup_privkey(SRK) failed");
    return TPM_FAIL;
  }
  if (tpm_compute_key_digest(&key, &key_digest) != 0) {
    debug("tpm_compute_key_digest() failed");
    free_TPM_KEY(key);
    return TPM_FAIL;
  }
  /* generate an OAEP encoding of the TPM_MIGRATE_ASYMKEY structure for
     the SRK: 0x00|seed|0x00-pad|0x01|TPM_MIGRATE_ASYMKEY */
  buf_len = tpmData.permanent.data.manuMaintPub.key.size >> 3;
  buf = tpm_malloc(buf_len);
  if (buf == NULL) {
    free_TPM_KEY(key);
    return TPM_NOSPACE;
  }
  buf[0] = 0x00;
  tpm_rsa_export_prime1(&tpmData.permanent.data.srk.key, &buf[5], &p_len);
  ptr = &buf[1]; len = 4;
  tpm_marshal_UINT32(&ptr, &len, p_len);
  memmove(&buf[buf_len - (1 + 45 + p_len - 16)], &buf[5 + 16], p_len - 16);
  memset(&buf[5 + 16], 0, buf_len - 1 - 20 - 1 - 45 - p_len + 16);
  len = 1 + 45 + p_len - 16;
  ptr = &buf[buf_len - len];
  tpm_marshal_BYTE(&ptr, &len, 0x01);  
  tpm_marshal_TPM_PAYLOAD_TYPE(&ptr, &len, TPM_PT_MAINT);
  tpm_marshal_TPM_NONCE(&ptr, &len, &tpmData.permanent.data.tpmProof);
  tpm_marshal_TPM_DIGEST(&ptr, &len, &key_digest);
  tpm_marshal_UINT32(&ptr, &len, p_len - 16); 
  tpm_rsa_mask_generation(&buf[1], SHA1_DIGEST_LENGTH, 
    &buf[1 + SHA1_DIGEST_LENGTH], buf_len - SHA1_DIGEST_LENGTH - 1);
  tpm_rsa_mask_generation(&buf[1 + SHA1_DIGEST_LENGTH], 
    buf_len - SHA1_DIGEST_LENGTH - 1, &buf[1], SHA1_DIGEST_LENGTH);
  /* encrypt OAEP encoding */
  if (tpm_rsa_encrypt(&tpmData.permanent.data.manuMaintPub.key, RSA_ES_PLAIN,
                      buf, buf_len, buf, &buf_len) != 0) {
    debug("tpm_rsa_encrypt() failed");
    free_TPM_KEY(key);
    tpm_free(buf);
    return TPM_FAIL;
  }
  key.encData = buf;
  key.encDataSize = buf_len;
  if (generateRandom) {
    *randomSize = buf_len;
    *random = tpm_malloc(*randomSize);
    if (*random == NULL) {
      free_TPM_KEY(key);
      return TPM_NOSPACE;
    }
    tpm_get_random_bytes(*random, *randomSize);
    for (len = 0; len < buf_len; len++) buf[len] ^= *random[len];
  } else {
    *randomSize = 0;
    *random = NULL;
    tpm_rsa_mask_generation(tpmData.permanent.data.ownerAuth,
                            SHA1_DIGEST_LENGTH, buf, buf_len);
  }
  /* marshal response */
  len = *archiveSize = sizeof_TPM_KEY(key);
  ptr = *archive = tpm_malloc(len);
  if (ptr == NULL || tpm_marshal_TPM_KEY(&ptr, &len, &key)) {
    tpm_free(ptr);
    tpm_free(*random);
    free_TPM_KEY(key);
    return TPM_NOSPACE;
  }
  free_TPM_KEY(key);
  *archiveSize -= len;
  tpmData.permanent.flags.maintenanceDone = TRUE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_LoadMaintenanceArchive(  
  UINT32 inArgumentsSize,
  BYTE *inArguments,
  TPM_AUTH *auth1,  
  UINT32 *outArgumentsSize,
  BYTE **outArguments  
)
{
  info("TPM_LoadMaintenanceArchive() not implemented yet");
  /* TODO: implement TPM_LoadMaintenanceArchive() */
  return TPM_FAIL;
}

TPM_RESULT TPM_KillMaintenanceFeature(TPM_AUTH *auth1)
{
  TPM_RESULT res;

  info("TPM_KillMaintenanceFeature()");
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  tpmData.permanent.flags.allowMaintenance = FALSE;
  return TPM_SUCCESS;
}

extern int tpm_compute_pubkey_checksum(TPM_NONCE *antiReplay, TPM_PUBKEY *pubKey,
                                       TPM_DIGEST *checksum);

TPM_RESULT TPM_LoadManuMaintPub(TPM_NONCE *antiReplay, TPM_PUBKEY *pubKey,
                                TPM_DIGEST *checksum)
{
  TPM_PUBKEY_DATA *key = &tpmData.permanent.data.manuMaintPub;

  info("TPM_LoadManuMaintPub()");
  if (key->valid) return TPM_DISABLED_CMD;
  if (pubKey->algorithmParms.algorithmID != TPM_ALG_RSA
      || pubKey->algorithmParms.encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1
      || pubKey->algorithmParms.sigScheme != TPM_SS_NONE
      || pubKey->pubKey.keyLength < 2048) return TPM_BAD_KEY_PROPERTY;
  key->encScheme = pubKey->algorithmParms.encScheme;
  key->sigScheme = pubKey->algorithmParms.sigScheme;
  if (tpm_rsa_import_public_key(&key->key, RSA_MSB_FIRST, 
        pubKey->pubKey.key, pubKey->pubKey.keyLength,
        pubKey->algorithmParms.parms.rsa.exponent,
        pubKey->algorithmParms.parms.rsa.exponentSize) != 0) return TPM_FAIL;
  if (tpm_compute_pubkey_checksum(antiReplay, pubKey, checksum) != 0)
    return TPM_FAIL;
  tpmData.permanent.data.manuMaintPub.valid = 1;
  return TPM_SUCCESS;
}

int tpm_setup_pubkey(TPM_PUBKEY_DATA *key, TPM_PUBKEY *pubkey)
{
  size_t key_length;
 
  key_length = key->key.size >> 3;
  pubkey->pubKey.key = tpm_malloc(key_length);
  if (pubkey->pubKey.key == NULL) return -1;
  tpm_rsa_export_public_modulus(&key->key, pubkey->pubKey.key, &key_length);
  pubkey->pubKey.keyLength = key_length;
  key_length = key->key.size >> 3;
  pubkey->algorithmParms.parms.rsa.exponent = tpm_malloc(key_length);
  if (pubkey->algorithmParms.parms.rsa.exponent == NULL) {
    tpm_free(pubkey->pubKey.key);
    return -1;
  }
  tpm_rsa_export_public_exponent(&key->key, 
    pubkey->algorithmParms.parms.rsa.exponent, &key_length);
  pubkey->algorithmParms.parms.rsa.exponentSize = key_length;
  pubkey->algorithmParms.algorithmID = TPM_ALG_RSA;
  pubkey->algorithmParms.encScheme = key->encScheme;
  pubkey->algorithmParms.sigScheme = key->sigScheme;
  pubkey->algorithmParms.parms.rsa.keyLength = key->key.size;
  pubkey->algorithmParms.parms.rsa.numPrimes = 2;
  pubkey->algorithmParms.parmSize = 
    sizeof_TPM_RSA_KEY_PARMS(pubkey->algorithmParms.parms.rsa);
  return 0;
}

TPM_RESULT TPM_ReadManuMaintPub(TPM_NONCE *antiReplay, TPM_DIGEST *checksum)
{
  TPM_PUBKEY key;
  int res;
  
  info("TPM_ReadManuMaintPub()");
  if (!tpmData.permanent.data.manuMaintPub.valid) return TPM_KEYNOTFOUND;
  if (tpm_setup_pubkey(&tpmData.permanent.data.manuMaintPub, &key) != 0)
    return TPM_FAIL;
  res = tpm_compute_pubkey_checksum(antiReplay, &key, checksum);
  free_TPM_PUBKEY(key);
  return (res == 0) ? TPM_SUCCESS : TPM_FAIL;
}

