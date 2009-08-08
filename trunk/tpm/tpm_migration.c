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
#include "tpm_marshalling.h"
#include "crypto/sha1.h"

/*
 * Migration ([TPM_Part3], Section 11)
 */

extern int tpm_decrypt_private_key(TPM_KEY_DATA *key, BYTE *enc,
  UINT32 enc_size, TPM_STORE_ASYMKEY *store, BYTE **buf, UINT32 *buf_size);

extern int tpm_encrypt_private_key(TPM_KEY_DATA *key, TPM_STORE_ASYMKEY *store,
                                   BYTE *enc, UINT32 *enc_size);

extern int tpm_decrypt(TPM_KEY_DATA *key, BYTE *enc, UINT32 enc_size,
                       BYTE *out, UINT32 *out_size);

extern int tpm_encrypt_public(TPM_PUBKEY_DATA *key, BYTE *in,
                              UINT32 in_size, BYTE *enc, UINT32 *enc_size);

extern int tpm_setup_pubkey(TPM_PUBKEY_DATA *key, TPM_PUBKEY *pubkey);

int tpm_compute_migration_digest(TPM_PUBKEY *migrationKey,
                                 TPM_MIGRATE_SCHEME migrationScheme,
                                 TPM_NONCE *tpmProof, TPM_DIGEST *digest)
{
  tpm_sha1_ctx_t sha1;
  UINT32 len = sizeof_TPM_PUBKEY((*migrationKey));
  BYTE *buf, *ptr, buf2[2];
  buf = ptr = tpm_malloc(len);
  if (buf == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, migrationKey)) {
    tpm_free(buf);
    return -1;
  }
  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, buf, sizeof_TPM_PUBKEY((*migrationKey)));
  ptr = buf2; len = 2;
  tpm_marshal_UINT16(&ptr, &len, migrationScheme);
  tpm_sha1_update(&sha1, buf2, 2);
  tpm_sha1_update(&sha1, tpmProof->nonce, sizeof(TPM_NONCE));
  tpm_sha1_final(&sha1, digest->digest);
  tpm_free(buf);
  return 0;
}

int tpm_verify_migration_digest(TPM_MIGRATIONKEYAUTH *migrationKeyAuth,
                                TPM_NONCE *tpmProof)
{
  TPM_DIGEST digest;
  if (tpm_compute_migration_digest(&migrationKeyAuth->migrationKey,
      migrationKeyAuth->migrationScheme, tpmProof, &digest)) return -1;
  return memcmp(digest.digest, migrationKeyAuth->digest.digest, sizeof(TPM_DIGEST));
}

TPM_RESULT TPM_CreateMigrationBlob(TPM_KEY_HANDLE parentHandle,
                                   TPM_MIGRATE_SCHEME migrationType,
                                   TPM_MIGRATIONKEYAUTH *migrationKeyAuth,
                                   UINT32 encDataSize, BYTE *encData,
                                   TPM_AUTH *auth1, TPM_AUTH *auth2,
                                   UINT32 *randomSize, BYTE **random,
                                   UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  TPM_SESSION_DATA *session;
  BYTE *ptr, *buf, *key_buf;
  UINT32 len, key_buf_size;
  TPM_STORE_ASYMKEY store;
  TPM_KEY_DATA key;
  TPM_PUBKEY_DATA key2;
  info("TPM_CreateMigrationBlob()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify parent authorization */
  res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
  if (res != TPM_SUCCESS) return res;
  session = tpm_get_auth(auth2->authHandle);
  if (session == NULL || session->type != TPM_ST_OIAP) return TPM_AUTHFAIL;
  /* verify key properties */
  if (parent->keyUsage != TPM_KEY_STORAGE) return TPM_INVALID_KEYUSAGE;
  /* decrypt private key */
  if (tpm_decrypt_private_key(parent, encData, encDataSize,
                              &store, &key_buf, &key_buf_size)
      || store.payload != TPM_PT_ASYM) {
    tpm_free(key_buf);
    return TPM_DECRYPT_ERROR;
  }
  /* verify migration authorization */
  res = tpm_verify_auth(auth2, store.migrationAuth, TPM_INVALID_HANDLE);
  if (res != TPM_SUCCESS) {
    tpm_free(key_buf);
    return TPM_MIGRATEFAIL;
  }
  if (tpm_verify_migration_digest(migrationKeyAuth,
      &tpmData.permanent.data.tpmProof)) {
    debug("tpm_verify_migration_digest() failed");
    tpm_free(key_buf);
    return TPM_MIGRATEFAIL;
  }
  /* set public key */
  if (tpm_setup_pubkey(&key2, &migrationKeyAuth->migrationKey) != 0) {
      debug("tpm_setup_pubkey() failed");
      tpm_free(key_buf);
      return TPM_FAIL;
  }
  /* perform migration */
  if (migrationType == TPM_MS_REWRAP) {
    /* re-encrypt raw key data */
    debug("migrationType = TPM_MS_REWRAP");
    random = NULL;
    randomSize = 0;
    *outDataSize = key2.key.size >> 3;
    *outData = tpm_malloc(*outDataSize);
    if (*outData == NULL) {
      free_TPM_PUBKEY_DATA(key2);
      tpm_free(*outData);
      tpm_free(key_buf);
      return TPM_FAIL;
    }
    if (tpm_encrypt_public(&key2, key_buf, key_buf_size,
                           *outData, outDataSize) != 0) {
        free_TPM_PUBKEY_DATA(key2);
        tpm_free(*outData);
        tpm_free(key_buf);
        return TPM_ENCRYPT_ERROR;
    }
  } else if (migrationType == TPM_MS_MIGRATE) {
    BYTE *ptr, *buf;
    UINT32 len, buf_len;
    /* generate an OAEP encoding of the TPM_MIGRATE_ASYMKEY structure:
       0x00|seed|K1|0x00-pad|0x01|TPM_MIGRATE_ASYMKEY */
    debug("migrationType = TPM_MS_MIGRATE");
    buf_len = key2.key.size >> 3;
    ptr = buf = tpm_malloc(buf_len);
    *randomSize = buf_len;
    *random = tpm_malloc(*randomSize);
    if (buf == NULL || *random == NULL) {
      free_TPM_PUBKEY_DATA(key2);
      tpm_free(buf);
      tpm_free(*random);
      tpm_free(key_buf);
      return TPM_NOSPACE;
    }
    buf[0] = 0x00;
    memcpy(&buf[1], store.migrationAuth, sizeof(TPM_SECRET));
    ptr = &buf[1 + sizeof(TPM_SECRET)];
    len = 4;
    tpm_marshal_UINT32(&ptr, &len, store.privKey.keyLength);
    memcpy(ptr, store.privKey.key, 16);
    memset(ptr + 16, 0, buf_len - 5 - 16);
    len = 1 + 45 + store.privKey.keyLength - 16;
    ptr = &buf[buf_len - len];
    tpm_marshal_BYTE(&ptr, &len, 0x01);
    tpm_marshal_TPM_PAYLOAD_TYPE(&ptr, &len, TPM_PT_MIGRATE);
    tpm_marshal_TPM_SECRET(&ptr, &len, &store.usageAuth);
    tpm_marshal_TPM_DIGEST(&ptr, &len, &store.pubDataDigest);
    tpm_marshal_UINT32(&ptr, &len, store.privKey.keyLength - 16);
    tpm_rsa_mask_generation(&buf[1], SHA1_DIGEST_LENGTH,
      &buf[1 + SHA1_DIGEST_LENGTH], buf_len - SHA1_DIGEST_LENGTH - 1);
    tpm_rsa_mask_generation(&buf[1 + SHA1_DIGEST_LENGTH],
      buf_len - SHA1_DIGEST_LENGTH - 1, &buf[1], SHA1_DIGEST_LENGTH);
    /* XOR encrypt OAEP encoding */
    tpm_get_random_bytes(*random, *randomSize);
    for (len = 0; len < buf_len; len++) buf[len] ^= (*random)[len];
    /* RSA encrypt OAEP encoding */
    if (tpm_rsa_encrypt(&key2.key, RSA_ES_PLAIN, buf, buf_len, buf, &buf_len)) {
      debug("tpm_rsa_encrypt() failed");
      free_TPM_PUBKEY_DATA(key2);
      tpm_free(buf);
      tpm_free(*random);
      tpm_free(key_buf);
      return TPM_ENCRYPT_ERROR;
    }
    *outDataSize = buf_len;
    *outData = buf;
  } else {
    debug("invalid migration type: %d", migrationType);
    free_TPM_PUBKEY_DATA(key2);
    tpm_free(key_buf);
    return TPM_BAD_PARAMETER;
  }
  free_TPM_PUBKEY_DATA(key2);
  tpm_free(key_buf);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ConvertMigrationBlob(TPM_KEY_HANDLE parentHandle,
                                    UINT32 inDataSize, BYTE *inData,
                                    UINT32 randomSize, BYTE *random,
                                    TPM_AUTH *auth1,
                                    UINT32 *outDataSize,BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  BYTE *ptr, *buf;
  UINT32 len, buf_len;
  TPM_STORE_ASYMKEY store;
  info("TPM_ConvertMigrationBlob()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify parent authorization */
  res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
  if (res != TPM_SUCCESS) return res;
  /* verify key properties */
  if (parent->keyUsage != TPM_KEY_STORAGE) return TPM_INVALID_KEYUSAGE;
  /* decrypt private key */
  buf_len = parent->key.size >> 3;
  buf = tpm_malloc(buf_len);
  if (buf == NULL) return TPM_NOSPACE;
  /* RSA decrypt OAEP encoding */
  if (tpm_rsa_decrypt(&parent->key, RSA_ES_PLAIN, inData, inDataSize, buf, &buf_len)
      || buf[0] != 0x00 || buf_len != randomSize) {
    debug("tpm_rsa_decrypt() failed");
    tpm_free(buf);
    return TPM_DECRYPT_ERROR;
  }
  /* XOR decrypt OAEP encoding */
  for (len = 0; len < buf_len; len++) buf[len] ^= random[len];
  /* unmask OAEP encoding */
  tpm_rsa_mask_generation(&buf[1 + SHA1_DIGEST_LENGTH],
    buf_len - SHA1_DIGEST_LENGTH - 1, &buf[1], SHA1_DIGEST_LENGTH);
  tpm_rsa_mask_generation(&buf[1], SHA1_DIGEST_LENGTH,
    &buf[1 + SHA1_DIGEST_LENGTH], buf_len - SHA1_DIGEST_LENGTH - 1);
  /* create a TPM_STORE_ASYMKEY structure */
  memcpy(store.migrationAuth, &buf[1], sizeof(TPM_SECRET));
  for (ptr = &buf[1 + sizeof(TPM_SECRET) + 20]; *ptr == 0x00; ptr++);
  if (ptr[0] != 0x01 || ptr[1] != TPM_PT_MIGRATE) {
      tpm_free(buf);
      return TPM_DECRYPT_ERROR;
  }
  ptr += 2;
  len = ptr - buf;
  store.payload = TPM_PT_ASYM;
  tpm_unmarshal_TPM_SECRET(&ptr, &len, &store.usageAuth);
  tpm_unmarshal_TPM_DIGEST(&ptr, &len, &store.pubDataDigest);
  tpm_unmarshal_UINT32(&ptr, &len, &store.privKey.keyLength);
  store.privKey.keyLength += 16;
  memmove(&buf[1 + sizeof(TPM_SECRET) + 20], ptr, len);
  store.privKey.key = &buf[1 + sizeof(TPM_SECRET) + 4];
  /* encrypt private key */
  *outDataSize = parent->key.size >> 3;
  *outData = tpm_malloc(*outDataSize);
  if (*outData == NULL) {
    tpm_free(buf);
    return TPM_NOSPACE;
  }
  if (tpm_encrypt_private_key(parent, &store, *outData, outDataSize)) {
    debug("tpm_encrypt_private_key() failed");
    tpm_free(*outData);
    tpm_free(buf);
    return TPM_ENCRYPT_ERROR;
  }
  tpm_free(buf);
  return TPM_SUCCESS;
}

static int tpm_copy_pubkey(TPM_PUBKEY *in, TPM_PUBKEY *out)
{
  memcpy(out, in, sizeof(TPM_PUBKEY));
  out->pubKey.key = tpm_malloc(out->pubKey.keyLength);
  if (out->pubKey.key == NULL) return -1;
  memcpy(out->pubKey.key, in->pubKey.key, out->pubKey.keyLength);
  out->algorithmParms.parms.rsa.exponent =
    tpm_malloc(out->algorithmParms.parms.rsa.exponentSize);
  if (out->algorithmParms.parms.rsa.exponent == NULL) {
    tpm_free(out->pubKey.key);
    return -1;
  }
  memcpy(out->algorithmParms.parms.rsa.exponent,
    in->algorithmParms.parms.rsa.exponent,
    out->algorithmParms.parms.rsa.exponentSize);
  return 0;
}

TPM_RESULT TPM_AuthorizeMigrationKey(TPM_MIGRATE_SCHEME migrateScheme,
                                     TPM_PUBKEY *migrationKey, TPM_AUTH *auth1,
                                     TPM_MIGRATIONKEYAUTH *outData)
{
  TPM_RESULT res;
  info("TPM_AuthorizeMigrationKey()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  /* verify the key size and encryption scheme */
  if (migrationKey->algorithmParms.encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1
      || migrationKey->algorithmParms.algorithmID != TPM_ALG_RSA)
    return TPM_INAPPROPRIATE_ENC;
  if (migrationKey->algorithmParms.parms.rsa.keyLength  < 2048)
    return TPM_BAD_KEY_PROPERTY;
  /* create migration key authorization */
  if (tpm_compute_migration_digest(migrationKey, migrateScheme,
      &tpmData.permanent.data.tpmProof, &outData->digest) != 0) {
      debug("tpm_compute_migration_digest() failed");
      return TPM_FAIL;
  }
  outData->migrationScheme = migrateScheme;
  if (tpm_copy_pubkey(migrationKey, &outData->migrationKey) != 0) {
      debug("tpm_copy_pubkey() failed");
      return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_MigrateKey(TPM_KEY_HANDLE maKeyHandle, TPM_PUBKEY *pubKey,
                          UINT32 inDataSize, BYTE *inData, TPM_AUTH *auth1,
                          UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_PUBKEY_DATA key2;
  UINT32 size;
  info("TPM_MigrateKey()");
  key = tpm_get_key(maKeyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify key authorization */
  res = tpm_verify_auth(auth1, key->usageAuth, maKeyHandle);
  if (res != TPM_SUCCESS) return res;
  /* verify key usage */
  if (key->keyUsage != TPM_KEY_MIGRATE) return TPM_BAD_KEY_PROPERTY;
  if (key->encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1) return TPM_INAPPROPRIATE_ENC;
  /* verify public key  */
  if (pubKey->algorithmParms.algorithmID != TPM_ALG_RSA
      || pubKey->algorithmParms.parms.rsa.keyLength < (inDataSize << 3))
    return TPM_BAD_KEY_PROPERTY;
  if (tpm_setup_pubkey(&key2, pubKey) != 0) return TPM_FAIL;
  /* decrypt inData and re-encrypt it with the public key */
  *outDataSize = size = pubKey->algorithmParms.parms.rsa.keyLength >> 3;
  *outData = tpm_malloc(*outDataSize);
  if (*outData == NULL) {
    free_TPM_PUBKEY_DATA(key2);
    return TPM_FAIL;
  }
  if (tpm_decrypt(key, inData, inDataSize, *outData, &size) != 0) {
    free_TPM_PUBKEY_DATA(key2);
    tpm_free(*outData);
    return TPM_DECRYPT_ERROR;
  }
  if (tpm_encrypt_public(&key2, *outData, size, *outData, outDataSize) != 0) {
    free_TPM_PUBKEY_DATA(key2);
    tpm_free(*outData);
    return TPM_ENCRYPT_ERROR;
  }
  free_TPM_PUBKEY_DATA(key2);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CMK_SetRestrictions(
  TPM_CMK_DELEGATE restriction,
  TPM_AUTH *auth1
)
{
  info("TPM_CMK_SetRestrictions() not implemented yet");
  /* TODO: implement TPM_CMK_SetRestrictions() */
  return TPM_FAIL;
}

TPM_RESULT TPM_CMK_ApproveMA(
  TPM_DIGEST *migrationAuthorityDigest,
  TPM_AUTH *auth1,
  TPM_HMAC *outData
)
{
  info("TPM_CMK_ApproveMA() not implemented yet");
  /* TODO: implement TPM_CMK_ApproveMA() */
  return TPM_FAIL;
}

TPM_RESULT TPM_CMK_CreateKey(
  TPM_KEY_HANDLE parentHandle,
  TPM_ENCAUTH *dataUsageAuth,
  TPM_KEY *keyInfo,
  TPM_DIGEST *migrationAuthorityDigest,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  TPM_KEY *wrappedKey
)
{
  info("TPM_CMK_CreateKey() not implemented yet");
  /* TODO: implement TPM_CMK_CreateKey() */
  return TPM_FAIL;
}

TPM_RESULT TPM_CMK_CreateTicket(
  TPM_PUBKEY *verificationKey,
  TPM_DIGEST *signedData,
  UINT32 signatureValueSize,
  BYTE *signatureValue,
  TPM_AUTH *auth1,
  TPM_DIGEST *sigTicket
)
{
  info("TPM_CMK_CreateTicket() not implemented yet");
  /* TODO: implement TPM_CMK_CreateTicket() */
  return TPM_FAIL;
}

TPM_RESULT TPM_CMK_CreateBlob(
  TPM_KEY_HANDLE parentHandle,
  TPM_MIGRATE_SCHEME migrationType,
  TPM_MIGRATIONKEYAUTH *migrationKeyAuth,
  TPM_DIGEST *pubSourceKeyDigest,
  UINT32 restrictTicketSize,
  BYTE *restrictTicket,
  UINT32 sigTicketSize,
  BYTE *sigTicket,
  UINT32 encDataSize,
  BYTE *encData,
  TPM_AUTH *auth1,
  UINT32 *randomSize,
  BYTE **random,
  UINT32 *outDataSize,
  BYTE **outData
)
{
  info("TPM_CMK_CreateBlob() not implemented yet");
  /* TODO: implement TPM_CMK_CreateBlob() */
  return TPM_FAIL;
}

TPM_RESULT TPM_CMK_ConvertMigration(
  TPM_KEY_HANDLE parentHandle,
  TPM_CMK_AUTH *restrictTicket,
  TPM_HMAC *sigTicket,
  TPM_KEY *migratedKey,
  UINT32 msaListSize,
  TPM_MSA_COMPOSITE *msaList,
  UINT32 randomSize,
  BYTE *random,
  TPM_AUTH *auth1,
  UINT32 *outDataSize,
  BYTE **outData
)
{
  info("TPM_CMK_ConvertMigration() not implemented yet");
  /* TODO: implement TPM_CMK_ConvertMigration() */
  return TPM_FAIL;
}
