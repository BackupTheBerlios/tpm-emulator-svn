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

#ifndef _TPM_STRUCTURES_H_
#define _TPM_STRUCTURES_H_

#include <linux/types.h>
#include "crypto/rsa.h"

/*
 * The following types and structures are specified in
 * TPM Main Part 2 TPM Structures [TPM_Part2].
 */

/*
 * Basic Data Types ([TPM_Part2], Section 2.2.1 and 2.2.2)
 */
typedef uint8_t  BYTE;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef BYTE     BOOL; 
#define TRUE     0x01
#define FALSE    0x00

/*
 * TPM Helper Data Types ([TPM_Part2], Section 2.2.3)
 */
typedef BYTE   TPM_AUTH_DATA_USAGE;
typedef BYTE   TPM_PAYLOAD_TYPE;
typedef UINT16 TPM_TAG;
typedef UINT16 TPM_PROTOCOL_ID;
typedef UINT16 TPM_STARTUP_TYPE;
typedef UINT16 TPM_ENC_SCHEME;
typedef UINT16 TPM_SIG_SCHEME;
typedef UINT16 TPM_MIGRATE_SCHEME;
typedef UINT16 TPM_PHYSICAL_PRESENCE;
typedef UINT16 TPM_ENTITY_TYPE;
typedef UINT16 TPM_KEY_USAGE;
typedef UINT16 TPM_EK_TYPE;
typedef UINT16 TPM_STRUCTURE_TAG;
typedef UINT16 TPM_PLATFORM_SPECIFIC;
typedef UINT32 TPM_COMMAND_CODE;
typedef UINT32 TPM_CAPABILITY_AREA;
typedef UINT32 TPM_KEY_FLAGS;
typedef UINT32 TPM_ALGORITHM_ID;
typedef UINT32 TPM_MODIFIER_INDICATOR;
typedef UINT32 TPM_ACTUAL_COUNT;
typedef UINT32 TPM_TRANSPORT_ATTRIBUTES;
typedef UINT32 TPM_AUTHHANDLE;
typedef UINT32 TPM_DIRINDEX;
typedef UINT32 TPM_KEY_HANDLE;
typedef UINT32 TPM_PCRINDEX;
typedef UINT32 TPM_RESULT;
typedef UINT32 TPM_RESOURCE_TYPE;
typedef UINT32 TPM_KEY_CONTROL;
typedef UINT32 TPM_NV_INDEX;
typedef UINT32 TPM_FAMILY_ID;
typedef UINT32 TPM_FAMILY_VERIFICATION;
typedef UINT32 TPM_STARTUP_EFFECTS;
typedef UINT32 TPM_SYM_MODE;
typedef UINT32 TPM_FAMILY_FLAGS;
typedef UINT32 TPM_DELEGATE_INDEX;
typedef UINT32 TPM_CMK_RESTRICT_DELEGATE;
typedef UINT32 TPM_COUNT_ID;
typedef UINT32 TPM_REDIT_COMMAND;
typedef UINT32 TPM_TRANSHANDLE;
typedef UINT32 TPM_HANDLE;
typedef UINT32 TPM_FAMILY_OPERATION;
typedef UINT32 TPM_GPIO_ATTRIBUTES;

/*
 * Vendor Specific ([TPM_Part2], Section 2.2.4)
 */
#define TPM_Vendor_Specific32   0x00000400
#define TPM_Vendor_Specific8    0x80

/*
 * Structure Tags ([TPM_Part2], Section 3.1) are defined
 * together with the dedicated structures.
 */

/*
 * TPM_RESOURCE_TYPE ([TPM_Part2], Section 4.1)
 * Specifies the resource type.
 */
#define TPM_RT_KEY              0x00000001
#define TPM_RT_AUTH             0x00000002
#define TPM_RT_HASH             0x00000003
#define TPM_RT_TRANS            0x00000004
#define TPM_RT_CONTEXT          0x00000005
#define TPM_RT_COUNTERS         0x00000006
#define TPM_RT_DELEGATE         0x00000007
#define TPM_RT_DAA_TPM          0x00000008
#define TPM_RT_DAA_V0           0x00000009
#define TPM_RT_DAA_V1           0x0000000A

/*
 * TPM_PAYLOAD_TYPE ([TPM_Part2], Section 4.2)
 * This specifies the type of payload in various messages.
 */
#define TPM_PT_ASYM                     0x01
#define TPM_PT_BIND                     0x02
#define TPM_PT_MIGRATE                  0x03
#define TPM_PT_MAINT                    0x04
#define TPM_PT_SEAL                     0x05
#define TPM_PT_MIGRATE_RESTRICTED       0x06
#define TPM_PT_MIGRATE_EXTERNAL         0x07
#define TPM_PT_CMK_MIGRATE              0x08
/* 0x09 - 0x7F Reserved for future use by TPM */
/* 0x80 - 0xFF Vendor specific payloads */

/*
 * TPM_ENTITY_TYPE ([TPM_Part2], Section 4.3)
 * This specifies the types of entity that are supported by the TPM.
 */
#define TPM_ET_KEYHANDLE        0x0001
#define TPM_ET_OWNER            0x0002
#define TPM_ET_DATA             0x0003
#define TPM_ET_SRK              0x0004
#define TPM_ET_KEY              0x0005
#define TPM_ET_REVOKE           0x0006
#define TPM_ET_DEL_OWNER_BLOB   0x0007
#define TPM_ET_DEL_ROW          0x0008
#define TPM_ET_DEL_KEY_BLOB     0x0009
#define TPM_ET_COUNTER          0x000A
#define TPM_ET_NV               0x000B
#define TPM_ET_KEYAES           0x000C
#define TPM_ET_KEYDES           0x000D
#define TPM_ET_OWNERAES         0x000E
#define TPM_ET_OWNERDES         0x000F
#define TPM_ET_KEYXOR           0x0010
#define TPM_ET_OWNERXOR         0x0011 // WATCH: does not exist (v1.2 rev 85)
#define TPM_ET_RESERVED_HANDLE  0x0040

/*
 * Reserved Key Handles ([TPM_Part2], Section 4.4)
 * These values specify specific keys or specific actions for the TPM.
 */
#define TPM_KH_SRK              0x40000000
#define TPM_KH_OWNER            0x40000001
#define TPM_KH_REVOKE           0x40000002
#define TPM_KH_TRANSPORT        0x40000003
#define TPM_KH_OPERATOR         0x40000004
#define TPM_KH_ADMIN            0x40000005
#define TPM_KH_EK               0x40000006

/*
 * TPM_STARTUP_TYPE ([TPM_Part2], Section 4.5)
 * To specify what type of startup is occurring.
 */
#define TPM_ST_CLEAR            0x0001
#define TPM_ST_STATE            0x0002
#define TPM_ST_DEACTIVATED      0x0003

/*
 * TPM_STARTUP_EFFECTS ([TPM_Part2], Section 4.6)
 * This structure lists for the various resources and sessions on a TPM
 * the affect that TPM_Startup has on the values.
 */
/* 31-28 reserved and must be 0 */
#define TPM_STARTUP_AUDIT_DIGEST_IGNORE        (1 << 7)
#define TPM_STARTUP_AUDIT_DIGEST_ST_CLEAR      (1 << 6)
#define TPM_STARTUP_AUDIT_DIGEST_ST_ANY        (1 << 5)
#define TPM_STARTUP_RT_KEY_ST_ANY              (1 << 4)
#define TPM_STARTUP_RT_AUTH_ST_STATE           (1 << 3)
#define TPM_STARTUP_RT_HASH_ST_STATE           (1 << 2)
#define TPM_STARTUP_RT_TRANS_ST_STATE          (1 << 1)
#define TPM_STARTUP_RT_CONTEXT_ST_STATE        (1 << 0)

/*
 * TPM_PROTOCOL_ID ([TPM_Part2], Section 4.7)
 * This value identifies the protocol in use.
 */
#define TPM_PID_OIAP            0x0001
#define TPM_PID_OSAP            0x0002
#define TPM_PID_ADIP            0x0003
#define TPM_PID_ADCP            0x0004
#define TPM_PID_OWNER           0x0005
#define TPM_PID_DSAP            0x0006
#define TPM_PID_TRANSPORT       0x0007

/*
 * TPM_ALGORITHM_ID ([TPM_Part2], Section 4.8)
 * This table defines the types of algorithms which may be supported by the TPM.
 */
#define TPM_ALG_RSA             0x00000001
#define TPM_ALG_DES             0x00000002
#define TPM_ALG_3DES            0x00000003
#define TPM_ALG_SHA             0x00000004
#define TPM_ALG_HMAC            0x00000005
#define TPM_ALG_AES128          0x00000006
#define TPM_ALG_MGF1            0x00000007
#define TPM_ALG_AES192          0x00000008
#define TPM_ALG_AES256          0x00000009
#define TPM_ALG_XOR             0x0000000A

/* 
 * TPM_ENC_SCHEME ([TPM_Part1], Section 29)
 * Encryption Schemes 
 */
#define TPM_ES_NONE                    0x0001
#define TPM_ES_RSAESPKCSv15            0x0002
#define TPM_ES_RSAESOAEP_SHA1_MGF1     0x0003
#define TPM_ES_SYM_CNT                 0x0004
#define TPM_ES_SYM_OFB                 0x0005

/*
 * TPM_SIG_SCHEME ([TPM_Part1], Section 29)
 * Signature Schemes
 */
#define TPM_SS_NONE                    0x0001
#define TPM_SS_RSASSAPKCS1v15_SHA1     0x0002
#define TPM_SS_RSASSAPKCS1v15_DER      0x0003
#define TPM_SS_RSASSAPKCS1v15_INFO     0x0004

/*
 * TPM_PHYSICAL_PRESENCE ([TPM_Part2], Section 4.9)
 * Values to setup the Physical Presence
 */
#define TPM_PHYSICAL_PRESENCE_HW_DISABLE        0x0200
#define TPM_PHYSICAL_PRESENCE_CMD_DISABLE       0x0100
#define TPM_PHYSICAL_PRESENCE_LIFETIME_LOCK     0x0080
#define TPM_PHYSICAL_PRESENCE_HW_ENABLE         0x0040
#define TPM_PHYSICAL_PRESENCE_CMD_ENABLE        0x0020
#define TPM_PHYSICAL_PRESENCE_NOTPRESENT        0x0010
#define TPM_PHYSICAL_PRESENCE_PRESENT           0x0008
#define TPM_PHYSICAL_PRESENCE_LOCK              0x0004

/*
 * TPM_MIGRATE_SCHEME ([TPM_Part2], Section 4.10)
 * Indicates how the StartMigrate command should handle the
 * migration of the encrypted blob.
 */
#define TPM_MS_MIGRATE                    0x0001
#define TPM_MS_REWRAP                     0x0002
#define TPM_MS_MAINT                      0x0003
#define TPM_MS_RESTRICT_MIGRATE           0x0004
#define TPM_MS_RESTRICT_APPROVE_DOUBLE    0x0005
#define TPM_MS_RESTRICT_MIGRATE_EXTERNAL  0x0006

/*
 * TPM_EK_TYPE ([TPM_Part2], Section 4.11)
 * Indicates what type of information that the EK is dealing with.
 */
#define TPM_EK_TYPE_ACTIVATE    0x0001
#define TPM_EK_TYPE_AUTH        0x0002

/*
 * TPM_PLATFORM_SPECIFIC ([TPM_Part2], Section 4.12)
 * Indicates the platform specific spec that the information relates to.
 */
#define TPM_PS_PC_11            0x0001
#define TPM_PS_PC_12            0x0002
#define TPM_PS_PDA_12           0x0003
#define TPM_PS_Server_12        0x0004
#define TPM_PS_Mobile_12        0x0005

/*
 * TPM Basic Structures
 */

/*
 * TPM_STRUCT_VER ([TPM_Part2], Section 5.1)
 * This indicates the version of the structure or TPM.
 */
typedef struct tdTPM_STRUCT_VER {
  BYTE major;
  BYTE minor;
  BYTE revMajor;
  BYTE revMinor;
} TPM_STRUCT_VER;

/*
 * TPM_VERSION ([TPM_Part2], Section 5.2)
 * This structure provides information relative the version of the TPM.
 */
typedef struct tdTPM_VERSION {
  BYTE major;
  BYTE minor;
  BYTE revMajor;
  BYTE revMinor;
} TPM_VERSION;

/*
 * TPM_DIGEST ([TPM_Part2], Section 5.3 and 22.4)
 * The digest value reports the result of a hash operation.
 * In version 1 the hash algorithm is SHA-1 (20 bytes resp. 160 bits).
 */
typedef struct tdTPM_DIGEST {
  BYTE digest[20];
} TPM_DIGEST;

typedef TPM_DIGEST TPM_CHOSENID_HASH;
typedef TPM_DIGEST TPM_COMPOSITE_HASH;
typedef TPM_DIGEST TPM_DIRVALUE;
typedef TPM_DIGEST TPM_HMAC;
typedef TPM_DIGEST TPM_PCRVALUE;
typedef TPM_DIGEST TPM_AUDITDIGEST;
typedef TPM_DIGEST TPM_DAA_TPM_SEED;
typedef TPM_DIGEST TPM_DAA_CONTEXT_SEED;

/*
 * TPM_NONCE ([TPM_Part2], Section 5.4)
 * A random value that provides protection from replay and other attacks.
 */
typedef struct tdTPM_NONCE{
  BYTE nonce[20];
} TPM_NONCE;

/*
 * TPM_AUTHDATA ([TPM_Part2], Section 5.5)
 * Information that to provide proof of ownership of an entity.
 * For version 1 this area is always 20 bytes.
 */
typedef BYTE TPM_AUTHDATA[20];
typedef TPM_AUTHDATA TPM_SECRET;
typedef TPM_AUTHDATA TPM_ENCAUTH;

/*
 * TPM_AUTH ([TPM_Part1], Section 11.2)
 * Authorization Protocol Input/Output Parameter
 */
typedef struct tdTPM_AUTH {
  TPM_AUTHHANDLE authHandle;
  TPM_NONCE nonceEven;
  TPM_NONCE nonceOdd;
  BOOL continueAuthSession;
  TPM_AUTHDATA auth;
  /* additional NOT marshalled parameters */
  TPM_SECRET *secret;
  BYTE digest[20];
} TPM_AUTH;

/*
 * TPM_KEY_HANDLE_LIST ([TPM_Part2], Section 5.6)
 * Structure used to describe the handles of all keys currently
 * loaded into a TPM.
 */
typedef struct tdTPM_KEY_HANDLE_LIST {
  UINT16 loaded;
  TPM_KEY_HANDLE *handle;
} TPM_KEY_HANDLE_LIST;

/*
 * TPM_KEY_USAGE ([TPM_Part2], Section 5.7)
 * Defines the types of keys that are possible.
 */
#define TPM_KEY_SIGNING         0x0010
#define TPM_KEY_STORAGE         0x0011
#define TPM_KEY_IDENTITY        0x0012
#define TPM_KEY_AUTHCHANGE      0x0013
#define TPM_KEY_BIND            0x0014
#define TPM_KEY_LEGACY          0x0015

/*
 * TPM_AUTH_DATA_USAGE ([TPM_Part2], Section 5.8)
 * Indication when authorization sessions for an entity are required.
 */
#define TPM_AUTH_NEVER          0x00
#define TPM_AUTH_ALWAYS         0x01
#define TPM_AUTH_PRIV_USE_ONLY  0x03

/*
 * TPM_KEY_FLAGS ([TPM_Part2], Section 5.9)
 * This table defines the meanings of the bits in a TPM_KEY_FLAGS structure.
 */
#define TPM_KEY_FLAG_REDIRECT   0x00000001
#define TPM_KEY_FLAG_MIGRATABLE 0x00000002
#define TPM_KEY_FLAG_VOLATILE   0x00000004
#define TPM_KEY_FLAG_PCR_IGNORE 0x00000008
#define TPM_KEY_FLAG_AUTHORITY  0x0000000C
#define TPM_KEY_FLAG_HAS_PCR    0x10000000 /* to use with TPM_KEY_DATA only! */
#define TPM_KEY_FLAG_MASK       0x0fffffff

/*
 * TPM_CHANGEAUTH_VALIDATE ([TPM_Part2], Section 5.10)
 * To store the new authorization data and the challenger s nonce.
 */
typedef struct tdTPM_CHANGEAUTH_VALIDATE {
  TPM_SECRET newAuthSecret;
  TPM_NONCE n1;
} TPM_CHANGEAUTH_VALIDATE;

/*
 * TPM_COUNTER_VALUE ([TPM_Part2], Section 5.12)
 * This structure returns the counter value.
 * For interoperability, the value size should be 4 bytes.
 */
#define TPM_TAG_COUNTER_VALUE 0x000E
typedef struct tdTPM_COUNTER_VALUE {
  TPM_STRUCTURE_TAG tag;
  BYTE label[4];
  TPM_ACTUAL_COUNT counter;
  /* additional, not marshalled data */
  TPM_SECRET usageAuth;
  BOOL valid;
} TPM_COUNTER_VALUE;
#define sizeof_TPM_COUNTER_VALUE(s) (2 + 4 + 4)
#define sizeof_TPM_COUNTER_VALUE2(s) (2 + 4 + 4 + 20 + 1)

/*
 * TPM_SIGN_INFO Structure ([TPM_Part2], Section 5.13)
 * To provide the mechanism to quote the current values of a list of PCRs.
 */
#define TPM_TAG_SIGNINFO 0x0005
typedef struct tdTPM_SIGN_INFO {
  TPM_STRUCTURE_TAG tag;
  BYTE fixed[4];
  TPM_NONCE replay;
  UINT32 dataLen;
  BYTE* data;
} TPM_SIGN_INFO;

/*
 * TPM_CMK_AUTH ([TPM_Part2], Section 5.14)
 */
typedef struct tdTPM_CMK_AUTH {
  TPM_DIGEST migrationAuthorityDigest;
  TPM_DIGEST destinationKeyDigest;
  TPM_DIGEST sourceKeyDigest;
} TPM_CMK_AUTH;

/*
 * TPM_CMK_RESTRICTDELEGATE ([TPM_Part2], Section 5.15)
 * Determine how to respond to delegated requests to manipulate a
 * restricted-migration key.
 */
typedef UINT32 TPM_CMK_RESTRICTDELEGATE;
#define TPM_RESTRICT_MIGRATE_SIGNING            (1 << 31)
#define TPM_RESTRICT_MIGRATE_STORAGE            (1 << 30)
#define TPM_RESTRICT_MIGRATE_BIND               (1 << 29)
#define TPM_RESTRICT_MIGRATE_LEGACY             (1 << 28)
/* 27-0 are reserved and must be 0 */

/*
 * Command Tags ([TPM_Part2], Section 6)
 * Indicate the construction of the command either as input or as output.
 */
#define TPM_TAG_RQU_COMMAND             0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND       0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND       0x00C3
#define TPM_TAG_RSP_COMMAND             0x00C4
#define TPM_TAG_RSP_AUTH1_COMMAND       0x00C5
#define TPM_TAG_RSP_AUTH2_COMMAND       0x00C6

/*
 * Oridinals ([TPM_Part2], Section 17)
 * The command ordinals provide the index value for each command.
 */
#define TPM_PROTECTED_COMMAND           0x00000000
#define TPM_UNPROTECTED_COMMAND         0x80000000
#define TPM_CONNECTION_COMMAND          0x40000000
#define TPM_VENDOR_COMMAND              0x20000000

#define TPM_MAIN                        0x00
#define TPM_PC                          0x01
#define TPM_PDA                         0x02
#define TPM_CELL_PHONE                  0x03
#define TPM_SERVER                      0x04

#define TPM_PROTECTED_ORDINAL           (TPM_PROTECTED_COMMAND | TPM_MAIN)
#define TPM_UNPROTECTED_ORDINAL         (TPM_UNPROTECTED_COMMAND | TPM_MAIN)
#define TPM_CONNECTION_ORDINAL          (TPM_CONNECTION_COMMAND | TPM_MAIN)

#define TPM_ORD_INDEX_MASK              0x0000FFFF

#define TPM_ORD_OIAP                            10
#define TPM_ORD_OSAP                            11
#define TPM_ORD_ChangeAuth                      12
#define TPM_ORD_TakeOwnership                   13
#define TPM_ORD_ChangeAuthAsymStart             14
#define TPM_ORD_ChangeAuthAsymFinish            15
#define TPM_ORD_ChangeAuthOwner                 16
#define TPM_ORD_DSAP                            17
#define TPM_ORD_CMK_CreateTicket                18
#define TPM_ORD_CMK_CreateKey                   19
#define TPM_ORD_Extend                          20
#define TPM_ORD_PCRRead                         21
#define TPM_ORD_Quote                           22
#define TPM_ORD_Seal                            23
#define TPM_ORD_Unseal                          24
#define TPM_ORD_DirWriteAuth                    25
#define TPM_ORD_DirRead                         26
#define TPM_ORD_CMK_CreateBlob                  27
#define TPM_ORD_CMK_SetRestrictions             28
#define TPM_ORD_UnBind                          30
#define TPM_ORD_CreateWrapKey                   31
#define TPM_ORD_LoadKey                         32
#define TPM_ORD_GetPubKey                       33
#define TPM_ORD_EvictKey                        34
#define TPM_ORD_KeyControlOwner                 35
#define TPM_ORD_CreateMigrationBlob             40
#define TPM_ORD_ConvertMigrationBlob            42
#define TPM_ORD_AuthorizeMigrationKey           43
#define TPM_ORD_CreateMaintenanceArchive        44
#define TPM_ORD_LoadMaintenanceArchive          45
#define TPM_ORD_KillMaintenanceFeature          46
#define TPM_ORD_LoadManuMaintPub                47
#define TPM_ORD_ReadManuMaintPub                48
#define TPM_ORD_CertifyKey                      50
#define TPM_ORD_CertifyKey2                     51
#define TPM_ORD_Sign                            60
#define TPM_ORD_LoadKey2                        65
#define TPM_ORD_GetRandom                       70
#define TPM_ORD_StirRandom                      71
#define TPM_ORD_SelfTestFull                    80
#define TPM_ORD_CertifySelfTest                 82
#define TPM_ORD_ContinueSelfTest                83
#define TPM_ORD_GetTestResult                   84
#define TPM_ORD_Reset                           90
#define TPM_ORD_OwnerClear                      91
#define TPM_ORD_DisableOwnerClear               92
#define TPM_ORD_ForceClear                      93
#define TPM_ORD_DisableForceClear               94
#define TPM_ORD_GetCapabilitySigned             100
#define TPM_ORD_GetCapability                   101
#define TPM_ORD_GetCapabilityOwner              102
#define TPM_ORD_OwnerSetDisable                 110
#define TPM_ORD_PhysicalEnable                  111
#define TPM_ORD_PhysicalDisable                 112
#define TPM_ORD_SetOwnerInstall                 113
#define TPM_ORD_PhysicalSetDeactivated          114
#define TPM_ORD_SetTempDeactivated              115
#define TPM_ORD_SetOperatorAuth                 116
#define TPM_ORD_SetOwnerPointer                 117
#define TPM_ORD_CreateEndorsementKeyPair        120
#define TPM_ORD_MakeIdentity                    121
#define TPM_ORD_ActivateIdentity                122
#define TPM_ORD_ReadPubek                       124
#define TPM_ORD_OwnerReadPubek                  125
#define TPM_ORD_DisablePubekRead                126
#define TPM_ORD_CreateRevocableEK               127
#define TPM_ORD_RevokeTrust                     128
#define TPM_ORD_OwnerReadInternalPub            129
#define TPM_ORD_GetAuditEvent                   130
#define TPM_ORD_GetAuditEventSigned             131
#define TPM_ORD_GetAuditDigest                  133
#define TPM_ORD_GetAuditDigestSigned            134
#define TPM_ORD_GetOrdinalAuditStatus           140
#define TPM_ORD_SetOrdinalAuditStatus           141
#define TPM_ORD_Terminate_Handle                150
#define TPM_ORD_Init                            151
#define TPM_ORD_SaveState                       152
#define TPM_ORD_Startup                         153
#define TPM_ORD_SetRedirection                  154
#define TPM_ORD_SHA1Start                       160
#define TPM_ORD_SHA1Update                      161
#define TPM_ORD_SHA1Complete                    162
#define TPM_ORD_SHA1CompleteExtend              163
#define TPM_ORD_FieldUpgrade                    170
#define TPM_ORD_SaveKeyContext                  180
#define TPM_ORD_LoadKeyContext                  181
#define TPM_ORD_SaveAuthContext                 182
#define TPM_ORD_LoadAuthContext                 183
#define TPM_ORD_SaveContext                     184
#define TPM_ORD_LoadContext                     185
#define TPM_ORD_FlushSpecific                   186
#define TPM_ORD_PCR_Reset                       200
#define TPM_ORD_NV_DefineSpace                  204
#define TPM_ORD_NV_WriteValue                   205
#define TPM_ORD_NV_WriteValueAuth               206
#define TPM_ORD_NV_ReadValue                    207
#define TPM_ORD_NV_ReadValueAuth                208
#define TPM_ORD_Delegate_UpdateVerification     209
#define TPM_ORD_Delegate_Manage                 210
#define TPM_ORD_Delegate_CreateKeyDelegation    212
#define TPM_ORD_Delegate_CreateOwnerDelegation  213
#define TPM_ORD_Delegate_VerifyDelegation       214
#define TPM_ORD_Delegate_LoadOwnerDelegation    216
#define TPM_ORD_Delegate_ReadAuth               217
#define TPM_ORD_Delegate_ReadTable              219
#define TPM_ORD_CreateCounter                   220
#define TPM_ORD_IncrementCounter                221
#define TPM_ORD_ReadCounter                     222
#define TPM_ORD_ReleaseCounter                  223
#define TPM_ORD_ReleaseCounterOwner             224
#define TPM_ORD_EstablishTransport              230
#define TPM_ORD_ExecuteTransport                231
#define TPM_ORD_ReleaseTransportSigned          232
#define TPM_ORD_SetTickType                     240
#define TPM_ORD_GetTicks                        241
#define TPM_ORD_TickStampBlob                   242
#define TSC_ORD_PhysicalPresence                (10 + TPM_CONNECTION_COMMAND)
#define TSC_ORD_ResetEstablishmentBit           (11 + TPM_CONNECTION_COMMAND)
#define TPM_ORD_DAA_Join                        41
#define TPM_ORD_DAA_Sign                        49
#define TPM_ORD_GPIO_AuthChannel                252 /* TODO: determine TPM_ORD_GPIO_AuthChannel */
#define TPM_ORD_GPIO_ReadWrite                  253 /* TODO: determine TPM_ORD_GPIO_ReadWrite */

#define TPM_ORD_MAX                             256

/*
 * PCR Structures
 */

/*
 * Number of PCRs of the TPM (must be a multiple of eight)
 */
#define TPM_NUM_PCR 24

/*
 * TPM_PCR_SELECTION ([TPM_Part2], Section 8.1)
 * Provides a standard method of specifying a list of PCR registers.
 * Note: An error is reported if sizeOfSelect > sizeof(pcrSelect).
 */
typedef struct tdTPM_PCR_SELECTION {
  UINT16 sizeOfSelect;
  BYTE pcrSelect[TPM_NUM_PCR/8];
} TPM_PCR_SELECTION;
#define sizeof_TPM_PCR_SELECTION(s) (2 + s.sizeOfSelect)

/*
 * TPM_PCR_COMPOSITE ([TPM_Part2], Section 8.2)
 * The composite structure provides the index and value of the PCR register
 * to be used when creating the value that SEALS an entity to the composite.
 */
typedef struct tdTPM_PCR_COMPOSITE {
  TPM_PCR_SELECTION select;
  UINT32 valueSize;
  TPM_PCRVALUE pcrValue[TPM_NUM_PCR];
} TPM_PCR_COMPOSITE;
#define sizeof_TPM_PCR_COMPOSITE(s) (sizeof_TPM_PCR_SELECTION(s.select) \
  + 4 + s.valueSize)

/*
 * TPM_LOCALITY_SELECTION ([TPM_Part2], Section 8.6)
 * When used with localityAtCreation only one bit is set and it corresponds
 * to the locality of the command creating the structure.
 */
typedef BYTE TPM_LOCALITY_SELECTION;
/* 5-7 are reserved and must be 0 */
#define TPM_LOC_FOUR    (1 << 4)
#define TPM_LOC_THREE   (1 << 3)
#define TPM_LOC_TWO     (1 << 2)
#define TPM_LOC_ONE     (1 << 1)
#define TPM_LOC_ZERO    (1 << 0)

/*
 * TPM_PCR_INFO ([TPM_Part2], Section 8.3)
 * Contains the information related to the wrapping of a key or the sealing
 * of data, to a set of PCRs.
 * The TPM_PCR_INFO_LONG ([TPM_Part2], Section 8.4) includes information 
 * necessary to properly define the configuration that creates the blob using 
 * the PCR selection.
 */
#define TPM_TAG_PCR_INFO_LONG 0x0006
typedef struct tdTPM_PCR_INFO {
  TPM_STRUCTURE_TAG tag;
  TPM_LOCALITY_SELECTION localityAtCreation;
  TPM_LOCALITY_SELECTION localityAtRelease;
  TPM_PCR_SELECTION creationPCRSelection;
  TPM_PCR_SELECTION releasePCRSelection;
  TPM_COMPOSITE_HASH digestAtCreation;
  TPM_COMPOSITE_HASH digestAtRelease;
} TPM_PCR_INFO;
#define sizeof_TPM_PCR_INFO(s) (2 + 1 + 1 \
  + sizeof_TPM_PCR_SELECTION(s.creationPCRSelection) \
  + sizeof_TPM_PCR_SELECTION(s.releasePCRSelection) + 20 +20)

/*
 * TPM_PCR_INFO_SHORT ([TPM_Part2], Section 8.5)
 * Defines a digest at release when the only information that is necessary
 * is the release configuration.
 */
typedef struct tdTPM_PCR_INFO_SHORT {
  TPM_PCR_SELECTION pcrSelection;
  TPM_LOCALITY_SELECTION localityAtRelease;
  TPM_COMPOSITE_HASH digestAtRelease;
} TPM_PCR_INFO_SHORT;
#define sizeof_TPM_PCR_INFO_SHORT(s) ( \
  sizeof_TPM_PCR_SELECTION(s.pcrSelection) + 1 + 20)

/*
 * TPM_PCR_ATTRIBUTES ([TPM_Part2], Section 8.8)
 * These attributes are available on a per PCR basis.
 */
#define TPM_NUM_LOCALITY 5
typedef struct tdTPM_PCR_ATTRIBUTES {
  BOOL pcrReset;
  BOOL pcrResetLocal[TPM_NUM_LOCALITY];
  BOOL pcrExtendLocal[TPM_NUM_LOCALITY];
} TPM_PCR_ATTRIBUTES;
#define sizeof_TPM_PCR_ATTRIBUTES(s) (1 + 2*TPM_NUM_LOCALITY)

/*
 * Storage Structures
 */

/*
 * TPM_STORED_DATA ([TPM_Part2], Section 9.1)
 * TPM_STORED_DATA12 ([TPM_Part2], Section 9.2)
 * The definition of this structure is necessary to ensure
 * the enforcement of security properties.
 */
#define TPM_TAG_STORED_DATA12 0x0016
typedef struct tdTPM_STORED_DATA {
  TPM_STRUCTURE_TAG tag;
  UINT16 fill;
  UINT32 sealInfoSize;
  TPM_PCR_INFO sealInfo;
  UINT32 encDataSize;
  BYTE* encData;
} TPM_STORED_DATA;
#define sizeof_TPM_STORED_DATA(s) (2 + 2 + 4 + s.sealInfoSize + 4 + s.encDataSize)
#define free_TPM_STORED_DATA(s) { if (s.encDataSize > 0) tpm_free(s.encData); }

/*
 * TPM_SEALED_DATA ([TPM_Part2], Section 9.3)
 * This structure contains confidential information related
 * to sealed data, including the data itself.
 */
typedef struct tdTPM_SEALED_DATA {
  TPM_PAYLOAD_TYPE payload;
  TPM_SECRET authData;
  TPM_NONCE tpmProof;
  TPM_DIGEST storedDigest;
  UINT32 dataSize;
  BYTE* data;
} TPM_SEALED_DATA;
#define sizeof_TPM_SEALED_DATA(s) (1 + 20 + 20 + 20 + 4 + s.dataSize)
#define free_TPM_SEALED_DATA(s) { if (s.dataSize > 0) tpm_free(s.data); }

/*
 * TPM_SYMMETRIC_KEY ([TPM_Part2], Section 9.4)
 * Describes a symmetric key.
 */
typedef struct tdTPM_SYMMETRIC_KEY {
  TPM_ALGORITHM_ID algId;
  TPM_ENC_SCHEME encScheme;
  UINT16 size;
  BYTE* data;
} TPM_SYMMETRIC_KEY;
#define sizeof_TPM_SYMMETRIC_KEY(s) (4 + 2 + 2 + s.size)
#define free_TPM_SYMMETRIC_KEY(s) { if (s.size > 0) tpm_free(s.data); }

/*
 * TPM_BOUND_DATA ([TPM_Part2], Section 9.5)
 * This structure is used by a TPM_UnBind command in a consistency check.
 */
typedef struct tdTPM_BOUND_DATA {
  TPM_STRUCT_VER ver;
  TPM_PAYLOAD_TYPE payload;
  BYTE* payloadData;
} TPM_BOUND_DATA;

/*
 * TPM_RSA_KEY_PARMS ([TPM_Part2], Section 10.1.1)
 * This structure describes the parameters of an RSA key.
 */
typedef struct tdTPM_RSA_KEY_PARMS {
  UINT32 keyLength;
  UINT32 numPrimes;
  UINT32 exponentSize;
  BYTE* exponent;
} TPM_RSA_KEY_PARMS;
#define sizeof_TPM_RSA_KEY_PARMS(s) (4 + 4 + 4 + s.exponentSize)
#define free_TPM_RSA_KEY_PARMS(s) { if (s.exponentSize > 0) tpm_free(s.exponent); }

/*
 * TPM_SYMMETRIC_KEY_PARMS ([TPM_Part2], Section 10.1.2)
 * This structure describes the parameters for symmetric algorithms.
 */
typedef struct tdTPM_SYMMETRIC_KEY_PARMS {
  UINT32 keyLength;
  UINT32 blockSize;
  UINT32 ivSize;
  BYTE* IV;
} TPM_SYMMETRIC_KEY_PARMS;
#define sizeof_TPM_SYMMETRIC_KEY_PARMS(s) (4 + 4 + 4 + s.ivSize)
#define free_TPM_SYMMETRIC_KEY_PARMS(s) { if (s.ivSize > 0) tpm_free(s.IV); }

/*
 * TPM_KEY_PARMS ([TPM_Part2], Section 10.1)
 * This provides a standard mechanism to define the parameters used to
 * generate a key pair.
 */
typedef struct tdTPM_KEY_PARMS {
  TPM_ALGORITHM_ID algorithmID;
  TPM_ENC_SCHEME encScheme;
  TPM_SIG_SCHEME sigScheme;
  UINT32 parmSize;
  union {
    BYTE* raw;
    TPM_RSA_KEY_PARMS rsa;
    TPM_SYMMETRIC_KEY_PARMS skp;
  } parms;
} TPM_KEY_PARMS;
#define sizeof_TPM_KEY_PARMS(s) (4 + 2 + 2 + 4 + s.parmSize)
#define free_TPM_KEY_PARMS(s) { if (s.parmSize > 0) { \
  switch (s.algorithmID) { \
    case TPM_ALG_RSA: free_TPM_RSA_KEY_PARMS(s.parms.rsa); break; \
    case TPM_ALG_DES: case TPM_ALG_3DES: \
    case TPM_ALG_AES192: case TPM_ALG_AES256: \
    free_TPM_SYMMETRIC_KEY_PARMS(s.parms.skp); break; \
    default: tpm_free(s.parms.raw); } } }

/*
 * TPM_STORE_PUBKEY ([TPM_Part2], Section 10.4)
 * This structure can be used in conjunction with a corresponding
 * TPM_KEY_PARMS to construct a public key which can be unambiguously used.
 */
typedef struct tdTPM_STORE_PUBKEY {
  UINT32 keyLength;
  BYTE* key;
} TPM_STORE_PUBKEY;
#define sizeof_TPM_STORE_PUBKEY(s) (4 + s.keyLength)
#define free_TPM_STORE_PUBKEY(s) { if (s.keyLength > 0) tpm_free(s.key); }

/*
 * TPM_KEY ([TPM_Part2], Section 10.2)
 * The TPM_KEY structure provides a mechanism to transport the entire
 * asymmetric key pair. The private portion of the key is always encrypted.
 * The TPM_KEY12 ([TPM_Part2], Section 10.3) structure uses the new
 * PCR_INFO_LONG structures and the new structure tagging.
 */

#define TPM_TAG_KEY12 0x0028
typedef struct tdTPM_KEY {
  TPM_STRUCTURE_TAG tag;
  UINT16 fill;
  TPM_KEY_USAGE keyUsage;
  TPM_KEY_FLAGS keyFlags;
  TPM_AUTH_DATA_USAGE authDataUsage;
  TPM_KEY_PARMS algorithmParms;
  UINT32 PCRInfoSize;
  TPM_PCR_INFO PCRInfo;
  TPM_STORE_PUBKEY pubKey;
  UINT32 encDataSize;
  BYTE* encData;
} TPM_KEY;
#define sizeof_TPM_KEY(s) (4 + 2 + 4 + 1 + sizeof_TPM_KEY_PARMS(s.algorithmParms) \
  + 4 + s.PCRInfoSize + sizeof_TPM_STORE_PUBKEY(s.pubKey) \
  + 4 + s.encDataSize)
#define free_TPM_KEY(s) { if (s.encDataSize > 0) tpm_free(s.encData); \
  free_TPM_KEY_PARMS(s.algorithmParms); free_TPM_STORE_PUBKEY(s.pubKey); }

/*
 * TPM_PUBKEY ([TPM_Part2], Section 10.5)
 * Public portion of an asymmetric key pair.
 */
typedef struct tdTPM_PUBKEY {
  TPM_KEY_PARMS algorithmParms;
  TPM_STORE_PUBKEY pubKey;
} TPM_PUBKEY;
#define sizeof_TPM_PUBKEY(s) (sizeof_TPM_KEY_PARMS(s.algorithmParms) \
  + sizeof_TPM_STORE_PUBKEY(s.pubKey))
#define free_TPM_PUBKEY(s) { free_TPM_KEY_PARMS(s.algorithmParms); \
  free_TPM_STORE_PUBKEY(s.pubKey); }

/*
 * TPM_STORE_PRIVKEY ([TPM_Part2], Section 10.7)
 * This structure can be used in conjunction with a corresponding TPM_PUBKEY
 * to construct a private key which can be unambiguously used.
 */
typedef struct tdTPM_STORE_PRIVKEY {
  UINT32 keyLength;
  BYTE* key;
} TPM_STORE_PRIVKEY;
#define sizeof_TPM_STORE_PRIVKEY(s) (4 + s.keyLength)
#define free_TPM_STORE_PRIVKEY(s) { if (s.keyLength > 0) tpm_free(s.key); }

/*
 * TPM_STORE_ASYMKEY ([TPM_Part2], Section 10.6)
 * The TPM_STORE_ASYMKEY structure provides the area to identify the
 * confidential information related to a key.
 */
typedef struct tdTPM_STORE_ASYMKEY {
  TPM_PAYLOAD_TYPE payload;
  TPM_SECRET usageAuth;
  TPM_SECRET migrationAuth;
  TPM_DIGEST pubDataDigest;
  TPM_STORE_PRIVKEY privKey;
} TPM_STORE_ASYMKEY;
#define sizeof_TPM_STORE_ASYMKEY(s) ( 1 + 20 + 20 + 20 \
  + sizeof_TPM_STORE_PRIVKEY(s.privKey))
#define free_TPM_STORE_ASYMKEY(s) { free_TPM_STORE_PRIVKEY(s.privKey) }

/*
 * TPM_MIGRATE_ASYMKEY ([TPM_Part2], Section 10.8)
 * The TPM_MIGRATE_ASYMKEY structure provides the area to identify the private
 * key factors of a asymmetric key while the key is migrating between TPM.
 */
typedef struct tdTPM_MIGRATE_ASYMKEY {
  TPM_PAYLOAD_TYPE payload;
  TPM_SECRET usageAuth;
  TPM_DIGEST pubDataDigest;
  UINT32 partPrivKeyLen;
  TPM_STORE_PRIVKEY partPrivKey;
} TPM_MIGRATE_ASYMKEY;

/*
 * TPM_MIGRATIONKEYAUTH ([TPM_Part2], Section 5.11)
 * To proof that the associated key has authorization to be a migration key.
 */
typedef struct tdTPM_MIGRATIONKEYAUTH {
  TPM_PUBKEY migrationKey;
  TPM_MIGRATE_SCHEME migrationScheme;
  TPM_DIGEST digest;
} TPM_MIGRATIONKEYAUTH;
#define sizeof_TPM_MIGRATIONKEYAUTH(s) (sizeof_TPM_PUBKEY(s.migrationKey) + 2 + 20)
#define free_TPM_MIGRATIONKEYAUTH(s) { free_TPM_PUBKEY(s.migrationKey); }

/*
 * TPM_KEY_CONTROL ([TPM_Part2], Section 10.9)
 * Attributes that can control various aspects of key usage and manipulation.
 */
/* 31:-1 reserved and must be 0 */
#define TPM_KEY_CONTROL_OWNER_EVICT 0

/*
 * Signed Structures
 */

/*
 * TPM_CERTIFY_INFO Structure ([TPM_Part2], Section 11.1)
 * TPM_CERTIFY_INFO2 Structure ([TPM_Part2], Section 11.2)
 * This structure provides the mechanism to provide a signature with a TPM
 * identity key on information that describes that key.
 */
#define TPM_TAG_CERTIFY_INFO2 0x0029
typedef struct tdTPM_CERTIFY_INFO {
  TPM_STRUCTURE_TAG tag;
  UINT16 fill;
  TPM_KEY_USAGE keyUsage;
  TPM_KEY_FLAGS keyFlags;
  TPM_AUTH_DATA_USAGE authDataUsage;
  TPM_KEY_PARMS algorithmParms;
  TPM_DIGEST pubkeyDigest;
  TPM_NONCE data;
  BOOL parentPCRStatus;
  UINT32 migrationAuthoritySize;
  BYTE* migrationAuthority;
  UINT32 PCRInfoSize;
  TPM_PCR_INFO PCRInfo;
} TPM_CERTIFY_INFO;
#define sizeof_TPM_CERTIFY_INFO(s) (4 + 2 + 4 + 1 + \
  sizeof_TPM_KEY_PARMS(s.algorithmParms) + 20 + 20 + 1 + 4 \
  + s.PCRInfoSize + s.migrationAuthoritySize)
#define free_TPM_CERTIFY_INFO(s) { free_TPM_KEY_PARMS(s.algorithmParms); \
  if (s.migrationAuthoritySize > 0) tpm_free(s.migrationAuthority); }

/*
 * TPM_QUOTE_INFO Structure ([TPM_Part2], Section 11.3)
 * This structure provides the mechanism for the TPM to quote the
 * current values of a list of PCRs.
 */
typedef struct tdTPM_QUOTE_INFO {
  TPM_STRUCT_VER version;
  BYTE fixed[4];
  TPM_COMPOSITE_HASH digestValue;
  TPM_NONCE externalData;
} TPM_QUOTE_INFO;

/*
 * Identity Structures
 */

/*
 * TPM_EK_BLOB ([TPM_Part2], Section 12.1)
 * This structure provides a wrapper to each type of structure that
 * will be in use when the endorsement key is in use.
 */
#define TPM_TAG_EK_BLOB_ACTIVATE 0x002B
typedef struct tdTPM_EK_BLOB {
  TPM_STRUCTURE_TAG tag;
  TPM_EK_TYPE ekType;
  UINT32 blobSize;
  BYTE* blob;
} TPM_EK_BLOB;

/*
 * TPM_EK_BLOB_ACTIVATE ([TPM_Part2], Section 12.2)
 * This structure contains the symmetric key to encrypt the identity
 * credential. This structure always is contained in a TPM_EK_BLOB.
 */
#define TPM_TAG_EK_BLOB_ACTIVATE 0x002B
typedef struct tdTPM_EK_BLOB_ACTIVATE {
  TPM_STRUCTURE_TAG tag;
  TPM_SYMMETRIC_KEY sessionKey;
  TPM_DIGEST idDigest;
  TPM_PCR_INFO_SHORT pcrInfo;
} TPM_EK_BLOB_ACTIVATE;

/*
 * TPM_EK_BLOB_AUTH ([TPM_Part2], Section 12.3)
 * This structure contains the symmetric key to encrypt the identity
 * credential. This structure always is contained in a TPM_EK_BLOB.
 */
#define TPM_TAG_EK_BLOB_AUTH 0x000D
typedef struct tdTPM_EK_BLOB_AUTH {
  TPM_STRUCTURE_TAG tag;
  TPM_SECRET authValue;
} TPM_EK_BLOB_AUTH;

/*
 * TPM_IDENTITY_CONTENTS ([TPM_Part2], Section 12.5)
 * TPM_MakeIdentity uses this structure and the signature of this structure
 * goes to a privacy CA during the certification process.
 */
typedef struct tdTPM_IDENTITY_CONTENTS {
  TPM_STRUCT_VER ver;
  UINT32 ordinal;
  TPM_CHOSENID_HASH labelPrivCADigest;
  TPM_PUBKEY identityPubKey;
} TPM_IDENTITY_CONTENTS;
#define sizeof_TPM_IDENTITY_CONTENTS(s) (4 + 4 + 20 + \
  sizeof_TPM_PUBKEY(s.identityPubKey))

/*
 * TPM_IDENTITY_REQ ([TPM_Part2], Section 12.6)
 * This structure is sent by the TSS to the Privacy CA to create the
 * identity credential.
 */
typedef struct tdTPM_IDENTITY_REQ {
  UINT32 asymSize;
  UINT32 symSize;
  TPM_KEY_PARMS asymAlgorithm;
  TPM_KEY_PARMS symAlgorithm;
  BYTE* asymBlob;
  BYTE* symBlob;
} TPM_IDENTITY_REQ;

/*
 * TPM_IDENTITY_PROOF ([TPM_Part2], Section 12.7)
 * Structure in use during the AIK credential process.
 */
typedef struct tdTPM_IDENTITY_PROOF {
  TPM_STRUCT_VER ver;
  UINT32 labelSize;
  UINT32 identityBindingSize;
  UINT32 endorsementSize;
  UINT32 platformSize;
  UINT32 conformanceSize;
  TPM_PUBKEY identityKey;
  BYTE* labelArea;
  BYTE* identityBinding;
  BYTE* endorsementCredential;
  BYTE* platformCredential;
  BYTE* conformanceCredential;
} TPM_IDENTITY_PROOF;

/*
 * TPM_ASYM_CA_CONTENTS ([TPM_Part2], Section 12.8)
 * Contains the symmetric key to encrypt the identity credential.
 */
typedef struct tdTPM_ASYM_CA_CONTENTS {
  TPM_SYMMETRIC_KEY sessionKey;
  TPM_DIGEST idDigest;
} TPM_ASYM_CA_CONTENTS;

/*
 * TPM_SYM_CA_ATTESTATION ([TPM_Part2], Section 12.9)
 * This structure returned by the Privacy CA with the encrypted
 * identity credential.
 */
typedef struct tdTPM_SYM_CA_ATTESTATION {
  UINT32 credSize;
  TPM_KEY_PARMS algorithm;
  BYTE* credential;
} TPM_SYM_CA_ATTESTATION;

/*
 * Tick Structures
 */

/*
 * TPM_CURRENT_TICKS ([TPM_Part2], Section 15.1)
 * This structure holds the current number of time ticks in the TPM.
 */
#define TPM_TAG_CURRENT_TICKS 0x0014
typedef struct tdTPM_CURRENT_TICKS {
  TPM_STRUCTURE_TAG tag;
  UINT64 currentTicks;
  UINT16 tickType;
  UINT16 tickRate;
  UINT16 tickSecurity;
  TPM_NONCE tickNonce;
} TPM_CURRENT_TICKS;
#define sizeof_TPM_CURRENT_TICKS(s) (2 + 8 + 2 + 2 + 2 + 20)

/*
 * TPM_TICKTYPE values ([TPM_Part2], Section 15.1.1)
 * These values indicate to challengers of the TPM the mechanism that the
 * TPM and the platform use to maintain the tick values inside of the TPM.
 */
typedef BYTE TPM_TICKTYPE;
#define TICK_INC                0x00
#define TICK_INC_SAVE           0x01
#define TICK_POWER              0x02
#define TICK_POWER_SAVE         0x03
#define TICK_STSTATE            0x04
#define TICK_STSTATE_SAVE       0x05
#define TICK_STCLEAR            0x06
#define TICK_STCLEAR_SAVE       0x07
#define TICK_ALWAYS             0x08
#define TICK_SEC_NO_CHECK       0x01
#define TICK_SEC_RATE_CHECK     0x02

/*
 * Transport Structures
 */

#define TPM_TRANSPORT_ENCRYPT   0x01
#define TPM_TRANSPORT_LOG       0x02
#define TPM_TRANSPORT_EXCL_ATTR 0x04

/*
 * TPM _TRANSPORT_PUBLIC ([TPM_Part2], Section 13.1)
 * The public information relative to a transport session.
 */
#define TPM_TAG_TRANSPORT_PUBLIC 0x001E
typedef struct tdTPM_TRANSPORT_PUBLIC {
  TPM_STRUCTURE_TAG tag;
  TPM_TRANSPORT_ATTRIBUTES transAttributes;
  TPM_ALGORITHM_ID algID;
  TPM_ENC_SCHEME encScheme;
} TPM_TRANSPORT_PUBLIC;
#define sizeof_TPM_TRANSPORT_PUBLIC(s) (2 + 4 + 4 + 2)

/*
 * TPM_TRANSPORT_INTERNAL ([TPM_Part2], Section 13.2)
 * The internal information regarding transport session.
 */
#define TPM_TAG_TRANSPORT_INTERNAL 0x000F
typedef struct tdTPM_TRANSPORT_INTERNAL {
  TPM_STRUCTURE_TAG tag;
  TPM_AUTHDATA authData;
  TPM_TRANSPORT_PUBLIC transPublic;
  TPM_TRANSHANDLE transHandle;
  TPM_NONCE transEven;
  TPM_DIGEST transDigest;
} TPM_TRANSPORT_INTERNAL;
#define sizeof_TPM_TRANSPORT_INTERNAL(s) (2 + 20 + 4 + 20 + 20 \
  + sizeof_TPM_TRANSPORT_PUBLIC(s.tranPublic))

/*
 * TPM_TRANSPORT_LOG_IN structure ([TPM_Part2], Section 13.3)
 * This structure is in use for input log calculations.
 */
#define TPM_TAG_TRANSPORT_LOG_IN 0x0010
typedef struct tdTPM_TRANSPORT_LOG_IN {
  TPM_STRUCTURE_TAG tag;
  TPM_COMMAND_CODE ordinal;
  TPM_DIGEST parameters;
  TPM_DIGEST pubKeyHash;
} TPM_TRANSPORT_LOG_IN;
#define sizeof_TPM_TRANSPORT_LOG_IN(s) (2 + 4 + 2*20)

/*
 * TPM_TRANSPORT_LOG_OUT structure ([TPM_Part2], Section 13.4)
 * This structure is in use for the INPUT logging during releaseTransport.
 */
#define TPM_TAG_TRANSPORT_LOG_OUT 0x0011
typedef struct tdTPM_TRANSPORT_LOG_OUT {
  TPM_STRUCTURE_TAG tag;
  TPM_CURRENT_TICKS currentTicks;
  TPM_DIGEST parameters;
  TPM_MODIFIER_INDICATOR locality;
} TPM_TRANSPORT_LOG_OUT;
#define sizeof_TPM_TRANSPORT_LOG_OUT(s) (2 + 20 + 4 \
  + sizeof_TPM_CURRENT_TICKS(s.currentTicks))

/*
 * TPM_TRANSPORT_AUTH structure ([TPM_Part2], Section 13.5)
 * Provides the validation for the encrypted authorization value.
 */
#define TPM_TAG_TRANSPORT_AUTH 0x001D
typedef struct tdTPM_TRANSPORT_AUTH {
  TPM_STRUCTURE_TAG tag;
  TPM_AUTHDATA authData;
} TPM_TRANSPORT_AUTH;
#define sizeof_TPM_TRANSPORT_AUTH(s) (2 + 20)

/*
 * Audit Structures
 */

/*
 * TPM_AUDIT_EVENT_IN structure ([TPM_Part2], Section 14.1)
 * This structure provides the auditing of the command upon receipt of
 * the command. It provides the information regarding the input parameters.
 */
#define TPM_TAG_AUDIT_EVENT_IN 0x0012
typedef struct tdTPM_AUDIT_EVENT_IN {
  TPM_STRUCTURE_TAG tag;
  TPM_COMMAND_CODE ordinal;
  TPM_DIGEST inputParms;
  TPM_COUNTER_VALUE auditCount;
} TPM_AUDIT_EVENT_IN;
#define sizeof_TPM_AUDIT_EVENT_IN(s) (2 + 4 + 20 \
  + sizeof_TPM_COUNTER_VALUE(s.auditCount))

/*
 * TPM_AUDIT_EVENT_OUT structure ([TPM_Part2], Section 14.2)
 * This structure reports the results of the command execution.
 * It includes the return code and the output parameters.
 */
#define TPM_TAG_AUDIT_EVENT_OUT 0x0013
typedef struct tdTPM_AUDIT_EVENT_OUT {
  TPM_STRUCTURE_TAG tag;
  TPM_COMMAND_CODE ordinal;
  TPM_DIGEST outputParms;
  TPM_COUNTER_VALUE auditCount;
  TPM_RESULT returncode;
} TPM_AUDIT_EVENT_OUT;
#define sizeof_TPM_AUDIT_EVENT_OUT(s) (2 + 4 + 20 \
  + sizeof_TPM_COUNTER_VALUE(s.auditCount) + 4)

/*
 * TPM Return Codes ([TPM_Part2], Section 16)
 */
#define TPM_NON_FATAL                   0x00000800
#define TPM_BASE                        0x00000000

#define TPM_SUCCESS                     (TPM_BASE + 0)
#define TPM_AUTHFAIL                    (TPM_BASE + 1)
#define TPM_BADINDEX                    (TPM_BASE + 2)
#define TPM_BAD_PARAMETER               (TPM_BASE + 3)
#define TPM_AUDITFAILURE                (TPM_BASE + 4)
#define TPM_CLEAR_DISABLED              (TPM_BASE + 5)
#define TPM_DEACTIVATED                 (TPM_BASE + 6)
#define TPM_DISABLED                    (TPM_BASE + 7)
#define TPM_DISABLED_CMD                (TPM_BASE + 8)
#define TPM_FAIL                        (TPM_BASE + 9)
#define TPM_BAD_ORDINAL                 (TPM_BASE + 10)
#define TPM_INSTALL_DISABLED            (TPM_BASE + 11)
#define TPM_INVALID_KEYHANDLE           (TPM_BASE + 12)
#define TPM_KEYNOTFOUND                 (TPM_BASE + 13)
#define TPM_INAPPROPRIATE_ENC           (TPM_BASE + 14)
#define TPM_MIGRATEFAIL                 (TPM_BASE + 15)
#define TPM_INVALID_PCR_INFO            (TPM_BASE + 16)
#define TPM_NOSPACE                     (TPM_BASE + 17)
#define TPM_NOSRK                       (TPM_BASE + 18)
#define TPM_NOTSEALED_BLOB              (TPM_BASE + 19)
#define TPM_OWNER_SET                   (TPM_BASE + 20)
#define TPM_RESOURCES                   (TPM_BASE + 21)
#define TPM_SHORTRANDOM                 (TPM_BASE + 22)
#define TPM_SIZE                        (TPM_BASE + 23)
#define TPM_WRONGPCRVAL                 (TPM_BASE + 24)
#define TPM_BAD_PARAM_SIZE              (TPM_BASE + 25)
#define TPM_SHA_THREAD                  (TPM_BASE + 26)
#define TPM_SHA_ERROR                   (TPM_BASE + 27)
#define TPM_FAILEDSELFTEST              (TPM_BASE + 28)
#define TPM_AUTH2FAIL                   (TPM_BASE + 29)
#define TPM_BADTAG                      (TPM_BASE + 30)
#define TPM_IOERROR                     (TPM_BASE + 31)
#define TPM_ENCRYPT_ERROR               (TPM_BASE + 32)
#define TPM_DECRYPT_ERROR               (TPM_BASE + 33)
#define TPM_INVALID_AUTHHANDLE          (TPM_BASE + 34)
#define TPM_NO_ENDORSEMENT              (TPM_BASE + 35)
#define TPM_INVALID_KEYUSAGE            (TPM_BASE + 36)
#define TPM_WRONG_ENTITYTYPE            (TPM_BASE + 37)
#define TPM_INVALID_POSTINIT            (TPM_BASE + 38)
#define TPM_INAPPROPRIATE_SIG           (TPM_BASE + 39)
#define TPM_BAD_KEY_PROPERTY            (TPM_BASE + 40)
#define TPM_BAD_MIGRATION               (TPM_BASE + 41)
#define TPM_BAD_SCHEME                  (TPM_BASE + 42)
#define TPM_BAD_DATASIZE                (TPM_BASE + 43)
#define TPM_BAD_MODE                    (TPM_BASE + 44)
#define TPM_BAD_PRESENCE                (TPM_BASE + 45)
#define TPM_BAD_VERSION                 (TPM_BASE + 46)
#define TPM_NO_WRAP_TRANSPORT           (TPM_BASE + 47)
#define TPM_AUDITFAIL_UNSUCCESSFUL      (TPM_BASE + 48)
#define TPM_AUDITFAIL_SUCCESSFUL        (TPM_BASE + 49)
#define TPM_NOTRESETABLE                (TPM_BASE + 50)
#define TPM_NOTLOCAL                    (TPM_BASE + 51)
#define TPM_BAD_TYPE                    (TPM_BASE + 52)
#define TPM_INVALID_RESOURCE            (TPM_BASE + 53)
#define TPM_NOTFIPS                     (TPM_BASE + 54)
#define TPM_INVALID_FAMILY              (TPM_BASE + 55)
#define TPM_NO_NV_PERMISSION            (TPM_BASE + 56)
#define TPM_REQUIRES_SIGN               (TPM_BASE + 57)
#define TPM_KEY_NOTSUPPORTED            (TPM_BASE + 58)
#define TPM_AUTH_CONFLICT               (TPM_BASE + 59)
#define TPM_AREA_LOCKED                 (TPM_BASE + 60)
#define TPM_BAD_LOCALITY                (TPM_BASE + 61)
#define TPM_READ_ONLY                   (TPM_BASE + 62)
#define TPM_PER_NOWRITE                 (TPM_BASE + 63)
#define TPM_FAMILYCOUNT                 (TPM_BASE + 64)
#define TPM_WRITE_LOCKED                (TPM_BASE + 65)
#define TPM_BAD_ATTRIBUTES              (TPM_BASE + 66)
#define TPM_INVALID_STRUCTURE           (TPM_BASE + 67)
#define TPM_KEY_OWNER_CONTROL           (TPM_BASE + 68)
#define TPM_BAD_COUNTER                 (TPM_BASE + 69)
#define TPM_NOT_FULLWRITE               (TPM_BASE + 70)
#define TPM_CONTEXT_GAP                 (TPM_BASE + 71)
#define TPM_MAXNVWRITES                 (TPM_BASE + 72)
#define TPM_NOOPERATOR                  (TPM_BASE + 73)
#define TPM_RESOURCEMISSING             (TPM_BASE + 74)
#define TPM_DELEGATE_LOCK               (TPM_BASE + 75)
#define TPM_DELEGATE_FAMILY             (TPM_BASE + 76)
#define TPM_DELEGATE_ADMIN              (TPM_BASE + 77)
#define TPM_TRANSPORT_EXCLUSIVE         (TPM_BASE + 78)
#define TPM_OWNER_CONTROL               (TPM_BASE + 79)
#define TPM_DAA_RESOURCES               (TPM_BASE + 80)
#define TPM_DAA_INPUT_DATA0             (TPM_BASE + 81)
#define TPM_DAA_INPUT_DATA1             (TPM_BASE + 82)
#define TPM_DAA_ISSUER_SETTINGS         (TPM_BASE + 83)
#define TPM_DAA_TPM_SETTINGS            (TPM_BASE + 84)
#define TPM_DAA_STAGE                   (TPM_BASE + 85)
#define TPM_DAA_ISSUER_VALIDITY         (TPM_BASE + 86)
#define TPM_DAA_WRONG_W                 (TPM_BASE + 87)
#define TPM_BADHANDLE                   (TPM_BASE + 88)
#define TPM_BAD_DELEGATE                (TPM_BASE + 89)
#define TPM_BADCONTEXT                  (TPM_BASE + 90)
#define TPM_TOOMANYCONTEXTS             (TPM_BASE + 91)
#define TPM_MA_TICKET_SIGNATURE         (TPM_BASE + 92)
#define TPM_MA_DESTINATION              (TPM_BASE + 93)
#define TPM_MA_SOURCE                   (TPM_BASE + 94)
#define TPM_MA_AUTHORITY                (TPM_BASE + 95)
#define TPM_PERMANENTEK                 (TPM_BASE + 97) // WATCH: 97 (v1.2 rev 85)
#define TPM_BAD_SIGNATURE               (TPM_BASE + 98)
#define TPM_NOCONTEXTSPACE              (TPM_BASE + 99) // FIXME: does not ex.
#define TPM_RETRY                       (TPM_BASE + TPM_NON_FATAL)
#define TPM_NEEDS_SELFTEST              (TPM_BASE + TPM_NON_FATAL + 1)
#define TPM_DOING_SELFTEST              (TPM_BASE + TPM_NON_FATAL + 2)
#define TPM_DEFEND_LOCK_RUNNING         (TPM_BASE + TPM_NON_FATAL + 3)

/*
 * NV Storage Structures
 */

/*
 * TPM_NV_INDEX ([TPM_Part2], Section 19.1)
 * The index provides the handle to identify the area of storage.
 */
#define TPM_NV_INDEX_LOCK               0xFFFFFFFFFFFFFFFF
#define TPM_NV_INDEX_0                  0x0000000000
#define TPM_NV_INDEX_DIR                0x0000000001
#define TPM_NV_INDEX_EKCert             0x000000F000
#define TPM_NV_INDEX_TPM_CC             0x000000F001
#define TPM_NV_INDEX_PlatformCert       0x000000F002
#define TPM_NV_INDEX_Platform_CC        0x000000F003

/*
 * TPM_NV_ATTRIBUTES ([TPM_Part2], Section 19.2)
 * This structure allows the TPM to keep track of the data and
 * permissions to manipulate the area.
 */
#define TPM_TAG_NV_ATTRIBUTES 0x0017
typedef struct tdTPM_NV_ATTRIBUTES {
  TPM_STRUCTURE_TAG tag;
  UINT32 attributes;
} TPM_NV_ATTRIBUTES;

/*
 * TPM_NV_DATA_PUBLIC ([TPM_Part2], Section 19.3)
 * Represents the public description and controls on the NV area.
 */
#define TPM_TAG_NV_DATA_PUBLIC 0x0018
typedef struct tdTPM_NV_DATA_PUBLIC {
  TPM_STRUCTURE_TAG tag;
  TPM_NV_INDEX nvIndex;
  TPM_PCR_INFO_SHORT pcrInfoRead;
  TPM_PCR_INFO_SHORT pcrInfoWrite;
  TPM_NV_ATTRIBUTES permission;
  BOOL bReadSTClear;
  BOOL bWriteSTClear;
  BOOL bWriteDefine;
  UINT32 dataSize;
} TPM_NV_DATA_PUBLIC;
#define sizeof_TPM_NV_DATA_PUBLIC(s) (2 + 4 + 6 + 3 + 4 \
  + sizeof_TPM_PCR_INFO_SHORT(s.pcrInfoRead) \
  + sizeof_TPM_PCR_INFO_SHORT(s.pcrInfoWrite))

/*
 * TPM_NV_DATA_SENSITIVE ([TPM_Part2], Section 19.4)
 * This is an internal structure that the TPM uses to keep the actual
 * NV data and the controls regarding the area.
 */
#define TPM_TAG_NV_DATA_SENSITIVE 0x0019
typedef struct tdTPM_NV_DATA_SENSITIVE {
  TPM_STRUCTURE_TAG tag;
  TPM_NV_DATA_PUBLIC pubInfo;
  TPM_SECRET authValue;
  BYTE* data;
  /* next is only internally used to build a linked list */
  struct tdTPM_NV_DATA_SENSITIVE *next; 
} TPM_NV_DATA_SENSITIVE;
#define sizeof_TPM_NV_DATA_SENSITIVE(s) (2 + 20 + \
  sizeof_TPM_NV_DATA_PUBLIC(s.pubInfo) + s.pubInfo.dataSize)
#define free_TPM_NV_DATA_SENSITIVE(s) { tpm_free(s.data); }

/*
 * Delegate Structures
 */

/*
 * TPM_DELEGATIONS ([TPM_Part2], Section 20.2)
 * The delegations are in a 64-bit field. Each bit describes a capability
 * that the TPM Owner can delegate to a trusted process by setting that bit.
 */
#define TPM_DEL_OWNER_BITS 0x00000001
#define TPM_DEL_KEY_BITS 0x00000002
#define TPM_TAG_DELEGATIONS 0x001A
typedef struct tdTPM_DELEGATIONS {
  TPM_STRUCTURE_TAG tag;
  UINT32 delegateType;
  UINT32 per1;
  UINT32 per2;
} TPM_DELEGATIONS;
#define sizeof_TPM_DELEGATIONS(s) (2 + 4 + 4 + 4)
#define free_TPM_DELEGATIONS(s)

/*
 * Owner Permission Settings ([TPM_Part2], Section 20.2.1)
 * Defines the order of bits in the permission array.
 */
/* 31-28 reserved and must be 0 */
#define TPM_DELEGATE_CMD_CreateTicket                   (1 << 26)
#define TPM_DELEGATE_CMK_CreateKey                      (1 << 25)
#define TPM_DELEGATE_LoadOwnerDelegation                (1 << 24)
#define TPM_DELEGATE_DAA_Join                           (1 << 23)
#define TPM_DELEGATE_AuthorizeMigrationKey              (1 << 22)
#define TPM_DELEGATE_CreateMaintenanceArchive           (1 << 21)
#define TPM_DELEGATE_LoadMaintenanceArchive             (1 << 20)
#define TPM_DELEGATE_KillMaintenanceFeature             (1 << 19)
#define TPM_DELEGATE_CreateKeyDelegation                (1 << 18)
#define TPM_DELEGATE_LoadBlobOwner                      (1 << 17)
#define TPM_DELEGATE_OwnerClear                         (1 << 16)
#define TPM_DELEGATE_DisableOwnerClear                  (1 << 15)
#define TPM_DELEGATE_DisableForceClear                  (1 << 14)
#define TPM_DELEGATE_OwnerSetDisable                    (1 << 13)
#define TPM_DELEGATE_SetOwnerInstall                    (1 << 12)
#define TPM_DELEGATE_MakeIdentity                       (1 << 11)
#define TPM_DELEGATE_ActivateIdentity                   (1 << 10)
#define TPM_DELEGATE_OwnerReadPubek                     (1 <<  9)
#define TPM_DELEGATE_DisablePubekRead                   (1 <<  8)
#define TPM_DELEGATE_SetRedirection                     (1 <<  7)
#define TPM_DELEGATE_FieldUpgrade                       (1 <<  6)
#define TPM_DELEGATE_UpdateVerification                 (1 <<  5)
#define TPM_DELEGATE_CreateCounter                      (1 <<  4)
#define TPM_DELEGATE_ReleaseCounterOwner                (1 <<  3)
#define TPM_DELEGATE_Delegate_Manage                    (1 <<  2)
#define TPM_DELEGATE_Delegate_CreateOwnerDelegation     (1 <<  1)
#define TPM_DELEGATE_DAA_Sign                           (1 <<  0)

/*
 * Key Permission settings ([TPM_Part2], Section 20.3)
 * Defines the order of bits in the permission array.
 */
/* 31-11 reserved and must be 0 */
#define TPM_DELEGATE_CMK_CreateBlob                     (1 << 10)
#define TPM_DELEGATE_CreateMigrationBlob                (1 <<  9)
#define TPM_DELEGATE_ConvertMigrationBlob               (1 <<  8)
#define TPM_DELEGATE_CreateBlob                         (1 <<  7)
/* 6 reserved and must be 0 */
#define TPM_DELEGATE_GetPubKey                          (1 <<  5)
#define TPM_DELEGATE_Unbind                             (1 <<  4)
#define TPM_DELEGATE_Quote                              (1 <<  3)
#define TPM_DELEGATE_Unseal                             (1 <<  2)
#define TPM_DELEGATE_Seal                               (1 <<  1)
#define TPM_DELEGATE_LoadKey                            (1 <<  0)

/*
 * TPM_FAMILY_FLAGS ([TPM_Part2], Section 20.4)
 * These flags indicate the operational state of the
 * delegation and family table.
 */
/* 31-2 reserved and must be 0 */
#define DELEGATE_ADMIN_LOCK     (1 << 1)
#define TPM_FAMFLAG_ENABLE      (1 << 0)

/*
 * TPM_FAMILY_LABEL ([TPM_Part2], Section 20.5)
 * Used in the family table to hold a one-byte numeric value (sequence number)
 * that software can map to a string of bytes.
 */
typedef struct tdTPM_FAMILY_LABEL {
  BYTE label;
} TPM_FAMILY_LABEL;

/*
 * TPM_FAMILY_TABLE_ENTRY ([TPM_Part2], Section 20.6)
 * The family table entry is an individual row in the family table.
 */
#define TPM_TAG_FAMILY_TABLE_ENTRY 0x0025
typedef struct tdTPM_FAMILY_TABLE_ENTRY {
  TPM_STRUCTURE_TAG tag;
  TPM_FAMILY_LABEL familyLabel;
  TPM_FAMILY_ID familyID;
  TPM_FAMILY_VERIFICATION verificationCount;
  TPM_FAMILY_FLAGS flags;
} TPM_FAMILY_TABLE_ENTRY;

/*
 * TPM_FAMILY_TABLE ([TPM_Part2], Section 20.7)
 * The family table is stored in a TPM shielded location. There are no
 * confidential values in the family table.
 */
#define TPM_NUM_FAMILY_TABLE_ENTRY 16
typedef struct tdTPM_FAMILY_TABLE {
  TPM_FAMILY_TABLE_ENTRY FamTableRow[TPM_NUM_FAMILY_TABLE_ENTRY];
} TPM_FAMILY_TABLE;

/*
 * TPM_DELEGATE_LABEL ([TPM_Part2], Section 20.8)
 * Used in both the delegate table and the family table to hold a string
 * of bytes that can be displayed or used by applications.
 */
typedef struct tdTPM_DELEGATE_LABEL {
  BYTE label;
} TPM_DELEGATE_LABEL;
#define sizeof_TPM_DELEGATE_LABEL(s) (1)
#define free_TPM_DELEGATE_LABEL(s)

/*
 * TPM_DELEGATE_PUBLIC ([TPM_Part2], Section 20.9)
 * The information of a delegate row that is public and does not have any
 * sensitive information.
 */
#define TPM_TAG_DELEGATE_PUBLIC 0x001B
typedef struct tdTPM_DELEGATE_PUBLIC {
  TPM_STRUCTURE_TAG tag;
  TPM_DELEGATE_LABEL rowLabel;
  TPM_PCR_INFO_SHORT pcrInfo;
  TPM_DELEGATIONS permissions;
  TPM_FAMILY_ID familyID;
  TPM_FAMILY_VERIFICATION verificationCount;
} TPM_DELEGATE_PUBLIC;
#define sizeof_TPM_DELEGATE_PUBLIC(s) (2 + sizeof_TPM_DELEGATE_LABEL(s.rowLabel) \
  + sizeof_TPM_PCR_INFO_SHORT(s.pcrInfo) + sizeof_TPM_DELEGATIONS(s.permissions) \
  + 4 + 4)
#define free_TPM_DELEGATE_PUBLIC(s) { free_TPM_DELEGATE_LABEL(s.rowLabel); \
  free_TPM_DELEGATIONS(s.permissions); }

/*
 * TPM_DELEGATE_TABLE_ROW ([TPM_Part2], Section 20.10)
 * A row of the delegate table.
 */
#define TPM_TAG_DELEGATE_TABLE_ROW 0x001C
typedef struct tdTPM_DELEGATE_TABLE_ROW {
  TPM_STRUCTURE_TAG tag;
  TPM_DELEGATE_PUBLIC pub;
  TPM_SECRET authValue;
} TPM_DELEGATE_TABLE_ROW;

/*
 * TPM_DELEGATE_TABLE ([TPM_Part2], Section 20.11)
 * This is the delegate table. This will be an entry in the
 * TPM_PERSISTENT_DATA structure.
 */
#define TPM_NUM_DELEGATE_TABLE_ENTRY 4
typedef struct tdTPM_DELEGATE_TABLE {
  TPM_DELEGATE_TABLE_ROW delRow[TPM_NUM_DELEGATE_TABLE_ENTRY];
} TPM_DELEGATE_TABLE;

/*
 * TPM_DELEGATE_SENSITIVE ([TPM_Part2], Section 20.12)
 * The TPM_DELEGATE_SENSITIVE structure is the area of a delegate
 * blob that contains sensitive information.
 */
#define TPM_TAG_DELEGATE_SENSITIVE 0x0026
typedef struct tdTPM_DELEGATE_SENSITIVE {
  TPM_STRUCTURE_TAG tag;
  TPM_SECRET authValue;
} TPM_DELEGATE_SENSITIVE;

/*
 * TPM_DELEGATE_OWNER_BLOB ([TPM_Part2], Section 20.13)
 * This data structure contains all the information necessary to
 * externally store a set of owner delegation rights.
 */
#define TPM_TAG_DELEGATE_OWNER_BLOB 0x002A
typedef struct tdTPM_DELEGATE_OWNER_BLOB {
  TPM_STRUCTURE_TAG tag;
  TPM_DELEGATE_PUBLIC pub;
  TPM_DIGEST integrityDigest;
  UINT32 additionalSize;
  BYTE* additionalArea;
  UINT32 sensitiveSize;
  BYTE* sensitiveArea;
} TPM_DELEGATE_OWNER_BLOB;
#define sizeof_TPM_DELEGATE_OWNER_BLOB(s) (2 + sizeof_TPM_DELEGATE_PUBLIC(s.pub) \
  + 20 + 4 + s.additionalSize + 4 + s.sensitiveSize)
#define free_TPM_DELEGATE_OWNER_BLOB(s) { free_TPM_DELEGATE_PUBLIC(s.pub); \
  if (s.additionalSize > 0) tpm_free(s.additionalArea); \
  if (s.sensitiveSize > 0) tpm_free(s.sensitiveArea); }

/*
 * TPM_DELEGATE_KEY_BLOB ([TPM_Part2], Section 20.14)
 * A structure identical to TPM_DELEGATE_OWNER_BLOB but which stores
 * delegation information for user keys.
 */
#define TPM_TAG_DELGATE_KEY_BLOB 0x0027
typedef struct tdTPM_DELEGATE_KEY_BLOB {
  TPM_STRUCTURE_TAG tag;
  TPM_DELEGATE_PUBLIC pub;
  TPM_DIGEST integrityDigest;
  TPM_DIGEST pubKeyDigest;
  UINT32 additionalSize;
  BYTE* additionalArea;
  UINT32 sensitiveSize;
  BYTE* sensitiveArea;
} TPM_DELEGATE_KEY_BLOB;
#define sizeof_TPM_DELEGATE_KEY_BLOB(s) (2 + sizeof_TPM_DELEGATE_PUBLIC(s.pub) \
  + 20 + 20 + 4 + s.additionalSize + 4 + s.sensitiveSize)
#define free_TPM_DELEGATE_KEY_BLOB(s) { free_TPM_DELEGATE_PUBLIC(s.pub); \
  if (s.additionalSize > 0) tpm_free(s.additionalArea); \
  if (s.sensitiveSize > 0) tpm_free(s.sensitiveArea); }

/*
 * TPM_FAMILY_OPERATION Values ([TPM_Part2], Section 20.15)
 * These are the opFlag values used by TPM_Delegate_Manage.
 */
#define TPM_FAMILY_CREATE       0x00000001
#define TPM_FAMILY_ENABLE       0x00000002
#define TPM_FAMILY_ADMIN        0x00000003
#define TPM_FAMILY_INVALIDATE   0x00000004

/*
 * TPM Capability areas ([TPM_Part2], Section 21)
 */
#define TPM_CAP_ORD                     0x00000001
#define TPM_CAP_ALG                     0x00000002
#define TPM_CAP_PID                     0x00000003
#define TPM_CAP_FLAG                    0x00000004
#define TPM_CAP_PROPERTY                0x00000005
#define TPM_CAP_VERSION                 0x00000006
#define TPM_CAP_KEY_HANDLE              0x00000007
#define TPM_CAP_CHECK_LOADED            0x00000008
#define TPM_CAP_BIT_OWNER               0x00000009
#define TPM_CAP_BIT_LOCAL               0x0000000A
#define TPM_CAP_DELEGATIONS             0x0000000B
#define TPM_CAP_KEY_STATUS              0x0000000C
#define TPM_CAP_NV_LIST                 0x0000000D
#define TPM_CAP_TABLE_ADMIN             0x0000000E
#define TPM_CAP_TABLE_ENABLE            0x0000000F
#define TPM_CAP_MFR                     0x00000010
#define TPM_CAP_NV_INDEX                0x00000011
#define TPM_CAP_TRANS_ALG               0x00000012
#define TPM_CAP_GPIO_CHANNEL            0x00000013
#define TPM_CAP_HANDLE                  0x00000014
#define TPM_CAP_TRANS_ES                0x00000015
/* subCap definitions */
#define TPM_CAP_PROP_PCR                0x00000101
#define TPM_CAP_PROP_DIR                0x00000102
#define TPM_CAP_PROP_MANUFACTURER       0x00000103
#define TPM_CAP_PROP_KEYS               0x00000104
#define TPM_CAP_MIN_COUNTER             0x00000107
#define TPM_CAP_FLAG_PERMANENT          0x00000108
#define TPM_CAP_FLAG_STCLEAR            0x00000109
#define TPM_CAP_PROP_AUTHSESS           0x0000010A
#define TPM_CAP_PROP_TRANSESS           0x0000010B
#define TPM_CAP_PROP_COUNTERS           0x0000010C
#define TPM_CAP_PROP_MAX_AUTHSESS       0x0000010D
#define TPM_CAP_PROP_MAX_TRANSESS       0x0000010E
#define TPM_CAP_PROP_MAX_COUNTERS       0x0000010F
#define TPM_CAP_PROP_MAX_KEYS           0x00000110
#define TPM_CAP_PROP_OWNER              0x00000111
#define TPM_CAP_PROP_CONTEXT            0x00000112
#define TPM_CAP_PROP_MAX_CONTEXT        0x00000113
#define TPM_CAP_PROP_FAMILYROWS         0x00000114
#define TPM_CAP_PROP_TIS                0x00000115
#define TPM_CAP_PROP_STARTUP_EFFECT     0x00000116
#define TPM_CAP_PROP_DELEGATE_ENTRIES   0x00000117
#define TPM_CAP_PROP_NV_MAXBUF          0x00000118
#define TPM_CAP_PROP_DAA_MAX            0x00000119
#define TPM_CAP_PROP_SESSION_DAA        0x0000011A // WATCH: conflict (v1.2 rev 85)
#define TPM_CAP_PROP_GLOBALLOCK         0x0001011A // FIXME
#define TPM_CAP_PROP_CONTEXT_DIST       0x0000011B
#define TPM_CAP_PROP_DAA_INTERRUPT      0x0000011C
#define TPM_CAP_PROP_SESSIONS           0x0000011D // WATCH: conflict (v1.2 rev 85)
#define TPM_CAP_FLAG_STANY              0x0001011D // FIXME
#define TPM_CAP_PROP_MAX_SESSIONS       0x0000011E // WATCH: conflict (v1.2 rev 85)
#define TPM_CAP_PROP_GPIO_CHANNEL       0x0001011E // FIXME
#define TPM_CAP_PROP_CMK_RESTRICTION    0x0000011F
#define TPM_CAP_PROP_DURATION           0x00000120
#define TPM_CAP_PROP_ACTIVE_COUNTER     0x00000122 // WATCH: 122 (v1.2 rev 85)
#define TPM_CAP_PROP_MAX_NV_AVAILABLE   0x00000123
#define TPM_CAP_PROP_INPUT_BUFFER       0x00000124

/*
 * DAA Structures
 */

/*
 * Size and constant definitions ([TPM_Part2], Section 22.1 and 22.2)
 */
#define DAA_SIZE_r0             43
#define DAA_SIZE_r1             43
#define DAA_SIZE_r2             128
#define DAA_SIZE_r3             168
#define DAA_SIZE_r4             219
#define DAA_SIZE_NT             20
#define DAA_SIZE_v0             128
#define DAA_SIZE_v1             192
#define DAA_SIZE_NE             256
#define DAA_SIZE_w              256
#define DAA_SIZE_issuerModulus  256

#define DAA_power0              104
#define DAA_power1              1024

/*
 * TPM_DAA_ISSUER ([TPM_Part2], Section 22.7)
 * This structure is the abstract representation of non-secret
 * settings controlling a DAA context.
 */
#define TPM_TAG_DAA_ISSUER 0x002F
typedef struct tdTPM_DAA_ISSUER {
  TPM_STRUCTURE_TAG tag;
  TPM_DIGEST DAA_digest_R0;
  TPM_DIGEST DAA_digest_R1;
  TPM_DIGEST DAA_digest_S0;
  TPM_DIGEST DAA_digest_S1;
  TPM_DIGEST DAA_digest_n;
  TPM_DIGEST DAA_digest_gamma;
  BYTE DAA_generic_q[26];
} TPM_DAA_ISSUER;

/*
 * TPM_DAA_TPM ([TPM_Part2], Section 22.8)
 * This structure is the abstract representation of TPM specific
 * parameters used during a DAA context.
 */
#define TPM_TAG_DAA_TPM 0x0032
typedef struct tdTPM_DAA_TPM {
  TPM_STRUCTURE_TAG tag;
  TPM_DIGEST DAA_digestIssuer;
  TPM_DIGEST DAA_digest_v0;
  TPM_DIGEST DAA_digest_v1;
  TPM_DIGEST DAA_rekey;
  UINT32 DAA_count;
} TPM_DAA_TPM;

/*
 * TPM_DAA_CONTEXT ([TPM_Part2], Section 22.9)
 * This structure is created and used inside a TPM, and never leaves it.
 */
#define TPM_TAG_DAA_CONTEXT 0x002D
typedef struct tdTPM_DAA_CONTEXT {
  TPM_STRUCTURE_TAG tag;
  TPM_DIGEST DAA_digestContext;
  TPM_DIGEST DAA_digest;
  TPM_DAA_CONTEXT_SEED DAA_contextSeed;
  BYTE DAA_scratch[256];
  BYTE DAA_stage;
} TPM_DAA_CONTEXT;

/*
 * TPM_DAA_JOINDATA ([TPM_Part2], Section 22.10)
 * This structure is the abstract representation of data that
 * exists only during a specific JOIN session.
 */
typedef struct tdTPM_DAA_JOINDATA {
  BYTE DAA_join_u0[128];
  BYTE DAA_join_u1[138]; /* WATCH: 138 (v1.2 rev 85) */
  TPM_DIGEST DAA_digest_n0;
} TPM_DAA_JOINDATA;

/*
 * TPM_DAA_BLOB ([TPM_Part2], Section 22.12)
 * The structure passed during the join process.
 */
#define TPM_TAG_DAA_BLOB 0x002C
typedef struct tdTPM_DAA_BLOB {
  TPM_STRUCTURE_TAG tag;
  TPM_RESOURCE_TYPE resourceType;
  BYTE label[16];
  TPM_DIGEST blobIntegrity;
  UINT32 additionalSize;
  BYTE* additionalData;
  UINT32 sensitiveSize;
  BYTE* sensitiveData;
} TPM_DAA_BLOB;
#define sizeof_TPM_DAA_BLOB(s) (sizeof(TPM_STRUCTURE_TAG) + \
  sizeof(TPM_RESOURCE_TYPE) + sizeof(s.label) + sizeof(TPM_DIGEST) + \
  2*sizeof(UINT32) + s.additionalSize + s.sensitiveSize)

/*
 * TPM_DAA_SENSITIVE ([TPM_Part2], Section 22.13)
 * The encrypted area for the DAA parameters.
 */
#define TPM_TAG_DAA_SENSITIVE 0x0031
typedef struct tdTPM_DAA_SENSITIVE {
  TPM_STRUCTURE_TAG tag;
  UINT32 internalSize;
  BYTE* internalData;
} TPM_DAA_SENSITIVE;
#define sizeof_TPM_DAA_SENSITIVE(s) (sizeof(TPM_STRUCTURE_TAG) + \
  sizeof(UINT32) + s.internalSize)

/*
 * GPIO structures
 */

 /*
  * TPM_GPIO_BUS ([TPM_Part2], Section 23.1)
  * The type(s) of data transfer channels that are supported by a TPM.
  */
typedef UINT32 TPM_GPIO_BUS;
#define TPM_GPIO_SINGLE         0x00000001
#define TPM_GPIO_SMBUS          0x00000002
#define TPM_GPIO_SMBUS_ARP      0x00000003

 /*
  * TPM_GPIO_ATTRIBUTES ([TPM_Part2], Section 23.2)
  * The attribute flags for the channel.
  */
/* 31-6 reserved and must be 0 */
#define TPM_GPIO_ATTR_REDIR_KEY (1 << 5)
#define TPM_GPIO_ATTR_REDIR     (1 << 4)
#define TPM_GPIO_ATTR_WRITE     (1 << 3)
#define TPM_GPIO_ATTR_READ      (1 << 2)
#define TPM_GPIO_ATTR_PP        (1 << 1)
#define TPM_GPIO_ATTR_AUTH      (1 << 0)

/*
 * TPM_GPIO_CHANNEL ([TPM_Part2], Section 23.3)
 * Information about the types of IO permitted on the channel identified
 * by the TPM-assigned logical channel number.
 */
#define TPM_TAG_GPIO_CHANNEL 0x0035
typedef struct tdTPM_GPIO_CHANNEL {
  TPM_STRUCTURE_TAG tag;
  TPM_PLATFORM_SPECIFIC ps;
  UINT16 channelNumber;
  TPM_GPIO_ATTRIBUTES attr;
  TPM_GPIO_BUS busInfo;
  UINT32 sizeOfAddress;
  BYTE* address;
  UINT32 sizeOfPubKey;
  TPM_DIGEST pubKey;
  UINT32 sizeOfPcrInfo;
  TPM_PCR_INFO_SHORT pcrInfo;
} TPM_GPIO_CHANNEL;
#define sizeof_TPM_GPIO_CHANNEL(s) (2 + 2 + 2 + 4 + 4 + 4 + s.sizeOfAddress \
  + 4 + 20 + 4 + sizeof_TPM_PCR_INFO_SHORT(s.pcrInfo))
#define free_TPM_GPIO_CHANNEL(s) { if (s.sizeOfAddress > 0) tpm_free(s.address); }

/*
 * TPM_GPIO_AUTHORIZE ([TPM_Part2], Section 23.4)
 * The owner uses TPM_GPIO_AuthChannel command to build structures of this
 * type to authorize later use of the specified IO channel.
 */
#define TPM_TAG_GPIO_AUTHORIZE 0x0033
typedef struct tdTPM_GPIO_AUTHORIZE {
  TPM_STRUCTURE_TAG tag;
  TPM_GPIO_CHANNEL channel;
  TPM_DIGEST blobIntegrity;
  UINT32 additionalSize;
  BYTE* additionalData;
  UINT32 sensitiveSize;
  BYTE* sensitiveData;
} TPM_GPIO_AUTHORIZE;
#define sizeof_TPM_GPIO_AUTHORIZE(s) (2 + sizeof_TPM_GPIO_CHANNEL(s.channel) \
  + 20 + 4 + s.additionalSize + 4 + s.sensitiveSize)
#define free_TPM_GPIO_AUTHORIZE(s) { free_TPM_GPIO_CHANNEL(s.channel); \
  if (s.additionalSize > 0) tpm_free(s.additionalData); \
  if (s.sensitiveSize > 0) tpm_free(s.sensitiveData); }

/*
 * TPM_GPIO_SENSITIVE  ([TPM_Part2], Section 23.5)
 * Secret information necessary to verify the authorization of the IO channel
 * which is encrypted before inclusion in the TPM_GPIO_CHANNEL structure.
 */
#define TPM_TAG_GPIO_SENSITIVE 0x0034
typedef struct tdTPM_GPIO_SENSITIVE {
  TPM_STRUCTURE_TAG tag;
  TPM_DIGEST authData;
} TPM_GPIO_SENSITIVE;

/*
 * Redirection
 */

 /*
  * TPM_REDIR_COMMAND ([TPM_Part2], Section 24.1)
  * The types of redirections.
  */
typedef UINT32 TPM_REDIR_COMMAND;
#define TPM_REDIR_GPIO 0x00000001

/*
 * Internal Data Held By TPM
 */

/*
 * TPM_PERMANENT_FLAGS ([TPM_Part2], Section 7.1)
 * These flags maintain state information for the TPM. The values are not
 * affected by any TPM_Startup command.
 */
#define TPM_TAG_PERMANENT_FLAGS 0x001F
typedef struct tdTPM_PERMANENT_FLAGS {
  TPM_STRUCTURE_TAG tag;
  BOOL disable;
  BOOL ownership;
  BOOL deactivated;
  BOOL readPubek;
  BOOL disableOwnerClear;
  BOOL allowMaintenance;
  BOOL physicalPresenceLifetimeLock;
  BOOL physicalPresenceHWEnable;
  BOOL physicalPresenceCMDEnable;
  BOOL CEKPUsed;
  BOOL TPMpost;
  BOOL TPMpostLock;
  BOOL FIPS;
  BOOL operator;
  BOOL enableRevokeEK;
  /* additional, not marshalled flags */
  BOOL selfTestSucceeded;
  BOOL owned;
} TPM_PERMANENT_FLAGS;
#define sizeof_TPM_PERMANENT_FLAGS(s) (2 + 15)

/*
 * TPM_STCLEAR_FLAGS ([TPM_Part2], Section 7.2)
 * These flags maintain state that is reset on each TPM_Startup(ST_Clear)
 * command. The values are not affected by TPM_Startup(ST_State) commands.
 */
#define TPM_TAG_STCLEAR_FLAGS 0x0020
#define TPM_MAX_FAMILY 8
typedef struct tdTPM_STCLEAR_FLAGS {
  TPM_STRUCTURE_TAG tag;
  BOOL deactivated;
  BOOL disableForceClear;
  BOOL physicalPresence;
  BOOL physicalPresenceLock;
  BOOL tableAdmin[TPM_MAX_FAMILY];
  BOOL bGlobalLock;
} TPM_STCLEAR_FLAGS;
#define sizeof_TPM_STCLEAR_FLAGS(s) (2 + 5 + TPM_MAX_FAMILY)

/*
 * TPM_STANY_FLAGS ([TPM_Part2], Section 7.3)
 * These flags reset on any TPM_Startup command.
 */
#define TPM_TAG_STANY_FLAGS 0x0021
typedef struct tdTPM_STANY_FLAGS {
  TPM_STRUCTURE_TAG tag;
  BOOL postInitialise;
  TPM_MODIFIER_INDICATOR localityModifier;
  BOOL transportExclusive;
} TPM_STANY_FLAGS;
#define sizeof_TPM_STANY_FLAGS(s) (2 + 1 + 4 + 1)

/*
 * TPM_KEY_DATA
 * This structure contains the data for stored RSA keys.
 */
typedef struct tdTPM_KEY_DATA {
  BOOL valid;
  TPM_KEY_USAGE keyUsage;
  TPM_KEY_FLAGS keyFlags;
  TPM_KEY_CONTROL keyControl;
  TPM_AUTH_DATA_USAGE authDataUsage;
  TPM_ENC_SCHEME encScheme;
  TPM_SIG_SCHEME sigScheme;
  TPM_SECRET usageAuth;
  TPM_PCR_INFO pcrInfo;
  BOOL parentPCRStatus;
  rsa_private_key_t key;
} TPM_KEY_DATA;
#define sizeof_RSA(s) (6 + 2*(s.size >> 3) + (s.size >> 4))
#define sizeof_TPM_KEY_DATA(s) (1 + 2 + 4 + 4 + 1 + 2 + 2 + 20 \
  + sizeof_TPM_PCR_INFO(s.pcrInfo) + 1 + sizeof_RSA(s.key))

/*
 * TPM_PERMANENT_DATA ([TPM_Part2], Section 7.4)
 * This structure contains the data fields that are permanently held in
 * the TPM and not affected by TPM_Startup(any).
 */
#define TPM_TAG_PERMANENT_DATA          0x0022
#define TPM_MAX_COUNTERS                4
#define TPM_DELEGATE_KEY                TPM_KEY
#define TPM_MAX_NV_WRITE_NOOWNER        64
#define TPM_MAX_KEYS                    10
#define TPM_CONTEXT_KEY_SIZE            32
typedef struct tdTPM_PERMANENT_DATA {
  TPM_STRUCTURE_TAG tag;
  TPM_VERSION version;
  TPM_NONCE tpmProof;
  //TPM_NONCE fipsReset;
  TPM_SECRET ownerAuth;
  TPM_SECRET operatorAuth;
  //TPM_SECRET adminAuth;
  //TPM_PUBKEY manuMaintPub;
  TPM_NONCE ekReset;
  rsa_private_key_t endorsementKey;
  TPM_KEY_DATA srk;
  BYTE contextKey[TPM_CONTEXT_KEY_SIZE];
  //TPM_KEY delegateKey;
  TPM_ACTUAL_COUNT auditMonotonicCounter;
  TPM_COUNTER_VALUE counters[TPM_MAX_COUNTERS];
  TPM_TICKTYPE tickType;
  TPM_PCR_ATTRIBUTES pcrAttrib[TPM_NUM_PCR];
  TPM_PCRVALUE pcrValue[TPM_NUM_PCR];
  BYTE ordinalAuditStatus[TPM_ORD_MAX / 8];
  //BYTE* rngState;
  //TPM_FAMILY_TABLE familyTable;
  //TPM_DELEGATE_TABLE delegateTable;
  //UINT32 maxNVBufSize;
  //UINT32 lastFamilyID;
  UINT32 noOwnerNVWrite;
  TPM_DIRVALUE DIR;
  TPM_NV_DATA_SENSITIVE *nvStorage;
  //TPM_CMK_RESTRICTDELEGATE restrictDelegate;
  TPM_DAA_TPM_SEED tpmDAASeed;
  TPM_KEY_DATA keys[TPM_MAX_KEYS];
  const char *testResult;
} TPM_PERMANENT_DATA;
#define sizeof_TPM_PERMANENT_DATA(s) (2 + 4 + 4*20 \
  + sizeof_RSA(s.endorsementKey) + TPM_ORD_MAX/8 \
  + (1+TPM_MAX_KEYS)*sizeof_TPM_KEY_DATA(s.srk) \
  + TPM_NUM_PCR*(sizeof_TPM_PCR_ATTRIBUTES(x)+20) \
  + TPM_MAX_COUNTERS*sizeof_TPM_COUNTER_VALUE2(x) + 1 + 4 + 20)

/*
 * TPM_STCLEAR_DATA ([TPM_Part2], Section 7.5)
 * Most of the data in this structure resets on TPM_Startup(ST_Clear).
 */
#define TPM_TAG_STCLEAR_DATA 0x0023
typedef struct tdTPM_STCLEAR_DATA {
  TPM_STRUCTURE_TAG tag;
  TPM_NONCE contextNonceKey;
  TPM_COUNT_ID countID;
  //UINT32 ownerReference;
} TPM_STCLEAR_DATA;

/*
 * TPM_SESSION_DATA
 * This structure contains the data for authorization and transport sessions.
 */
#define TPM_ST_INVALID    0
#define TPM_ST_OIAP       1
#define TPM_ST_OSAP       2
#define TPM_ST_TRANSPORT  4
typedef struct tdTPM_SESSION_DATA {
  BYTE type;
  TPM_NONCE nonceEven;
  TPM_NONCE lastNonceEven;
  TPM_SECRET sharedSecret;
  TPM_HANDLE handle;
  TPM_ENTITY_TYPE entityType;
  TPM_TRANSPORT_INTERNAL transInternal;
} TPM_SESSION_DATA;
#define sizeof_TPM_SESSION_DATA(s) (1 + 3*20 + 4 + 2 \
  + ((s.type == TPM_ST_TRANSPORT) ? \
     sizeof_TPM_TRANSPORT_INTERNAL(s.transInternal) : 0))

/*
 * TPM_DAA_SESSION_DATA
 * This structure contains the data for DAA sessions.
 */
#define TPM_ST_DAA        8
typedef UINT32 TPM_DAAHANDLE;
typedef struct tdTPM_DAA_SESSION_DATA {
  BYTE type;
  TPM_DAA_ISSUER DAA_issuerSettings;
  TPM_DAA_TPM DAA_tpmSpecific;
  TPM_DAA_CONTEXT DAA_session;
  TPM_DAA_JOINDATA DAA_joinSession;
  TPM_HANDLE handle;
} TPM_DAA_SESSION_DATA;

/*
 * TPM_STANY_DATA ([TPM_Part2], Section 7.6)
 * Most of the data in this structure resets on TPM_Startup(ST_State).
 */
#define TPM_TAG_STANY_DATA        0x0024
#define TPM_MAX_SESSIONS          3
#define TPM_MAX_SESSION_LIST      16
#define TPM_MAX_SESSIONS_DAA      1
typedef struct tdTPM_STANY_DATA {
  TPM_STRUCTURE_TAG tag;
  TPM_NONCE contextNonceSession;
  TPM_DIGEST auditDigest;
  BOOL auditSession;
  TPM_CURRENT_TICKS currentTicks;
  UINT32 contextCount;
  UINT32 contextList[TPM_MAX_SESSION_LIST];
  TPM_SESSION_DATA sessions[TPM_MAX_SESSIONS];
  /*
   * TPM_STANY_DATA ([TPM_Part2], Section 22.11)
   * This shows that the volatile data areas are added to the
   * TPM_STANY_DATA structure.
   */
  TPM_DAA_SESSION_DATA sessionsDAA[TPM_MAX_SESSIONS_DAA];
  TPM_TRANSHANDLE transExclusive;
} TPM_STANY_DATA;

/*
 * TPM_DATA
 * Internal data of the TPM
 */
typedef struct tdTPM_DATA {
  struct {
    TPM_PERMANENT_FLAGS flags;
    TPM_PERMANENT_DATA data;
  } permanent;
  struct {
    TPM_STCLEAR_FLAGS flags;
    TPM_STCLEAR_DATA data;
  } stclear;
  struct {
    TPM_STANY_FLAGS flags;
    TPM_STANY_DATA data;
  } stany;
} TPM_DATA;

/*
 * Context Structures
 */

/*
 * TPM_CONTEXT_BLOB ([TPM_Part2], Section 18.1)
 * This is the header for the wrapped context. The blob contains all
 * information necessary to reload the context back into the TPM.
 */
#define TPM_TAG_CONTEXTBLOB 0x0001
typedef struct tdTPM_CONTEXT_BLOB {
  TPM_STRUCTURE_TAG tag;
  TPM_RESOURCE_TYPE resourceType;
  TPM_HANDLE handle;
  BYTE label[16];
  UINT32 contextCount;
  TPM_DIGEST blobIntegrity;
  UINT32 additionalSize;
  BYTE* additionalData;
  UINT32 sensitiveSize;
  BYTE* sensitiveData;
} TPM_CONTEXT_BLOB;
#define sizeof_TPM_CONTEXT_BLOB(s) (2 + 4 + 4 + 16 + 4 + 20 + 4 \
 + s.additionalSize + 4 + s.sensitiveSize)
#define free_TPM_CONTEXT_BLOB(s) { \
  if (s.additionalSize > 0) tpm_free(s.additionalData); \
  if (s.sensitiveSize > 0) tpm_free(s.sensitiveData); }

/*
 * TPM_CONTEXT_SENSITIVE ([TPM_Part2], Section 18.2)
 * The internal areas that the TPM needs to encrypt and store off the TPM.
 */
#define TPM_TAG_CONTEXT_SENSITIVE 0x0002
typedef struct tdTPM_CONTEXT_SENSITIVE {
  TPM_STRUCTURE_TAG tag;
  TPM_NONCE contextNonce;
  UINT32 internalSize;
  TPM_RESOURCE_TYPE resourceType;
  union {
    TPM_KEY_DATA key;
    TPM_SESSION_DATA session;
    TPM_DAA_SESSION_DATA sessionDAA;
  } internalData;
} TPM_CONTEXT_SENSITIVE;
#define sizeof_TPM_CONTEXT_SENSITIVE(s) (2 + 20 + 4 + s.internalSize)

/*
 * TPM communication packets
 */

/*
 * TPM_REQUEST 
 * TPM command request
 */
typedef struct tdTPM_REQUEST {
  TPM_TAG tag;
  UINT32 size;
  TPM_COMMAND_CODE ordinal;
  BYTE *param;
  UINT32 paramSize;
  TPM_AUTH auth1;
  TPM_AUTH auth2;
} TPM_REQUEST;

/*
 * TPM_RESPONSE
 * TPM command response
 */
typedef struct tdTPM_RESPONSE {
  TPM_TAG tag;
  UINT32 size;
  TPM_RESULT result;
  BYTE *param;
  UINT32 paramSize;
  TPM_AUTH *auth1;
  TPM_AUTH *auth2;
} TPM_RESPONSE;

#endif /* _TPM_STRUCTURES_H_ */
