/* Software-Based Trusted Platform Module (TPM) Emulator for Linux
 * Copyright (C) 2004 Mario Strasser <mast@gmx.net>,
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

#ifndef _RSA_H_
#define _RSA_H_

#include "linux_module.h"
#include "gmp.h"

typedef struct {
  mpz_t n;
  mpz_t e;
  mpz_t d;
  mpz_t p;
  mpz_t q;
  mpz_t u;
  int size;
} rsa_private_key_t;

typedef struct {
  mpz_t n;
  mpz_t e;
  int size;
} rsa_public_key_t;

enum { 
  RSA_ES_PKCSV15, 
  RSA_ES_OAEP_SHA1, 
  RSA_SSA_PKCS1_SHA1, 
  RSA_SSA_PKCS1_SHA1_RAW,
  RSA_SSA_PKCS1_DER
};

enum {
  RSA_LSB_FIRST = -1, RSA_MSB_FIRST = 1
};

#define RSA_EXTRACT_PUBLIC_KEY(priv_key, pub_key) { \
  mpz_init_set(pub_key.n, priv_key.n); \
  mpz_init_set(pub_key.e, priv_key.e); \
  pub_key.size = priv_key.size; }

int rsa_import_key(rsa_private_key_t *key, int endian, 
                   uint8_t *n, size_t n_len, uint8_t *e, size_t e_len, 
                   uint8_t *p, uint8_t *q);

void rsa_copy_key(rsa_private_key_t *dst, rsa_private_key_t *src);

int rsa_import_public_key(rsa_public_key_t *key, int endian, 
                          uint8_t *n, size_t n_len, uint8_t *e, size_t e_len);

int rsa_generate_key(rsa_private_key_t *key, int key_size);

void rsa_release_private_key(rsa_private_key_t *key);

void rsa_release_public_key(rsa_public_key_t *key);

void rsa_export_modulus(rsa_private_key_t *key, 
                        uint8_t *modulus, size_t *length);

void rsa_export_exponent(rsa_private_key_t *key, 
                         uint8_t *exponent, size_t *length);

void rsa_export_prime1(rsa_private_key_t *key, 
                       uint8_t *prime, size_t *length);

void rsa_export_prime2(rsa_private_key_t *key, 
                       uint8_t *prime, size_t *length);

/* Note: Input and output areas MUST NOT overlap (i.e., one can't 
   use the same buffer for data and sig or in and out). */

int rsa_sign(rsa_private_key_t *key, int type,
             uint8_t *data, size_t data_len, uint8_t *sig);

int rsa_verify(rsa_public_key_t *key, int type,
               uint8_t *data, size_t data_len, uint8_t *sig);

int rsa_decrypt(rsa_private_key_t *key, int type,
                uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

int rsa_encrypt(rsa_public_key_t *key, int type,
                uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

#endif /* _RSA_H_ */

