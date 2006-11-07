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

#include "rsa.h"
#include "sha1.h"

static int rsa_public(rsa_public_key_t *key, 
                      const uint8_t *in, size_t in_len, uint8_t *out)
{
  size_t t;
  mpz_t p, c;

  mpz_init2(p, key->size + GMP_NUMB_BITS);
  mpz_init2(c, key->size + GMP_NUMB_BITS);
  mpz_import(p, in_len, 1, 1, 0, 0, in);
  /* c = p ^ d mod n */
  mpz_powm(c, p, key->e, key->n);
  t = mpz_sizeinbase(c, 2);
  if (t > key->size) {
    mpz_clear(p);
    mpz_clear(c);
    return -1;
  }
  t = (key->size - t) >> 3;
  memset(out, 0, t);
  mpz_export(&out[t], &t, 1, 1, 0, 0, c);
  mpz_clear(p);
  mpz_clear(c);
  return 0;
}

static int rsa_private(rsa_private_key_t *key,
                       const uint8_t *in, size_t in_len, uint8_t *out)
{
  size_t t;
  mpz_t p, c, m1, m2, h;

  mpz_init2(p, key->size + GMP_NUMB_BITS);
  mpz_init2(c, key->size + GMP_NUMB_BITS);
  mpz_import(p, in_len, 1, 1, 0, 0, in);

  if (!key->p || !key->q || !key->u) {
    /* c = p ^ d mod n */
    mpz_powm(c, p, key->d, key->n);
  } else {
    mpz_init2(m1, key->size / 2);
    mpz_init2(m2, key->size / 2);
    mpz_init2(h, key->size / 2 + GMP_NUMB_BITS);
    /* m1 = p ^ (d mod (p-1)) mod p */
    mpz_sub_ui(h, key->p, 1);
    mpz_mod(h, key->d, h);
    mpz_powm(m1, p, h, key->p);
    /* m2 = p ^ (d mod (q-1)) mod q */
    mpz_sub_ui(h, key->q, 1);
    mpz_mod(h, key->d, h);
    mpz_powm(m2, p, h, key->q);
    /* h = u * ( m2 - m1 ) mod q */
    mpz_sub(h, m2, m1);
    if (mpz_sgn(h) < 0) mpz_add(h, h, key->q);
    mpz_mul(h, key->u, h);
    mpz_mod(h, h, key->q);
    /* c = m1 + h * p */
    mpz_mul(h, h, key->p);
    mpz_add(c, m1, h);
    mpz_clear(m1);
    mpz_clear(m2);
  }
  t = mpz_sizeinbase(c, 2);
  if (t > key->size) {
    mpz_clear(p);
    mpz_clear(c);
    return -1;
  }
  t = (key->size - t) >> 3;
  memset(out, 0, t);
  mpz_export(&out[t], &t, 1, 1, 0, 0, c);
  mpz_clear(p);
  mpz_clear(c);
  return 0;
}

static int rsa_test_key(rsa_private_key_t *key)
{
  mpz_t a, b, t;
  int res = 0;
  
  mpz_init2(a, key->size + GMP_NUMB_BITS);
  mpz_init2(b, key->size + GMP_NUMB_BITS);
  mpz_init2(t, key->size + GMP_NUMB_BITS);
  mpz_set_ui(t, 0xdeadbeef);
  mpz_powm(a, t, key->e, key->n);
  mpz_powm(b, a, key->d, key->n);
  if (mpz_cmp(t, b) != 0) res = -1;
  mpz_powm(a, t, key->d, key->n);
  mpz_powm(b, a, key->e, key->n);
  if (mpz_cmp(t, b) != 0) res = -1;
  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(t);
  return res;
}

int rsa_import_key(rsa_private_key_t *key, int endian,
                   const uint8_t *n, size_t n_len,
                   const uint8_t *e, size_t e_len,
                   const uint8_t *p, const uint8_t *q)
{
  mpz_t t1, t2, phi;
  if (n == NULL || n_len == 0 || (p == NULL && q == NULL)) return -1;
  /* init key */
  key->size = n_len << 3;
  if (e == NULL || e_len == 0) {
    mpz_init_set_ui(key->e, 65537);
  } else {
    mpz_init2(key->e, (e_len << 3) + GMP_NUMB_BITS);
    mpz_import(key->e, e_len, endian, 1, 0, 0, e);
  }
  mpz_init2(key->n, key->size + GMP_NUMB_BITS);
  mpz_init2(key->p, key->size / 2 + GMP_NUMB_BITS);
  mpz_init2(key->q, key->size / 2 + GMP_NUMB_BITS);
  mpz_init2(key->d, key->size + GMP_NUMB_BITS);
  mpz_init2(key->u, key->size / 2 + GMP_NUMB_BITS); 
  mpz_init2(t1, key->size / 2 + GMP_NUMB_BITS);
  mpz_init2(t2, key->size / 2 + GMP_NUMB_BITS);
  mpz_init2(phi, key->size + GMP_NUMB_BITS);
  /* import values */
  mpz_import(key->n, n_len, endian, 1, 0, 0, n);
  if (p != NULL) mpz_import(key->p, n_len / 2, endian, 1, 0, 0, p);
  if (q != NULL) mpz_import(key->q, n_len / 2, endian, 1, 0, 0, q);
  if (p == NULL) mpz_tdiv_q(key->p, key->n, key->q);
  if (q == NULL) mpz_tdiv_q(key->q, key->n, key->p);
  /* p shall be smaller than q */
  if (mpz_cmp(key->p, key->q) > 0) mpz_swap(key->p, key->q);
  /* calculate missing values */
  mpz_sub_ui(t1, key->p, 1);
  mpz_sub_ui(t2, key->q, 1);
  mpz_mul(phi, t1, t2);
  mpz_invert(key->d, key->e, phi);
  mpz_invert(key->u, key->p, key->q);
  /* release helper variables */
  mpz_clear(t1);
  mpz_clear(t2);
  mpz_clear(phi);
  /* test key */
  if (rsa_test_key(key) != 0) {
    rsa_release_private_key(key);
    return -1;
  }
  return 0;
}

void rsa_copy_key(rsa_private_key_t *dst, rsa_private_key_t *src)
{
  mpz_init_set(dst->n, src->n);
  mpz_init_set(dst->e, src->n);
  mpz_init_set(dst->d, src->n);
  mpz_init_set(dst->p, src->n);
  mpz_init_set(dst->q, src->n);
  mpz_init_set(dst->u, src->n);
  dst->size = src->size;
}

int rsa_import_public_key(rsa_public_key_t *key, int endian,
                          const uint8_t *n, size_t n_len,
                          const uint8_t *e, size_t e_len)
{
  if (n == NULL || n_len == 0) return -1;
  /* init key */
  key->size = n_len << 3;
  if (e == NULL || e_len == 0) {
    mpz_init_set_ui(key->e, 65537);
  } else {
    mpz_init2(key->e, (e_len << 3) + GMP_NUMB_BITS);
    mpz_import(key->e, e_len, endian, 1, 0, 0, e);
  }
  mpz_init2(key->n, key->size + GMP_NUMB_BITS);
  /* import values */
  mpz_import(key->n, n_len, endian, 1, 0, 0, n);
  return 0;
}

static void rsa_mpz_random(mpz_t a, size_t nbits)
{
  size_t size = nbits >> 3;
  char buf[size];
  tpm_get_random_bytes(buf, size);
  mpz_import(a, size, 1, 1, 0, 0, buf);
}

int rsa_generate_key(rsa_private_key_t *key, uint16_t key_size)
{
  mpz_t e, p, q, n, t1, t2, phi, d, u;

  /* bit_size must be a multiply of eight */
  while (key_size & 0x03) key_size++;
  /* we use e = 65537 */
  mpz_init_set_ui(e, 65537);
  mpz_init2(p, key_size / 2 + GMP_NUMB_BITS);
  mpz_init2(q, key_size / 2 + GMP_NUMB_BITS);
  mpz_init2(n, key_size + GMP_NUMB_BITS);
  mpz_init2(t1, key_size / 2 + GMP_NUMB_BITS);
  mpz_init2(t2, key_size / 2 + GMP_NUMB_BITS);
  mpz_init2(phi, key_size + GMP_NUMB_BITS);
  mpz_init2(d, key_size + GMP_NUMB_BITS);
  mpz_init2(u, key_size / 2 + GMP_NUMB_BITS);
  do {  
    /* get prime p */
    rsa_mpz_random(p, key_size / 2);
    mpz_setbit(p, 0); 
    mpz_setbit(p, key_size / 2 - 1);
    mpz_setbit(p, key_size / 2 - 2);
    mpz_nextprime(p, p);
    mpz_sub_ui(t1, p, 1);
    mpz_gcd(phi, e, t1);
    if (mpz_cmp_ui(phi, 1) != 0) continue;
    /* get prime q */
    rsa_mpz_random(q, key_size / 2);
    mpz_setbit(q, 0);
    mpz_setbit(q, key_size / 2 - 1);
    mpz_setbit(q, key_size / 2 - 2);
    mpz_nextprime(q, q);
    mpz_sub_ui(t2, q, 1); 
    mpz_gcd(phi, e, t1);
    if (mpz_cmp_ui(phi, 1) != 0) continue;
    /* p shall be smaller than q */
    if (mpz_cmp(p, q) > 0) mpz_swap(p, q);
    /* calculate the modulus */
    mpz_mul(n, p, q);
  } while (mpz_sizeinbase(n, 2) != key_size);
  /* calculate Euler totient: phi = (p-1)(q-1) */
  mpz_mul(phi, t1, t2);
  /* calculate the secret key d = e^(-1) mod phi */
  mpz_invert(d, e, phi);
  /* calculate the inverse of p and q (used for chinese remainder theorem) */
  mpz_invert(u, p, q);
  /* setup private key */
  mpz_init_set(key->n, n);
  mpz_init_set(key->e, e);
  mpz_init_set(key->p, p);
  mpz_init_set(key->q, q);
  mpz_init_set(key->d, d);
  mpz_init_set(key->u, u);  
  key->size = key_size;
  /* release helper variables */
  mpz_clear(e);
  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(n);
  mpz_clear(t1);
  mpz_clear(t2);
  mpz_clear(phi);
  mpz_clear(d);
  mpz_clear(u);
  /* test key */
  if (rsa_test_key(key) != 0) {
    rsa_release_private_key(key);
    return -1;
  }
  return 0;
}

void rsa_release_private_key(rsa_private_key_t *key)
{
  mpz_clear(key->n);
  mpz_clear(key->e);
  mpz_clear(key->p);
  mpz_clear(key->q);
  mpz_clear(key->d);
  mpz_clear(key->u);
  memset(key, 0, sizeof(*key));
}

void rsa_release_public_key(rsa_public_key_t *key)
{
  mpz_clear(key->n);
  mpz_clear(key->e);
  memset(key, 0, sizeof(*key));
}

void rsa_export_modulus(rsa_private_key_t *key, 
                        uint8_t *modulus, size_t *length)
{
  mpz_export(modulus, length, 1 , 1, 0, 0, key->n);
}

void rsa_export_exponent(rsa_private_key_t *key, 
                         uint8_t *exponent, size_t *length)
{
  mpz_export(exponent, length, 1 , 1, 0, 0, key->e);
}

void rsa_export_prime1(rsa_private_key_t *key, 
                       uint8_t *prime, size_t *length)
{
  mpz_export(prime, length, 1 , 1, 0, 0, key->p);
}

void rsa_export_prime2(rsa_private_key_t *key, 
                       uint8_t *prime, size_t *length)
{
  mpz_export(prime, length, 1 , 1, 0, 0, key->q);
}

void mask_generation(const uint8_t *seed, size_t seed_len, 
                     uint8_t *data, size_t data_len)
{
  sha1_ctx_t ctx;
  uint8_t mask[SHA1_DIGEST_LENGTH];
  uint32_t i, len, counter = 0;
  
  while (data_len > 0) {
    sha1_init(&ctx);
    sha1_update(&ctx, seed, seed_len);
    sha1_update(&ctx, (uint8_t*)&counter, 4);
    sha1_final(&ctx, mask);
    counter = CPU_TO_BE32(BE32_TO_CPU(counter) + 1);
    len = (data_len < SHA1_DIGEST_LENGTH) ? data_len : SHA1_DIGEST_LENGTH;
    for (i = 0; i < len; i++) *data++ ^= mask[i];
    data_len -= len; 
  }
}

static int encode_message(int type, const uint8_t *data, size_t data_len, 
                          uint8_t *msg, size_t msg_len)
{
  size_t i;
  sha1_ctx_t ctx;

  /* encode message according to type */
  switch (type) {
    case RSA_SSA_PKCS1_SHA1:
      /* EM = 0x00||0x01||0xff-pad||0x00||SHA-1 DER header||SHA-1 digest */
      if (msg_len < 35 + 11) return -1;
      msg[0] = 0x00; msg[1] = 0x01;
      memset(&msg[2], 0xff, msg_len - 38); 
      msg[msg_len - 36] = 0x00;
      memcpy(&msg[msg_len - 35], "\x30\x21\x30\x09\x06\x05\x2b"
        "\x0e\x03\x02\x1a\x05\x00\x04\x14", 15);
      sha1_init(&ctx);
      sha1_update(&ctx, data, data_len);
      sha1_final(&ctx, &msg[msg_len - 20]);
      break;
    case RSA_SSA_PKCS1_SHA1_RAW:
      /* EM = 0x00||0x01||0xff-pad||0x00||SHA-1 DER header||SHA-1 digest */
      if (msg_len < 35 + 11 || data_len != 20) return -1;
      msg[0] = 0x00; msg[1] = 0x01;
      memset(&msg[2], 0xff, msg_len - 38);
      msg[msg_len - 36] = 0x00;
      memcpy(&msg[msg_len - 35], "\x30\x21\x30\x09\x06\x05\x2b"
        "\x0e\x03\x02\x1a\x05\x00\x04\x14", 15);
      memcpy(&msg[msg_len - 20], data, data_len);
      break;
    case RSA_SSA_PKCS1_DER:
      /* EM = 0x00||0x01||0xff-pad||0x00||DER encoded data */
      if (msg_len < data_len + 11) return -1;
      msg[0] = 0x00; msg[1] = 0x01;
      memset(&msg[2], 0xff, msg_len - data_len - 3);
      msg[msg_len - data_len - 1] = 0x00;
      memcpy(&msg[msg_len - data_len], data, data_len);
      break;
    case RSA_ES_PKCSV15:
      /* EM = 0x00||0x02||nonzero random-pad||0x00||data */
      if (msg_len < data_len + 11) return -1;
      msg[0] = 0x00; msg[1] = 0x02;
      tpm_get_random_bytes(&msg[2], msg_len - data_len - 3);
      for (i = 2; i < msg_len - data_len; i++)
        while (!msg[i]) tpm_get_random_bytes(&msg[i], 1);
      msg[msg_len - data_len - 1] = 0x00;
      memcpy(&msg[msg_len - data_len], data, data_len);
      break;
    case RSA_ES_OAEP_SHA1:
      /* DB = SHA-1("TCPA")||0x00-pad||0x01||data
         seed = random value of size SHA1_DIGEST_LENGTH
         masked-seed = seed xor MFG(seed, seed_len)
         masked-DB = DB xor MFG(seed, DB_len)
         EM = 0x00||masked-seed||masked-DB */
      if (msg_len < data_len + 2 * SHA1_DIGEST_LENGTH + 2) return -1;
      msg[0] = 0x00;
      tpm_get_random_bytes(&msg[1], SHA1_DIGEST_LENGTH);
      sha1_init(&ctx);
      sha1_update(&ctx, "TCPA", 4);
      sha1_final(&ctx, &msg[1 + SHA1_DIGEST_LENGTH]);
      memset(&msg[1 + 2 * SHA1_DIGEST_LENGTH], 0x00, 
        msg_len - data_len - 2 * SHA1_DIGEST_LENGTH - 2);
      msg[msg_len - data_len - 1] = 0x01;
      memcpy(&msg[msg_len - data_len], data, data_len);
      mask_generation(&msg[1], SHA1_DIGEST_LENGTH, 
        &msg[1 + SHA1_DIGEST_LENGTH], msg_len - SHA1_DIGEST_LENGTH - 1);
      mask_generation(&msg[1 + SHA1_DIGEST_LENGTH], 
        msg_len - SHA1_DIGEST_LENGTH - 1, &msg[1], SHA1_DIGEST_LENGTH);
      break; 
    default:
      /* unsupported encoding method */
      return -1;
  }
  return 0;
}

static int decode_message(int type, uint8_t *msg, size_t msg_len,
                          uint8_t *data, size_t *data_len)
{
  size_t i;
  sha1_ctx_t ctx;

  /* decode message according to type */
  switch (type) {
    case  RSA_ES_PKCSV15:
      /* EM = 0x00||0x02||nonzero random-pad||0x00||data */
      if (msg_len < 11) return -1;
      if (msg[0] != 0x00 || msg[1] != 0x02) return -1;
      for (i = 2; i < msg_len && msg[i]; i++);
      if (i < 10 || i >= msg_len) return -1;
      *data_len = msg_len - i - 1;
      memmove(data, &msg[i + 1], *data_len);
      break;
    case RSA_ES_OAEP_SHA1:
      /* DB = SHA-1("TCPA")||0x00-pad||0x01||data
         seed = random value of size SHA1_DIGEST_LENGTH
         masked-seed = seed xor MFG(seed, seed_len)
         masked-DB = DB xor MFG(seed, DB_len)
         EM = 0x00||masked-seed||masked-DB */
      if (msg_len < 2 + 2 * SHA1_DIGEST_LENGTH) return -1;
      if (msg[0] != 0x00) return -1;
      mask_generation(&msg[1 + SHA1_DIGEST_LENGTH],
        msg_len - SHA1_DIGEST_LENGTH - 1, &msg[1], SHA1_DIGEST_LENGTH);
      mask_generation(&msg[1], SHA1_DIGEST_LENGTH,
        &msg[1 + SHA1_DIGEST_LENGTH], msg_len - SHA1_DIGEST_LENGTH - 1);
      sha1_init(&ctx);
      sha1_update(&ctx, "TCPA", 4);
      sha1_final(&ctx, &msg[1]);
      if (memcmp(&msg[1], &msg[1 + SHA1_DIGEST_LENGTH], 
          SHA1_DIGEST_LENGTH) != 0) return -1;
      for (i = 1 + 2 * SHA1_DIGEST_LENGTH; i < msg_len && !msg[i]; i++);
      if (i >= msg_len || msg[i] != 0x01) return -1;
      *data_len = msg_len - i - 1;
      memmove(data, &msg[i + 1], *data_len);
      break;
    default:
      /* unsupported encoding method */
      return -1;
  }
  return 0;
}

int rsa_sign(rsa_private_key_t *key, int type, 
             const uint8_t *data, size_t data_len, uint8_t *sig)
{
  size_t sig_len = key->size >> 3;

  /* encode message */
  if (encode_message(type, data, data_len, sig, sig_len) != 0) return -1;
  /* sign encoded message */
  if (rsa_private(key, sig, sig_len, sig) != 0) return -1;
  return 0;
}

int rsa_verify(rsa_public_key_t *key, int type,
               const uint8_t *data, size_t data_len, uint8_t *sig)
{
  size_t sig_len = key->size >> 3;
  uint8_t msg_a[sig_len];
  uint8_t msg_b[sig_len];

  /* encode message */
  if (encode_message(type, data, data_len, msg_a, sig_len) != 0) return -1;
  /* decrypt signature */
  if (rsa_public(key, sig, sig_len, msg_b) != 0) return -1;
  /* compare messages */
  return (memcmp(msg_a, msg_b, sig_len) == 0) ? 0 : 1;
}

int rsa_decrypt(rsa_private_key_t *key, int type,
                const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
  *out_len = key->size >> 3;
  if (in_len != *out_len || in_len < 11) return -1;
  /* decrypt message */
  if (rsa_private(key, in, in_len, out) != 0) return -1;
  /* decode message */
  if (decode_message(type, out, *out_len, out, out_len) != 0) return -1;
  return 0;
}

int rsa_encrypt(rsa_public_key_t *key, int type,
                const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
  *out_len = key->size >> 3;
  /* encode message */
  if (encode_message(type, in, in_len, out, *out_len) != 0) return -1;
  /* encrypt encoded message */
  if (rsa_public(key, out, *out_len, out) != 0) return -1;
  return 0;
}

