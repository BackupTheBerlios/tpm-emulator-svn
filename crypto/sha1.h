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

#ifndef _SHA1_H_
#define _SHA1_H_

#include "linux_module.h"

#define SHA1_DIGEST_LENGTH 20

typedef struct {
  uint32_t h[5];
  uint32_t count_lo, count_hi;
  uint8_t buf[64];
} sha1_ctx_t;

void sha1_init(sha1_ctx_t *ctx);

void sha1_update(sha1_ctx_t *ctx, uint8_t *data, uint32_t length);

void sha1_final(sha1_ctx_t *ctx, uint8_t digest[SHA1_DIGEST_LENGTH]);

#endif /* _SHA1_H_ */
