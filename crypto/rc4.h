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
 
#ifndef _RC4_H_
#define _RC4_H_

#include "linux_module.h"

typedef struct {
    uint8_t state[256];
    uint8_t x, y;
} rc4_ctx_t;

void rc4_init(rc4_ctx_t *s, uint8_t *key, size_t key_len);

void rc4_crypt(rc4_ctx_t *s, uint8_t *in, uint8_t *out, size_t length);

#endif /* _RC4_h_ */
