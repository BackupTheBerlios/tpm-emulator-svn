/* Software-Based Trusted Platform Module (TPM) Emulator for OpenBSD
 * Copyright (C) 2007 Sebastian Schuetz <sebastian_schuetz@genua.de>
 * Copyright (C) 2007 Mario Strasser <mast@gmx.net>,
 *                    Swiss Federal Institute of Technology (ETH) Zurich
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id$
 */

#ifndef _TPM_DEV_HEADER_
#define _TPM_DEV_HEADER_

#define cdev_tpm_init(c,n) { \
    dev_init(c,n,open),dev_init(c,n,close),dev_init(c,n,read), \
    dev_init(c,n,write), dev_init(c,n,ioctl),(dev_type_stop((*))) lkmenodev, \
    0,(dev_type_poll((*))) lkmenodev,(dev_type_mmap((*))) lkmenodev }


/* This code is from linux_module.c */

/* module state */
static uint32_t module_state;
static struct socket *tpmd_sock = NULL;
static struct mbuf *nm = NULL;
static struct simplelock slock;

char tpmd_socket_name[] = "/var/tpm/tpmd_socket:0";

#define TPM_MODULE_NAME   "tpm_dev"
#define TPM_STATE_IS_OPEN 0


#ifdef DEBUG
#define debug(fmt, ...) printf("%s %s:%d: Debug: " fmt "\n", \
                        TPM_MODULE_NAME, __FILE__, __LINE__, ## __VA_ARGS__)
#else
#define debug(fmt, ...)
#endif
#define error(fmt, ...) printf("%s %s:%d: Error: " fmt "\n", \
                        TPM_MODULE_NAME, __FILE__, __LINE__, ## __VA_ARGS__)

#endif /* _TPM_DEV_HEADER_ */
