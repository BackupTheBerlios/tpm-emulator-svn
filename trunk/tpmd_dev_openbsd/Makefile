# Software-Based Trusted Platform Module (TPM) Emulator for OpenBSD
# Copyright (C) 2007 Sebastian Schuetz <sebastian_schuetz@genua.de>
# Copyright (C) 2007 Mario Strasser <mast@gmx.net>
#
# $Id$

CFLAGS= -D_KERNEL -I/usr/src/sys
SRC=	tpmd_dev.c
MODULE= tpmd_dev.o

all:
	cc -c $(SRC) $(CFLAGS)
	ld -r -o $(MODULE) $(SRC:.c=.o)

clean:
	rm -rf $(SRC:.c=.o)
	rm -f $(MODULE)

load:	all mknod
	modload -o tpm.o -etpm $(MODULE)

unload: rknod
	modunload -n tpm

mknod:
	mknod -m 644 /dev/tpm c 29 0

rknod:
	rm /dev/tpm
