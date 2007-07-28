# TPM Device Driver Library for the TPM-Emulator package
# Copyright (C) 2006 Mario Strasser <mast@gmx.net>,
#                    Swiss Federal Institute of Technology (ETH) Zurich
#
# $Id$

CC     := gcc
WFLAGS := -Wall -Werror -Wno-unused -Wpointer-arith -Wcast-align \
           -Wwrite-strings -Wsign-compare -Wno-multichar
#WFLAGS += -Wextra -Wcast-qual -Wmissing-prototypes -Wmissing-declarations -Wstrict-aliasing
CFLAGS := $(WFLAGS) -O2
TDDL   := libtddl.so

LIBDIR := /usr/lib/
INCDIR := /usr/include/

all: $(TDDL)

$(TDDL): tddl.c tddl.h
	$(CC) $(CFLAGS) -fPIC -c -o tddl.o tddl.c
	ld -soname $(TDDL) -shared -o $(TDDL) tddl.o

test_tddl: test_tddl.c
	$(CC) $(CFLAGS) -I. -L. test_tddl.c -ltddl -o test_tddl

clean:
	rm -rf $(TDDL) *.o test_tddl

install: $(TDDL)
	cp $(TDDL) $(LIBDIR)
	cp tddl.h $(INCDIR)
	ldconfig

test: test_tddl
	LD_LIBRARY_PATH=. ./test_tddl

.PHONY: all clean install test

