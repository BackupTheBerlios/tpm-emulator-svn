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

TDDL    := libtddl.so
TDDLSO1 := $(TDDL).1.2
TDDLSO2 := $(TDDL).1.2.0

LIBDIR := /usr/lib/
INCDIR := /usr/include/

all: $(TDDL)

$(TDDL): tddl.c tddl.h
	$(CC) $(CFLAGS) -fPIC -c -o tddl.o tddl.c
	ld -shared -soname $(TDDLSO1) -o $(TDDLSO2) tddl.o
	test -s $(TDDLSO1) || ln -s $(TDDLSO2) $(TDDLSO1)
	test -s $(TDDL) || ln -s $(TDDLSO1) $(TDDL)

test_tddl: test_tddl.c
	$(CC) $(CFLAGS) -I. -L. test_tddl.c -ltddl -o test_tddl

clean:
	rm -rf $(TDDL) $(TDDLSO1) $(TDDLSO2) *.o test_tddl

INSTALL ?= install

install: $(TDDL)
	$(INSTALL) -m 644 tddl.h $(DESTDIR)/$(INCDIR)
	$(INSTALL) -m 644 $(TDDLSO2) $(DESTDIR)/$(LIBDIR)
	ln -s $(DESTDIR)/$(LIBDIR)/$(TDDLSO2) $(DESTDIR)/$(LIBDIR)/$(TDDLSO1)
	ln -s $(DESTDIR)/$(LIBDIR)/$(TDDLSO1) $(DESTDIR)/$(LIBDIR)/$(TDDL)
	ldconfig

test: test_tddl
	LD_LIBRARY_PATH=. ./test_tddl

.PHONY: all clean install test

