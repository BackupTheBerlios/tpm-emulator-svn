# Software-Based Trusted Platform Module (TPM) Emulator for Linux
# Copyright (C) 2004-2006 Mario Strasser <mast@gmx.net>
#
# $Id$

CC      := gcc
WFLAGS  := -Wall -Werror -Wextra -Wno-unused -Wpointer-arith -Wcast-align \
           -Wwrite-strings -Wsign-compare -Wno-multichar
           #WFLAGS  += -Wcast-qual -Wmissing-prototypes -Wmissing-declarations -Wstrict-aliasing
CFLAGS  := $(WFLAGS) -g -I.. -I. -O2 -fno-strict-aliasing
LDFLAGS := -lgmp

BINDIR  := /usr/sbin/

TPMD    := tpmd
DIRS    := ../tpm ../crypto
SRCS    := $(foreach dir, $(DIRS), $(wildcard $(dir)/*.c))
OBJS    := $(patsubst %.c, %.o, $(SRCS))
OBJS    := $(foreach dir, $(DIRS), $(patsubst $(dir)/%.o, %.o, $(filter $(dir)/%.o, $(OBJS))))

vpath %.c $(strip $(DIRS))

all: $(TPMD)

$(TPMD): $(OBJS)

clean:
	rm -f $(TPMD) $(OBJS)

install: $(TPMD)
	test -d /var/tpm || mkdir /var/tpm
	cp $(TPMD) $(BINDIR)

.PHONY: all clean install

