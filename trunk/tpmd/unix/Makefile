# Software-Based Trusted Platform Module (TPM) Emulator for Linux
# Copyright (C) 2004-2006 Mario Strasser <mast@gmx.net>
#
# $Id$

CC      := gcc
WFLAGS  := -Wall -Werror -Wno-unused -Wpointer-arith -Wcast-align \
           -Wwrite-strings -Wsign-compare -Wno-multichar
           #WFLAGS  += -Wextra -Wcast-qual -Wmissing-prototypes -Wmissing-declarations -Wstrict-aliasing
CFLAGS  += $(WFLAGS) -g -I.. -I. -O2 -fno-strict-aliasing
LDFLAGS += -lgmp

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

TPMD_USER  ?= tss
TPMD_GROUP ?= tss
INSTALL    ?= install

install: $(TPMD)
	$(INSTALL) -m 755 -o $(TPMD_USER) -g $(TPMD_GROUP) -d $(DESTDIR)/var/lib/tpm
	$(INSTALL) -m 755 -o $(TPMD_USER) -g $(TPMD_GROUP) -d $(DESTDIR)/var/run/tpm
	$(INSTALL) -D -d $(DESTDIR)/$(BINDIR)
	$(INSTALL) -m 755 $(TPMD) $(DESTDIR)/$(BINDIR)

.PHONY: all clean install

