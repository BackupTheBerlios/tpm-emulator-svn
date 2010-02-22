# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id$

KEXT_BIN = build/Release/tpm_bridge.kext

all:
	@xcodebuild > /dev/null

clean:
	@xcodebuild clean > /dev/null

TPM_OWNER ?= root
TPM_GROUP ?= wheel
INSTALL ?= install

install: $(KEXT_BIN)
	@$(INSTALL) -o $(TPM_OWNER) -g $(TPM_GROUP) -d $(KEXT_BIN) $(DESTDIR)/System/Library/Extensions

.PHONY: all clean install
