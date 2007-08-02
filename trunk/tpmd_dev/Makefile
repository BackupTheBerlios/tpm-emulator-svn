# Software-Based Trusted Platform Module (TPM) Emulator for Linux
# Copyright (C) 2006 Mario Strasser <mast@gmx.net>
#
# $Id$

# kernel settings
KERNEL_RELEASE := $(shell uname -r)
KERNEL_BUILD   := /lib/modules/$(KERNEL_RELEASE)/build
MOD_SUBDIR     := misc

# module settings
MODULE_NAME    := tpmd_dev
obj-m          := $(MODULE_NAME).o

# do not print "Entering directory ..."
MAKEFLAGS      += --no-print-directory
EXTRA_CFLAGS   += -Wall -Werror -DDEBUG

all:
	@$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) modules

clean:
	@$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) clean
	rm -f Modules.symvers

install:
	@$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) modules_install
	cp tpmd_dev.rules /etc/udev/rules.d/80-tpmd_dev.rules
	depmod -a

.PHONY: all clean install

