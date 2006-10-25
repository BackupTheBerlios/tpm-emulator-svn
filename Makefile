# Software-Based Trusted Platform Module (TPM) Emulator for Linux
# Copyright (C) 2004 Mario Strasser <mast@gmx.net>
#
# $Id$

# kernel settings
KERNEL_RELEASE := $(shell uname -r)
KERNEL_BUILD   := /lib/modules/$(KERNEL_RELEASE)/build
MOD_SUBDIR     := misc

# module settings
MODULE_NAME    := tpm_emulator
VERSION_MAJOR  := 0
VERSION_MINOR  := 4
VERSION_BUILD  := $(shell date +"%s")

# enable/disable DEBUG messages
EXTRA_CFLAGS   += -Wall -DDEBUG -g

# GNU MP configuration
GMP_LIB        := /usr/lib/libgmp.a
GMP_HEADER     := /usr/include/gmp.h

# sources and objects
src            ?= .
DIRS           := . crypto tpm 
SRCS           := $(foreach dir, $(DIRS), $(wildcard $(src)/$(dir)/*.c))
OBJS           := $(patsubst %.c, %.o, $(SRCS))
SRCS           += $(foreach dir, $(DIRS), $(wildcard $(src)/$(dir)/*.h))
DISTSRC        := ./README ./AUTHORS ./ChangeLog ./Makefile $(SRCS)
DISTDIR        := tpm_emulator-$(VERSION_MAJOR).$(VERSION_MINOR)

obj-m               := $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(patsubst $(src)/%.o, %.o, $(OBJS)) crypto/libgmp.a

EXTRA_CFLAGS   += -I$(src) -I$(src)/crypto -I$(src)/tpm 

# do not print "Entering directory ..."
MAKEFLAGS      += --no-print-directory

all:	$(src)/crypto/gmp.h $(src)/crypto/libgmp.a version
	@$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) modules

install:
	@$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) modules_install
	test -d /var/tpm || mkdir /var/tpm
	test -c /dev/tpm || mknod /dev/tpm c 10 224
	chmod 666 /dev/tpm
	depmod -a

clean:
	@$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) clean
	rm -f $(src)/crypto/gmp.h $(src)/crypto/libgmp.a

dist:	$(DISTSRC)
	rm -rf $(DISTDIR)
	mkdir $(DISTDIR)
	cp --parents $(DISTSRC) $(DISTDIR)/
	rm -f $(DISTDIR)/crypto/gmp.h 
	tar -chzf $(DISTDIR).tar.gz $(DISTDIR)
	rm -rf $(DISTDIR)

$(src)/crypto/libgmp.a:
	test -f $(src)/crypto/libgmp.a || ln -s $(GMP_LIB) $(src)/crypto/libgmp.a

# Note: We have to make sure that we use stack-based calling conventions 
# when using GNU MP library functions
$(src)/crypto/gmp.h:
	test -r $(src)/crypto/gmp.h || cat $(GMP_HEADER) | \
		sed -e "s/\(__GMP_DECLSPEC [^e].*\);/\1 __attribute__ ((regparm(0)));/" | \
		sed -e "s/^int$$/int __attribute__ ((regparm(0)))/" | \
		sed -e "s/^void$$/void __attribute__ ((regparm(0)))/" | \
		sed -e "s/^size_t$$/size_t __attribute__ ((regparm(0)))/" | \
		sed -e "s/^mp_limb_t$$/mp_limb_t __attribute__ ((regparm(0)))/" | \
		sed -e "s/^__GMP_EXTERN_INLINE void$$/__GMP_EXTERN_INLINE void __attribute__ ((regparm(0)))/" | \
		sed -e "s/^unsigned long$$/unsigned long __attribute__ ((regparm(0)))/" | \
		sed -e "s/\(.* (\*__gmp_allocate_func) .*\);/\1 __attribute__ ((regparm(0)));/" | \
		sed -e "s/\(.* (\*__gmp_reallocate_func) .*\);/\1 __attribute__ ((regparm(0)));/" | \
		sed -e "s/\(.* (\*__gmp_free_func) .*\);/\1 __attribute__ ((regparm(0)));/" \
		> $(src)/crypto/gmp.h

version:
	@echo "#ifndef _TPM_VERSION_H_" > $(src)/tpm/tpm_version.h
	@echo "#define _TPM_VERSION_H_" >> $(src)/tpm/tpm_version.h
	@echo "#define VERSION_MAJOR $(VERSION_MAJOR)" >> $(src)/tpm/tpm_version.h
	@echo "#define VERSION_MINOR $(VERSION_MINOR)" >> $(src)/tpm/tpm_version.h
	@echo "#define VERSION_BUILD $(VERSION_BUILD)" >> $(src)/tpm/tpm_version.h
	@echo "#endif /* _TPM_VERSION_H_ */" >> $(src)/tpm/tpm_version.h

.PHONY: all install clean dist gmp version

