#!/usr/bin/perl
DSTDIR = 
WPP = ./wpp

# list of all source raws in current directory
SRC = $(subst ./,, $(shell find -name "*.raw"))

# list of all htmls we want to create in DSTDIR
DST = $(addprefix $(DSTDIR)/, $(SRC:.raw=.html))

all : $(DST) 

$(DSTDIR)/%.html : %.raw
	$(WPP) $<


# rule to build 'Makefile.dep', alias 'dep'
Makefile.dep dep :
	@$(WPP) -d $(SRC) > Makefile.dep 

