#
# Makefile for Zebedee
#
# $Id: Makefile,v 1.3 2001-08-02 15:21:58 ndwinton Exp $

ZBD_VERSION = 2.3.0

OS = 

###
### Locations of tools, libraries and installation directories.
### You may well need to change these.
###

# Chose your C compiler

CC_$(OS) = gcc

CC_win32 = c:/gcc-2.95.2/bin/gcc
CC_linux = gcc -pthread
CC_solaris = gcc
CC_freebsd = gcc -pthread
CC_tru64 = cc
CC = $(CC_$(OS))

# Optimise/debug compilation

#OPTIM = -Wall -g
OPTIM = -O3

# Location of gmp include and library
#
# NOTE: These are no longer used unless you define USE_GMP_LIBRARY (which is
# undefined by default). Uncomment them as necessary.

# GMPINC = -I../gmp-2.0.2
# GMPLIB = ../gmp-2.0.2/libgmp.a

# Location of Blowfish include and library

BFINC = -I../blowfish-0.9.5a
BFLIB = ../blowfish-0.9.5a/libblowfish.a

# Location of zlib include and library

ZINC = -I../zlib-1.1.3
ZLIB = ../zlib-1.1.3/libz.a

# Location of bzlib include and library
# Set these empty if you don't want bzib2 support

BZINC = -I../bzip2-1.0.1
BZLIB = ../bzip2-1.0.1/libbz2.a

#
# Tools needed for Perl "POD"-format documentation conversion.
#
PERL_$(OS) = perl
PERL_win32 = c:/perl/bin/perl	# Avoid Cygwin port
PERL = $(PERL_$(OS))

BAT_win32 = .bat

POD2HTML = $(PERL) -S pod2html$(BAT_$(OS))
POD2MAN = $(PERL) -S pod2man$(BAT_$(OS))

# Installation directories for the Linux/Solaris/*NIX World

ROOTDIR = /usr
BINDIR = $(ROOTDIR)/bin
ZBDDIR = $(ROOTDIR)/lib/zebedee
MANDIR = $(ROOTDIR)/man/man1

# This is a BSD-style install

INSTALL_$(OS) = install -c

INSTALL_linux = install -c
INSTALL_solaris = /usr/ucb/install -c
INSTALL_freebsd = install -c
INSTALL_tru64 = installbsd -c
INSTALL = $(INSTALL_$(OS))

# InnoSetup compiler for Win32 (see http://www.jordanr.dhs.org/)

ISCOMP = "c:/Program Files/Inno Setup 1.11/compil32.exe"

###
### OS-specific definitions
###
### You should probably not have to change these. If you port Zebedee to
### a new platform add definitions of the form XXXX_osname
###

# Define one or more of the following ...
#
# Multi-threading:
#   Use -DHAVE_PTHREADS if you have (and wish to use) POSIX threads
#
#   If you have a system (such as FreeBSD) where fork and pthreads don't
#   mix well define BUGGY_FORK_WITH_THREADS as well.
#
# Use of bzip2 compression:
#   Use -DDONT_HAVE_BZIP2 if you do not have or do not want to support
#   the use of bzip2 compression

DEFINES_win32 =
DEFINES_linux = -DHAVE_PTHREADS
DEFINES_solaris = -D_REENTRANT -DHAVE_PTHREADS
DEFINES_freebsd = -DHAVE_PTHREADS -DBUGGY_FORK_WITH_THREADS
DEFINES_tru64 = -D_REENTRANT -DHAVE_PTHREADS
DEFINES = $(DEFINES_$(OS))

# Suffix for executables

EXE_win32 = .exe	# Win32
EXE = $(EXE_$(OS))

# Extra OS-specific libraries

OSLIBS_win32 = -lwsock32 -lwinmm
OSLIBS_linux = -lpthread
OSLIBS_solaris = -lsocket -lnsl -lthread
OSLIBS_freebsd =
OSLIBS_tru64 = -lpthread
OSLIBS = $(OSLIBS_$(OS))

# Supplementary object files (Win32 ONLY)

GETOPTOBJ_win32 = getopt.o
GETOPTOBJ = $(GETOPTOBJ_$(OS))

SERVICEOBJ_win32 = service.o
SERVICEOBJ = $(SERVICEOBJ_$(OS))

####
#### You REALLY shouldn't have to modify anything beyond here ...
####

CFLAGS = $(OPTIM) $(DEFINES) -I. $(GMPINC) $(BFINC) $(ZINC) $(BZINC)

LIBS = $(GMPLIB) $(BFLIB) $(ZLIB) $(BZLIB) $(OSLIBS)

OBJS = zebedee.o sha_func.o huge.o $(GETOPTOBJ) $(SERVICEOBJ)

ZBDFILES = server.zbd vncviewer.zbd vncserver.zbd server.key server.id \
	client1.key client2.key clients.id

TXTFILES = README.txt LICENCE.txt GPL2.txt CHANGES.txt \
	zebedee.html ftpgw.tcl.html zebedee.ja_JP.html

EXTRAFILES = $(ZBDFILES) $(TXTFILES)

all : precheck zebedee$(EXE) zebedee.1 zebedee.html ftpgw.tcl.1 ftpgw.tcl.html zebedee.ja_JP.html

precheck :
	@ if test -z "$(OS)"; then echo "Use '$(MAKE) OS=xxx' where xxx is win32, linux, solaris, freebsd or tru64"; exit 1; fi

zebedee$(EXE) : $(OBJS)
	$(CC) $(CFLAGS) -o zebedee$(EXE) $(OBJS) $(LIBS)

huge.o : huge.h

zebedee.1 : zebedee.pod
	rm -f ./tmp/zebedee.pod
	mkdir -p tmp
	$(PERL) -pe 's/^\=head3/\=head2/;' zebedee.pod > ./tmp/zebedee.pod
	$(POD2MAN) --release="Zebedee $(ZBD_VERSION)" --center=Zebedee ./tmp/zebedee.pod > zebedee.1
	rm -f ./tmp/zebedee.pod

zebedee.html : zebedee.pod
	$(POD2HTML) --title="Zebedee: A simple, secure IP tunnel" --noindex zebedee.pod > zebedee.tmp
	$(PERL) fixhtml.pl < zebedee.tmp > zebedee.html
	rm -f zebedee.tmp

zebedee.ja_JP.html :
	( cd doc_jp; \
	$(MAKE) PERL="$(PERL)" POD2HTML="$(POD2HTML)" POD2MAN="$(POD2MAN)" INSTALL="$(INSTALL)" ROOTDIR="$(ROOTDIR)" )

ftpgw.tcl.1 : ftpgw.tcl.pod
	$(POD2MAN) --release="1.0" --center=ftpgw.tcl ftpgw.tcl.pod > ftpgw.tcl.1

ftpgw.tcl.html : ftpgw.tcl.pod
	$(POD2HTML) --title="ftpgw.tcl: A simple FTP tunnelling gateway" --noindex ftpgw.tcl.pod > ftpgw.tcl.tmp
	$(PERL) fixhtml.pl < ftpgw.tcl.tmp > ftpgw.tcl.html
	rm -f ftpgw.tcl.tmp

install : precheck zebedee$(EXE) zebedee.1 ftpgw.tcl.1 $(ZBDFILES) $(TXTFILES)
	-mkdir -p $(BINDIR) $(MANDIR) $(ZBDDIR)
	$(INSTALL) zebedee$(EXE) $(BINDIR)
	$(INSTALL) -m 0755 ftpgw.tcl $(BINDIR)
	$(INSTALL) zebedee.1 $(MANDIR)
	$(INSTALL) ftpgw.tcl.1 $(MANDIR)
	$(INSTALL) $(ZBDFILES) $(ZBDDIR)
	$(INSTALL) $(TXTFILES) $(ZBDDIR)

clean : precheck
	rm -f zebedee$(EXE) *.o core *.1 *.html *.tmp *.bak

# This makes the Win32 setup.exe using InnoSetup. The perl command in
# this sequence "dosifies" the text files ... sigh ...

zbdsetup.exe : zebedee$(EXE) zebedee.html zebedee.ico vncloopback.reg \
		$(ZBDFILES) $(TXTFILES)
	$(PERL) -ni.bak -e print $(ZBDFILES) $(TXTFILES) vncloopback.reg
	$(ISCOMP) /cc zebedee.iss
	mv -f Output/setup.exe zbdsetup.exe
