Summary: Zebedee: a simple, free, secure TCP and UDP tunnel program
%define name zebedee
Name: %{name}
%define version 2.4.1
%define ostype linux
Version: %{version}
Release: 1
Group: Applications/Security
Copyright: GPL
URL: http://www.winton.org.uk/zebedee/
Source: %{name}-%{version}.tar.gz
Prefix: /usr
BuildRoot: /var/tmp/zebedee

%description
Zebedee is a simple program to establish an encrypted, compressed 
"tunnel" for TCP/IP or UDP data transfer between two systems. 
This allows traffic such as telnet, ftp and X to be protected from 
snooping as well as potentially gaining performance over 
low-bandwidth networks from compression.

The main goals for Zebedee are to:

- Provide full client and server functionality under both UNIX and 
  Windows. Be easy to install, use and maintain with little or no
  configuration required. Have a small footprint, low wire protocol
  overhead and give significant traffic reduction by the use of
  compression. 

- Use only algorithms that are either unpatented or for which the 
  patent has expired. 

- Be entirely free for commercial or non-commercial use and 
  distributed under the term of the GNU General Public Licence. 

%prep
%setup

%build
make OS=%{ostype} ZINC= ZLIB=-lz BZINC= BZLIB=-lbz2 BFINC=-I/usr/include/openssl BFLIB=-lcrypto

%install
make install OS=%{ostype} "ROOTDIR=$RPM_BUILD_ROOT/usr"

%files
/usr/bin/zebedee
/usr/bin/ftpgw.tcl
/usr/lib/zebedee
%doc /usr/man/man1/zebedee.1*
%doc /usr/man/man1/ftpgw.tcl.1*
%doc *.txt *.html

%changelog
* Tue May 29 2002 Neil Winton <neil@winton.org.uk>
- Zebedee version 2.4.1

* Thu May 09 2002 Neil Winton <neil@winton.org.uk>
- Zebedee version 2.4.0

* Fri Mar 22 2002 Neil Winton <neil@winton.org.uk>
- Zebedee version 2.3.2

* Fri Mar 15 2002 Neil Winton <neil@winton.org.uk>
- Zebedee version 2.3.1

* Thu Mar 07 2002 Neil Winton <neil@winton.org.uk>
- Zebedee version 2.3.0

* Fri Apr 13 2001 Neil Winton <neil@winton.org.uk>
- Zebedee version 2.2.2

* Fri Feb 09 2001 Neil Winton <neil@winton.org.uk>
- Zebedee version 2.2.1

* Fri Feb 02 2001 Neil Winton <neil@winton.org.uk>
- Zebedee version 2.2.0

* Sat Oct 14 2000 Neil Winton <neil@winton.org.uk>
- Modified based on Marc's work -- fixed the man page creation
- Zebedee version 2.1.3

* Sun Sep 3 2000 Marc Lavallée <odradek@videotron.ca>
- initial RPM package, should work with most Unix
- modified Makefile: disabled the buggy zebedee man page creation
- inclusion of the zebedee man page
