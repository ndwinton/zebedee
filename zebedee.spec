Summary: Zebedee: a simple, free, secure TCP and UDP tunnel program
%define name zebedee
Name: %{name}
%define version 2.2.2
%define os linux # linux, freebsd, solaris or tru64
%define zlib 1.1.3
%define bzip 1.0.1
%define blowfish 0.9.5a
Version: %{version}
Release: 1
Group: Applications/Security
Copyright: GPL
URL: http://www.winton.org.uk/zebedee/
Source: %{name}-%{version}.tar.gz
Source1: blowfish-%{blowfish}.tar.gz
Source2: zlib-%{zlib}.tar.gz
Source3: bzip2-%{bzip}.tar.gz

%description
Zebedee is a simple program to establish an encrypted, compressed 
"tunnel" for TCP/IP or UDP data transfer between two systems. 
This allows traffic such as telnet, ftp and X to be protected from 
snooping as well as potentially gaining performance over 
low-bandwidth networks from compression.

The main goals for Zebedee are to:

- Provide full client and server functionality under both UNIX and 
  Windows 95/98/NT. Be easy to install, use and maintain with little 
  or no configuration required. Have a small footprint, low wire 
  protocol overhead and give significant traffic reduction by the 
  use of compression. 

- Use only algorithms that are either unpatented or for which the 
  patent has expired. 

- Be entirely free for commercial or non-commercial use and 
  distributed under the term of the GNU General Public Licence. 

%prep
%setup -b 1 -b 2 -b 3

%build
cd ../blowfish-%{blowfish}
make optimize
cd ../zlib-%{zlib}
./configure
make
cd ../bzip2-%{bzip}
make
cd ../%{name}-%{version}
make OS=%{os}

%install
make install OS=%{os}

%files
/usr/bin/zebedee
/usr/bin/ftpgw.tcl
/usr/lib/zebedee
%doc /usr/man/man1/zebedee.1
%doc /usr/man/man1/ftpgw.tcl.1
%doc *.txt *.html

%changelog
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
