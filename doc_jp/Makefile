PERL = perl
POD2HTML = pod2html
POD2MAN = pod2man
INSTALL = install
FIXHTML = ../fixhtml.pl

ROOTDIR = /usr
JAMANDIR = $(ROOTDIR)/man/ja/man1

all : zebedee.1 zebedee.html ftpgw.tcl.1 ftpgw.tcl.html ../zebedee.ja_JP.html

zebedee.1 : zebedee.pod
	rm -f ../tmp/zebedee.pod
	$(PERL) -pe 's/^\=head3/\=head2/;' zebedee.pod > ../tmp/zebedee.pod
	$(POD2MAN) --release="Zebedee 2.1.0" --center=Zebedee ../tmp/zebedee.pod > zebedee.1
	rm -f ../tmp/zebedee.pod

zebedee.html : zebedee.pod
	$(POD2HTML) --title="Zebedee: A simple, secure IP tunnel" --noindex zebedee.pod > zebedee.tmp
	$(PERL) $(FIXHTML) < zebedee.tmp > zebedee.html
	rm -f zebedee.tmp

ftpgw.tcl.1 : ftpgw.tcl.pod
	$(POD2MAN) --release="1.0" --center=ftpgw.tcl ftpgw.tcl.pod > ftpgw.tcl.1

ftpgw.tcl.html : ftpgw.tcl.pod
	$(POD2HTML) --title="ftpgw.tcl: A simple FTP tunnelling gateway" --noindex ftpgw.tcl.pod > ftpgw.tcl.tmp
	$(PERL) $(FIXHTML) < ftpgw.tcl.tmp > ftpgw.tcl.html
	rm -f ftpgw.tcl.tmp

../zebedee.ja_JP.html : zebedee.html
	rm -f ../zebedee.ja_JP.html
	ln zebedee.html ../zebedee.ja_JP.html

install : zebedee.1 zebedee.html ftpgw.tcl.1 ftpgw.tcl.html
	-mkdir -p $(JAMANDIR) 
	$(INSTALL) zebedee.1 $(JAMANDIR)
	$(INSTALL) ftpgw.tcl.1 $(JAMANDIR)

clean : 
	rm -f core *.1 *.html *.tmp *.bak pod2html*
