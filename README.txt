Zebedee Secure Tunnel
=====================

THIS IS THE LATEST DEVELOPMENT RELEASE.
THE LATEST STABLE RELEASE IS 2.4.1.

Zebedee is a simple program to establish an encrypted, compressed
"tunnel" for TCP/IP or UDP traffic between two systems. This
allows data from, for example, telnet, ftp and X sessions to be
protected from snooping. You can also use compression, either
with or without data encryption, to gain performance over
low-bandwidth networks.

The main goals for Zebedee are to:

 * Provide client and server functionality under both UNIX/Linux
   and Windows.

 * Be easy to install, use and maintain with little or no
   configuration required.

 * Have a small footprint, low wire protocol overhead and
   give significant traffic reduction by the use of
   compression.

 * Use only algorithms that are either unpatented or for
   which the patent has expired.

 * Be entirely free for commercial or non-commercial use and
   distributed under the term of the GNU General Public
   Licence (see LICENCE.txt for details).

For further information on how to use Zebedee see the file
zebedee.html in the distribution (or the manual page for
zebedee(1) under UNIX -- it is basically the same text). Example
configuration files are also provided.

Versions of Zebedee in the 2.4.x series are stable, "production"
versions. The development series, containing new features, but
less well tested is numbered 2.5.x.

Building Zebedee
----------------

For instructions on how to build Zebedee see the file
BUILDING.txt in the distribution.

Special Notes for Windows Installations
---------------------------------------

The installation on Windows systems creates a Start Menu entry
that contains an icon to start a Zebedee server. If you select
this menu entry Zebedee will take its configuration information
from the file "server.zbd" in the Zebedee installation directory.
You MUST edit this file before you can do anything useful with
Zebedee. The "out of the box" configuration is deliberately
as secure as possible and will not allow you create any tunnels
to the server without you explicitly enabling them.

The Zebedee service is not installed automatically. If you want
to run Zebedee as a service you must use the "-Sinstall" option
from the command-line.

Zebedee clients will probably, in general, be started from the
command line. However, a file-type association is created by
theinstallation for files of type ".zbd". This can be used to
launch Zebedee clients automatically from Explorer or elsewhere
-- provided that all the necessary information is contained
within the configuration file.

Neil Winton, 2003/07/02
