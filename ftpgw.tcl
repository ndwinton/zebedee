#!/bin/sh
#
# ftpgw.tcl -- FTP gateway to permit tunnelling
#
# Usage: ftpgw.tcl [-p port-range] [-v] [listen-port [ftpd-host [ftpd-port]]]
#
# This program is a simple FTP gateway that intercepts PORT commands and
# passive-mode responses so that it can set up handlers for the data
# streams associated with them. It then rewites these control lines so
# that traffic to an FTP server apparently comes from the gateway process.
# Similarly a client sees a remote port that it can access for passive
# mode transfers. This allows the FTP control (but not data) channel to
# be tunnelled and encrypted.
#
# By default the program listens on port 2121 and will redirect traffic
# to a local FTP server on port 21. These values can be overridden on the
# command line. The -v option turns on verbose logging to stderr.
#
# If the -p option is specified then the argument is a range of port
# numbers in the form xxx-yyy. All passive-mode data ports will be in
# the range xxx to yyy and the response lines will be re-written to
# redirect a client to the corresponding port on 127.0.0.1 (localhost).
# This means that passive-mode data connections can be tunnelled in
# addition to the control connection.
#
#
# This file is part of "zebedee".
#
# Copyright 2000, 2001 by Neil Winton. All rights reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# For further details on "zebedee" see http://www.winton.org.uk/zebedee/
#
#
# $Id: ftpgw.tcl,v 1.2 2001-04-13 17:42:30 ndwinton Exp $
#
# Restart using tclsh. Do not delete this backslash -> \
    exec tclsh $0 ${1+"$@"}

set ListenPort 2121	    ;# Port on which to listen
set FtpdHost localhost	    ;# Host on which ftpd is running
set FtpdPort 21		    ;# Port on which ftpd is listening
set FtpdAddr 127.0.0.1	    ;# Address of host on which ftpd is running
set Verbose 0		    ;# Verbose mode -- log messages to stderr
set Initialised 0	    ;# Flag to indicate initialisation complete
set MinPasvPort 0	    ;# Minimum value for passive data port
set MaxPasvPort 0	    ;# Maximum value for passive data port


# log
#
# Log a message in verbose mode

proc log {msg} {
    global Verbose

    if {$Verbose} {puts stderr $msg}
}

# acceptCtrlConn
#
# Accept a new control connection and create a socket to the real ftpd.
# Traffic on either connection is handled by the handleCtrl routine.

proc acceptCtrlConn {mySock ipAddr port} {
    global FtpdHost FtpdPort Initialised

    if {!$Initialised} {
	# First connection received will be a dummy to determine the host
	# address -- ignore it
	set Initialised 1
	close $mySock
	return
    }

    log "$mySock: new client from $ipAddr/$port"

    if {[catch {socket $FtpdHost $FtpdPort} ftpdSock]} {
	close $mySock
	error "can't create forwarding control connection to $FtpdHost/$FtpdPort: $ftpdSock"
    }

    log "$mySock: connected to $FtpdHost/$FtpdPort via $ftpdSock"

    fconfigure $mySock -blocking false
    fconfigure $ftpdSock -blocking false

    fileevent $mySock readable [list handleCtrl $mySock $ftpdSock]
    fileevent $ftpdSock readable [list handleCtrl $ftpdSock $mySock]
}

# handleCtrl
#
# Handle a control connection. This is used for both traffic from and to
# the server. Data is read from fromSock and written to toSock. It may
# be transformed before being written. Specifically, PORT commands from
# a client result and passive-mode replies (227) from a server result in
# a new local data socket and handler being created and the address details
# being rewritten.

proc handleCtrl {fromSock toSock} {
    global HostAddr FtpdHost FtpdAddr MaxPasvPort MinPasvPort DataSock

    # Check for EOF and close connections if necessary

    if {[gets $fromSock line] < 0} {
	close $fromSock
	close $toSock
    } {
	# Make sure we do not show passwords in verbose output

	if {[string match "PASS *" $line]} {
	    log "$fromSock -> $toSock: PASS <password>"
	} {
	    log "$fromSock -> $toSock: $line"
	}

	# Re-write PORT command lines from the client.

	if {[regexp -nocase {^PORT ([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)} $line dummy a1 a2 a3 a4 p1 p2]} {
	    log "$fromSock -> $toSock: Rewriting $line"

	    set clientAddr "$a1.$a2.$a3.$a4"
	    set clientPort [expr {$p1 * 256 + $p2}]
	    set handler [list acceptDataConn [list $FtpdAddr 127.0.0.1] $clientAddr $clientPort]

	    if {[catch {createDataConn $handler 1024 65535} connInfo]} {
		close $fromSock
		close $toSock
		log "$fromSock -> $toSock: Error creating data connection: $connInfo"
		return
	    }

	    # Note the socket handle used for this address/port combination
	    # so that we can close it after a connection has been accepted.

	    set DataSock($clientAddr,$clientPort) [lindex $connInfo 0]

	    # Construct new PORT command referring to the new local
	    # data socket.

	    set port [lindex $connInfo 1]
	    set port [expr {$port / 256}],[expr {$port % 256}]

	    # If the ftpd is running locally then we need to supply
	    # the localhost address otherwise the full machine IP
	    # address is needed for the data connection to appear to
	    # come from the same place as the control connection.

	    if {$FtpdAddr == "127.0.0.1"} {
		set myAddr "127.0.0.1"
	    } {
		set myAddr $HostAddr
	    }
	    set myAddr [join [split $myAddr .] ,]

	    set line "PORT $myAddr,$port"

	    log "$fromSock -> $toSock: Rewritten to $line"
	}

	# Rewrite passive mode lines response lines from server

	if {[regexp {^227 .*[^0-9]([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)} $line dummy a1 a2 a3 a4 p1 p2]} {
	    log "$fromSock -> $toSock: Rewriting $line"

	    set serverAddr "$a1.$a2.$a3.$a4"
	    set serverPort [expr {$p1 * 256 + $p2}]

	    if {$MinPasvPort} {
		set allowed 127.0.0.1
	    } {
		set allowed {}
	    }
	    set handler [list acceptDataConn $allowed $serverAddr $serverPort]

	    if {[catch {createDataConn $handler $MinPasvPort $MaxPasvPort} connInfo]} {
		close $fromSock
		close $toSock
		log "$fromSock -> $toSock: Error creating data connection: $connInfo"
		return
	    }

	    # Note the socket handle used for this address/port combination
	    # so that we can close it after a connection has been accepted.

	    set DataSock($serverAddr,$serverPort) [lindex $connInfo 0]

	    # Construct a 227 response line referring to the new local
	    # data socket.

	    set port [lindex $connInfo 1]
	    set port [expr {$port / 256}],[expr {$port % 256}]

	    # If a port range has been specified then we must only supply
	    # the localhost address because this is being used for
	    # tunnelling and for this to work the client must connect to
	    # its matching local port.

	    if {$MinPasvPort} {
		set myAddr "127.0.0.1"
	    } {
		set myAddr $HostAddr
	    }
	    set myAddr [join [split $myAddr .] ,]
	    set line "227 Entering Passive Mode ($myAddr,$port)"

	    log "$fromSock -> $toSock: Rewritten to $line"
	}

	puts $toSock $line
	flush $toSock
    }
}

# createDataConn
#
# Create a new data connection listener socket with handler command "cmd".
# The function returns the port number. The "loPort" and "hiPort" parameters
# give the range in which the port should lie. If loPort is zero then any
# port (>= 1024) is acceptable. Within the range we try to pick a port at
# random (sort of :-) to avoid the worst excesses of passive port stealing.
#
# Returns a list of the socket handle and port number

proc createDataConn {cmd loPort hiPort} {

    if {$loPort < 1024} {
	set loPort 1024
    }
    if {$hiPort > 65535 || $hiPort < 1024} {
	set hiPort 65535
    }

    set count [expr {$hiPort - $loPort + 1}]

    # Pick a random starting point

    set start [expr {int(rand() * $count)}]

    for {set i 0} {$i < $count} {incr i} {

	set port [expr {(($i + $start) % $count) + $loPort}]

	if {![catch {socket -server $cmd $port} sock]} {
	    break
	}
    }

    if {$i >= $count} {
	error "can't find free data port socket"
    }

    return [list $sock $port]
}

# acceptDataConn
#
# Accept a new data connection and set up forwarding data channel handlers
# (in binary data mode) to the address and port in toAddr/toPort. The
# connection will be rejected unless it comes from an address named in
# allowFrom, if set, to avoid port "theft".

proc acceptDataConn {allowFrom toAddr toPort mySock ipAddr port} {
    global DataSock

    log "$mySock: new data connection from $ipAddr/$port"

    if {$allowFrom != {} && [lsearch -exact $allowFrom $ipAddr] == -1} {
	log "$mySock: WARNING: rejected connection from $ipAddr"
	close $mySock
	return
    }

    # Once a data connection has been accepted we can close the listening
    # socket. It will only be used once.

    if {[info exists DataSock($toAddr,$toPort)]} {
	close $DataSock($toAddr,$toPort)
	unset DataSock($toAddr,$toPort)
    }

    # Open a connection to the real destination

    if {[catch {socket $toAddr $toPort} toSock]} {
	close $mySock
	error "can't make forwarding data connection to $toAddr/$toPort: $toSock"
    }

    log "$mySock: forwards to $toSock"

    # Make the channels handle binary data

    fconfigure $toSock -translation binary
    fconfigure $mySock -translation binary

    # Set up data transfer based on which end of the pipe becomes readable

    fileevent $mySock readable [list startCopy $mySock $toSock]
    fileevent $toSock readable [list startCopy $toSock $mySock]
}

# startCopy
#
# Set up fcopy to handle copying the data in the background from fromSock to
# toSock.

proc startCopy {fromSock toSock} {

    fileevent $toSock readable {}
    fileevent $fromSock readable {}

    log "$fromSock -> $toSock: starting data copy"
    fcopy $fromSock $toSock -command [list finishCopy $fromSock $toSock]
}

# finishCopy
#
# Handler routine for end of fcopy

proc finishCopy {fromSock toSock bytes {error {}}} {
    if {"$error" != {}} {
	log "$fromSock -> $toSock: error copying data: $error"
    }

    log "$fromSock -> $toSock: copy finished, $bytes bytes transferred"

    catch {
	close $fromSock
	close $toSock
    }
}

# bgerror
#
# Handle an error -- just print a message in verbose mode

proc bgerror {args} {
    log "ERROR: $args"
}

###
### Main Code
###

for {set i 0} {$i < [llength $argv]} {incr i} {
    switch -exact -- [lindex $argv $i] {
	{-v} {
	    incr Verbose
	}

	{-p} {
	    incr i
	    if {[scan [lindex $argv $i] "%hu-%hu" MinPasvPort MaxPasvPort] != 2} {
		error "$argv0: invalid range to -r: [lindex $argv $i]"
	    }
	    if {$MinPasvPort < 1024} {
		error "$argv0: minimum passive data port must be >= 1024"
	    }
	    if {$MinPasvPort > $MaxPasvPort} {
		error "$argv0: minimum passive data port must be <= maximum"
	    }
	}

	default {
	    break
	}
    }
}

set argv [lrange $argv $i end]

if {[lindex $argv 0] != {}} {
    set ListenPort [lindex $argv 0]
}
if {[lindex $argv 1] != {}} {
    set FtpdHost [lindex $argv 1]
}
if {[lindex $argv 2] != {}} {
    set FtpdPort [lindex $argv 2]
}

# Try connecting to the ftpd server both to validate the date and to
# get its IP address

log "Contacting FTP server on $FtpdHost/$FtpdPort"

if {[catch {socket $FtpdHost $FtpdPort} s]} {
    error "$argv0: can't contact FTP server on $FtpdHost/$FtdPort"
}
set FtpdAddr [lindex [fconfigure $s -peername] 0]
close $s

# Start the local listener

set Listener [socket -server acceptCtrlConn $ListenPort]

log "Listening on port $ListenPort"

# Get the local IP address. We do this by making a connection to the
# port we have just set up for listening and then using fconfigure. Note
# that on Windows systems fconfigure can take an unexpectedly long time.

log "Determining the host address ..."

set s [socket [info hostname] $ListenPort]
set HostAddr [lindex [fconfigure $s -sockname] 0]
close $s

log "Host [info hostname], address $HostAddr"

# Enter the Tcl event loop ...

vwait forever
