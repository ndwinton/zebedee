#!/usr/bin/wish -f
#
# Simple passphrase-to-key generator for Zebedee.
#
# This can be invoked from Zebedee by using the "keygencommand" keyword.
# When invoked with no additional arguments it will prompt for a passphrase
# and output a key derived from it to standard output. If an argument is
# specified it must be the name of a supplementary key data file. The script
# will read the first line from this file and add this to the passphrase
# before generating the key.
#
#
# This file is part of "Zebedee".
#
# Copyright 2001, 2002 by Neil Winton. All rights reserved.
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
# For further details on "Zebedee" see http://www.winton.org.uk/zebedee/
#
# $Id: passphrase.tcl,v 1.1 2002-05-07 08:28:10 ndwinton Exp $

# The SHA1 hash generation code was derived from code containing the
# following attribution. Note that there is a slight modification for
# Zebedee compatibility (the "PreNIST" option).
#
##################################################
#
# sha1.tcl - SHA1 in Tcl
# Author: Don Libes <libes@nist.gov>, May 2001
# Version 1.0.0
#
# SHA1 defined by FIPS 180-1, "The SHA1 Message-Digest Algorithm",
#          http://www.itl.nist.gov/fipspubs/fip180-1.htm
# HMAC defined by RFC 2104, "Keyed-Hashing for Message Authentication"
#
# Some of the comments below come right out of FIPS 180-1; That's why
# they have such peculiar numbers.  In addition, I have retained
# original syntax, etc. from the FIPS.  All remaining bugs are mine.
#
# HMAC implementation by D. J. Hagberg <dhagberg@millibits.com> and
# is based on C code in FIPS 2104.
#
# For more info, see: http://expect.nist.gov/sha1pure
#
# - Don
##################################################

namespace eval sha1pure {
    variable i
    variable j
    variable t
    variable K
    variable PreNIST

    set j 0
    foreach t {
	0x5A827999
	0x6ED9EBA1
	0x8F1BBCDC
	0xCA62C1D6
    } {
	for {set i 0} {$i < 20} {incr i; incr j} {
	    set K($j) $t
	}
    }

    # Set this true for compatibility with the original version on SHA1
    # prior to modification by NIST for the final standard. This is,
    # unfortunately, the version used by Zebedee 2.x ...

    set PreNIST true
}

proc sha1pure::sha1 {msg} {
    variable K
    variable PreNIST

    #
    # 4. MESSAGE PADDING
    #

    # pad to 512 bits (512/8 = 64 bytes)

    set msgLen [string length $msg]

    # last 8 bytes are reserved for msgLen
    # plus 1 for "1"

    set padLen [expr {56 - $msgLen%64}]
    if {$msgLen % 64 >= 56} {
	incr padLen 64
    }

    # 4a. and b. append single 1b followed by 0b's
    append msg [binary format "a$padLen" \200]

    # 4c. append 64-bit length
    # Our implementation obviously limits string length to 32bits.
    append msg \0\0\0\0[binary format "I" [expr {8*$msgLen}]]
    
    #
    # 7. COMPUTING THE MESSAGE DIGEST
    #

    # initial H buffer

    set i 0
    foreach t {
	0x67452301
	0xEFCDAB89
	0x98BADCFE
	0x10325476
	0xC3D2E1F0
    } {
	set H($i) [expr $t]
	incr i
    }

    #
    # process message in 16-word blocks (64-byte blocks)
    #

    # convert message to array of 32-bit integers
    # each block of 16-words is stored in M($i,0-16)

    binary scan $msg I* words
    set i 1
    set j 0
    foreach w $words {
	lappend M($i) $w
	if {[incr j] == 16} {
	    incr i
	    set j 0
	}
    }

    set blockLen [expr {$i-1}]

    for {set i 1} {$i <= $blockLen} {incr i} {
	    # 7a. Divide M[i] into 16 words W[0], W[1], ...
	    set t 0
	    foreach m $M($i) {
		set W($t) $m
		incr t
	    }

	    # 7b. For t = 16 to 79 let W[t] = ....
	    set t   16
	    set t3  12
	    set t8   7
	    set t14  1
	    set t16 -1
	    for {} {$t < 80} {incr t} {
		set x [expr {$W([incr t3]) ^ $W([incr t8]) ^ $W([incr t14]) ^ $W([incr t16])}]
		if {$PreNIST} {
		    set W($t) $x
		} {
		    set W($t) [expr {($x << 1) | (($x >> 31) & 1)}]
		}
	    }

	    # 7c. Let A = H[0] ....
	    set A $H(0)
	    set B $H(1)
	    set C $H(2)
	    set D $H(3)
	    set E $H(4)

	    # 7d. For t = 0 to 79 do
	    for {set t 0} {$t < 80} {incr t} {
		set TEMP [expr {(($A << 5) | (($A >> 27) & 0x1f)) + [f $t $B $C $D] + $E + $W($t) + $K($t)}]
		set E $D
		set D $C
		set C [expr {($B << 30) | (($B >> 2) & 0x3fffffff)}]
		set B $A
		set A $TEMP
	    }

	    incr H(0) $A
	    incr H(1) $B
	    incr H(2) $C
	    incr H(3) $D
	    incr H(4) $E
    }
    return [bytes $H(0)][bytes $H(1)][bytes $H(2)][bytes $H(3)][bytes $H(4)]
}

proc sha1pure::f {t B C D} {
    switch [expr {$t/20}] {
	0 {
	    expr {($B & $C) | ((~$B) & $D)}
	} 1 - 3 {
	    expr {$B ^ $C ^ $D}
	} 2 {
	    expr {($B & $C) | ($B & $D) | ($C & $D)}
	}
    }
}

proc sha1pure::byte0 {i} {expr {0xff & $i}}
proc sha1pure::byte1 {i} {expr {(0xff00 & $i) >> 8}}
proc sha1pure::byte2 {i} {expr {(0xff0000 & $i) >> 16}}
proc sha1pure::byte3 {i} {expr {((0xff000000 & $i) >> 24) & 0xff}}

proc sha1pure::bytes {i} {
    format %0.2x%0.2x%0.2x%0.2x [byte3 $i] [byte2 $i] [byte1 $i] [byte0 $i]
}

### End of SHA1 code

# The main program starts here ...

# If an additional file has been mentioned on the command line
# the read the first line from this and stash it in FileKey.

set FileKey {}

if {[lindex $argv 0] != {}} {
    if {[catch {open [lindex $argv 0]} fh]} {
	wm withdraw .
	tk_messageBox -icon error -type ok -title Error -message "Can't open supplementary key data file [lindex $argv 0]:\n$fh"
	destroy .
	exit 1
    }

    catch {
	set FileKey [gets $fh]
	close $fh
    }
}

# Create the basic dialogue entry box

frame .f
label .f.label -text "Enter Pass Phrase:"

entry .f.entry -width 30 -relief sunken -textvariable PassPhrase -show {*}

button .finish -text " OK " -command {
    puts [sha1pure::sha1 "$PassPhrase$FileKey"]
    flush stdout
    destroy .
}

# Pack all the elements for display

pack .f.label -side left -expand no -fill x -padx 5
pack .f.entry -side right -expand yes -fill x -padx 5
pack .f -side top -expand yes -fill both -pady 5
pack .finish -side bottom -anchor e -pady 5 -padx 10

bind . <Return> {.finish invoke}

# Calculate location of top left corner of box necessary to place
# it in the middle of the screen.

set xRoot [expr {[winfo screenwidth .]/2 - [winfo reqwidth .]/2}]
set yRoot [expr {[winfo screenheight .]/2 - [winfo reqheight .]/2}]

wm geometry . +$xRoot+$yRoot
wm title . "Zebedee Key Generator"

# Put the window to the top, focus on it and grab all mouse events.

raise .
grab -global .
focus .f.entry
