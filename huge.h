/*
** huge.h
**
** Arbitrary precision integer library from Python sources.
**
** This is a minor modification of the file "huge-number.h" taken from
** mirrordir-0.10.49 which in turn contains these copyrights ...
**
** $Id: huge.h,v 1.1 2001-04-12 18:08:01 ndwinton Exp $
*/

/* huge-number.h: arbitrary precision integer library from Python sources
   This has nothing to do with cryptography.
   Copyright (C) 1998 Paul Sheer

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _HUGE_H
#define _HUGE_H

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
/* this gives a roughly a 7/4 speed increase with powmod() */
#define SHIFT	31
typedef unsigned int digit;
typedef unsigned int wdigit;	/* digit widened to parameter size */
typedef unsigned long long twodigits;
typedef long long stwodigits;	/* signed variant of twodigits */
#else
#define SHIFT	15
typedef unsigned short digit;
typedef unsigned int wdigit;
typedef unsigned long twodigits;
typedef long stwodigits;
#endif

#define BASE	((digit)1 << SHIFT)
#define MASK	((int)(BASE - 1))

typedef struct huge_number {
    long size;			/* ob_size */
    digit *d;			/* ob_digit */
} Huge;

/* we want to wipe as we go along, so that secret keys cannot be read from memory: */
#define huge_free(x)					\
    {							\
	if (x) {					\
	    memset (x, 0, sizeof (Huge) + 		\
		    sizeof (digit) * (((x)->size) >= 0 ? ((x)->size) : -((x)->size)));	\
	    free (x);					\
	}						\
	(x) = 0;					\
    }

/* management */
Huge *huge_new (int size);
void huge_copy (Huge * a, Huge * b);
Huge *huge_dup (Huge * a);
/* void huge_free (Huge *a); */

/* type conversion */
Huge *huge_from_string (char *str, char **pend, int base);
Huge *huge_from_long (long ival);
Huge *huge_from_unsigned_long (unsigned long ival);
long huge_as_long (Huge * v);
unsigned long huge_as_unsigned_long (Huge * v);

/* bit manipulation */
Huge *huge_set_bit (Huge * v, int i);
void huge_clear_bit (Huge * v, int i);

/* octet stream */
Huge *huge_from_binary (unsigned char *s, int l);
char *huge_as_binary (Huge * a, int *l);

/* formatting */
char *huge_format (Huge * a, int base);
char *huge_oct (Huge * v);
char *huge_hex (Huge * v);
char *huge_dec (Huge * v);

/* comparison */
int huge_compare (Huge * a, Huge * b);
int huge_nonzero (Huge * v);

/* arithmetic */
Huge *huge_add (Huge * a, Huge * b);
Huge *huge_sub (Huge * a, Huge * b);
Huge *huge_mul (Huge * a, Huge * b);
Huge *huge_div (Huge * v, Huge * w);
Huge *huge_mod (Huge * v, Huge * w);
Huge *huge_divmod (Huge * v, Huge * w, Huge ** remainder /* may be null */ );
Huge *huge_invert (Huge * v);

/* exponentiation */
Huge *huge_pow (Huge * a, Huge * b);
Huge *huge_powmod (Huge * a, Huge * b, Huge * c);

/* unary */
Huge *huge_neg (Huge * v);
Huge *huge_abs (Huge * v);

/* shifting */
Huge *huge_rshift (Huge * a, int shiftby);
Huge *huge_lshift (Huge * a, int shiftby);

/* logical */
Huge *huge_and (Huge * a, Huge * b);
Huge *huge_xor (Huge * a, Huge * b);
Huge *huge_or (Huge * a, Huge * b);

/* log */
/* #define huge_log(x,y) xhuge_log(x,y,__FILE__,__LINE__) */
#define huge_log(x,y) 
void xhuge_log(Huge *h, char *msg, char *file, int line);

#endif				/* ! _HUGE_H */


