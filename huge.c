/*
** huge.c
**
** Arbitrary precision integer library from Python sources.
**
** This is a minor modification of the file "huge-number.c" taken from
** mirrordir-0.10.49 which in turn contains these copyrights ...
**
** $Id: huge.c,v 1.1 2001-04-12 18:08:01 ndwinton Exp $
*/

/* huge-number.c: arbitrary precision integer library from Python sources
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

/* This file was taken from the Python source for `long' type
   integers. I have changed it to compile independently of the
   Python source, and added the optimisation that GNU C can
   use 31 bit digits instead of Python's 15 bit. You can download
   the original from www.python.org. This file bears little
   resemblance to the original though - paul */

/***********************************************************
Copyright 1991-1995 by Stichting Mathematisch Centrum, Amsterdam,
The Netherlands.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the names of Stichting Mathematisch
Centrum or CWI or Corporation for National Research Initiatives or
CNRI not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

While CWI is the initial source for this software, a modified version
is made available by the Corporation for National Research Initiatives
(CNRI) at the Internet address ftp://ftp.python.org.

STICHTING MATHEMATISCH CENTRUM AND CNRI DISCLAIM ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH
CENTRUM OR CNRI BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

******************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "huge.h"

#undef ABS
#undef MAX
#undef MIN
#define ABS(x) ((x) >= 0 ? (x) : -(x))
#define MAX(x, y) ((x) < (y) ? (y) : (x))
#define MIN(x, y) ((x) > (y) ? (y) : (x))

#define ob_size size
#define ob_digit d

#ifdef __GNUC__
#define huge_assert(x) { if (!(x)) { fprintf (stderr, "huge: assertion failed, %s:%d\n", __FILE__, __LINE__); abort(); } }
#else
#define huge_assert(x) { if (!(x)) abort(); }
#endif

static Huge *huge_normalize (Huge *);
static Huge *mul1 (Huge *, wdigit);
static Huge *muladd1 (Huge *, wdigit, wdigit);
static Huge *divrem1 (Huge *, wdigit, digit *);
static Huge *x_divrem (Huge * v1, Huge * w1, Huge ** prem);

#define huge_error(x) fprintf (stderr, "huge_%s\n", x)

/* Normalize (remove leading zeros from) a long int object.
   Doesn't attempt to free the storage--in most cases, due to the nature
   of the algorithms used, this could save at most be one word anyway. */

static Huge *huge_normalize (Huge * v)
{
    int j = ABS (v->ob_size);
    int i = j;

    while (i > 0 && v->ob_digit[i - 1] == 0)
	--i;
    if (i != j)
	v->ob_size = (v->ob_size < 0) ? -(i) : i;
    return v;
}

Huge *huge_new (int size)
{
    Huge *h;
    char *x;
    h = malloc (sizeof (Huge) + size * sizeof (digit));
    x = (char *) h;
    x += sizeof (Huge);
    h->d = (digit *) x;
    h->size = size;
    memset (h->d, 0, size * sizeof (digit));
    return h;
}

void huge_copy (Huge * a, Huge * b)
{
    int i;
    for (i = 0; i < ABS (b->size); i++)
	a->d[i] = b->d[i];
    a->size = b->size;
}

Huge *huge_dup (Huge * a)
{
    Huge *b;
    if (!a)
	return 0;
    b = huge_new (ABS (a->ob_size));
    huge_copy (b, a);
    return b;
}

/* Create a new long int object from a C long int */

Huge *huge_from_long (long ival)
{
    /* Assume a C long fits in at most 5 'digits' */
    /* Works on both 32- and 64-bit machines */
    Huge *v = huge_new (5);
    unsigned long t = ival;
    int i;
    if (ival < 0) {
	t = -ival;
	v->ob_size = -(v->ob_size);
    }
    for (i = 0; i < 5; i++) {
	v->ob_digit[i] = (digit) (t & MASK);
	t >>= SHIFT;
    }
    return huge_normalize (v);
}

Huge *huge_set_bit (Huge * v, int i)
{
    Huge *w;
    w = huge_new (MAX (ABS (v->ob_size), i / SHIFT + 1));
    huge_copy (w, v);
    w->d[i / SHIFT] |= (1 << (i % SHIFT));
    return w;
}

void huge_clear_bit (Huge * v, int i)
{
    if (i / SHIFT < ABS (v->ob_size))
	v->d[i / SHIFT] &= ~(1 << (i % SHIFT));
    huge_normalize (v);
}

static inline unsigned char _huge_get_char (Huge * a, int j)
{
    twodigits r = 0;
    int i;
    i = j * 8 / SHIFT;
    if (i < a->size) {
	r = a->d[i];
	if (++i < a->size)
	    r |= (twodigits) a->d[i] << SHIFT;
    }
    r >>= ((j * 8) % SHIFT);
    return r & 0xFF;
}

/* result must be free'd */
char *huge_as_binary (Huge * a, int *l)
{
    char *s;
    int i;
    *l = (a->size * SHIFT) / 8 + 1;
    s = malloc (*l + 1);
    for (i = 0; i < *l; i++)
	s[i] = _huge_get_char (a, i);
    while (*l > 0 && !s[*l - 1])
	(*l)--;
    return s;
}

/* result must be free'd */
Huge *huge_from_binary (unsigned char *s, int n)
{
    Huge *z;
    int i, size;
    digit *d;
    size = n * 8 / SHIFT;
    z = huge_new (size + 1);
    d = z->d;
    for (i = 0; i < size + 1; i++) {
	int j;
	twodigits t = 0;
	int r;
	r = i * SHIFT / 8;
	for (j = 0; j < SHIFT / 8 + 3 && r < n; j++, r++)
	    t |= (twodigits) s[r] << (j * 8);
	t >>= ((i * SHIFT) % 8);
	*d++ = (digit) t & MASK;
    }
    return huge_normalize (z);
}

/* Create a new long int object from a C unsigned long int */

Huge *huge_from_unsigned_long (unsigned long ival)
{
    unsigned long t = ival;
    int i;
    /* Assume a C long fits in at most 5 'digits' */
    /* Works on both 32- and 64-bit machines */
    Huge *v = huge_new (5);
    for (i = 0; i < 5; i++) {
	v->ob_digit[i] = (digit) (t & MASK);
	t >>= SHIFT;
    }
    return huge_normalize (v);
}

/* Get a C long int from a long int object.
   Returns -1 and sets an error condition if overflow occurs. */

long huge_as_long (Huge * v)
{
    long x, prev;
    int i, sign;

    i = v->ob_size;
    sign = 1;
    x = 0;
    if (i < 0) {
	sign = -1;
	i = -(i);
    }
    while (--i >= 0) {
	prev = x;
	x = (x << SHIFT) + v->ob_digit[i];
	if ((x >> SHIFT) != prev) {
	    huge_error ("as_long(): long int too long to convert");
	    return -1;
	}
    }
    return x * sign;
}

/* Get a C long int from a long int object.
   Returns -1 and sets an error condition if overflow occurs. */

unsigned long huge_as_unsigned_long (Huge * v)
{
    unsigned long x, prev;
    int i;

    i = v->ob_size;
    x = 0;
    if (i < 0) {
	huge_error ("as_unsigned_long(): can't convert negative value to unsigned long");
	return (unsigned long) -1;
    }
    while (--i >= 0) {
	prev = x;
	x = (x << SHIFT) + v->ob_digit[i];
	if ((x >> SHIFT) != prev) {
	    huge_error ("as_unsigned_long(): long int too long to convert");
	    return (unsigned long) -1;
	}
    }
    return x;
}

/* Get a C double from a long int object. */


/* Multiply by a single digit, ignoring the sign. */

static Huge *mul1 (Huge * a, wdigit n)
{
    return muladd1 (a, n, (digit) 0);
}

/*
 *    gcc knows about 64bit product, so no optimisation needed:
 *
 *      pushl -8(%ebp)
 *      pushl $.LC2
 *      call printf
 *.stabn 68,0,47,.LM64-huge_from_long
 *.LM64:
 *      pushl %edi
 *      pushl $.LC2
 *      call printf
 *.stabn 68,0,48,.LM65-huge_from_long
 *.LM65:
 *      movl -8(%ebp),%eax
 *      imull %edi
 *      movl %eax,-16(%ebp)
 *      movl %edx,-12(%ebp)
 *.stabn 68,0,49,.LM66-huge_from_long
 *.LM66:
 *      pushl -12(%ebp)
 *      pushl -16(%ebp)
 *      pushl $.LC2
 *      call printf
 */

static Huge *muladd1 (Huge * a, wdigit n, wdigit extra)
{
    int size_a = ABS (a->ob_size);
    Huge *z = huge_new (size_a + 1);
    twodigits carry = extra;
    int i;
    for (i = 0; i < size_a; ++i) {
	carry += (twodigits) a->ob_digit[i] * n;
	z->ob_digit[i] = (digit) (carry & MASK);
	carry >>= SHIFT;
    }
    z->ob_digit[i] = (digit) carry;
    return huge_normalize (z);
}

/* Divide a long integer by a digit, returning both the quotient
   (as function result) and the remainder (through *prem).
   The sign of a is ignored; n should not be zero. */

static Huge *divrem1 (Huge * a, wdigit n, digit * prem)
{
    int size = ABS (a->ob_size);
    Huge *z;
    int i;
    twodigits rem = 0;

    huge_assert (n > 0 && n <= MASK);
    z = huge_new (size);
    for (i = size; --i >= 0;) {
	rem = (rem << SHIFT) + a->ob_digit[i];
	z->ob_digit[i] = (digit) (rem / n);
	rem %= n;
    }
    *prem = (digit) rem;
    return huge_normalize (z);
}

/* Convert a long int object to a string, using a given conversion base.
   Return a string object.

   NDW: The following does not apply here ....
   If base is 8 or 16, add the proper prefix '0' or '0x'.
   External linkage: used in bltinmodule.c by hex() and oct(). */

char *huge_format (Huge * a, int base)
{
    char *str;
    int i;
    int size_a = ABS (a->ob_size);
    char *p;
    int bits;
    char sign = '\0';

    a = huge_dup (a);
    huge_assert (base >= 2 && base <= 36);

    /* Compute a rough upper bound for the length of the string */
    i = base;
    bits = 0;
    while (i > 1) {
	++bits;
	i >>= 1;
    }
    i = 6 + (size_a * SHIFT + bits - 1) / bits;
    str = malloc (i + 1);
    p = str + i;
    *p = '\0';
#ifdef ORIGINAL_BEHAVIOUR
    *--p = 'L';
#endif
    if (a->ob_size < 0) {
	sign = '-';
	a->ob_size = ABS (a->ob_size);
    }

    do {
	digit rem;
	Huge *temp = divrem1 (a, (digit) base, &rem);
	if (temp == 0) {
	    huge_free (a);
	    free (str);
	    return 0;
	}
	if (rem < 10)
	    rem += '0';
	else
	    rem += 'a' - 10;
	huge_assert (p > str);
	*--p = (char) rem;
	huge_free (a);
	a = temp;
    } while (ABS (a->ob_size) != 0);
    huge_free (a);
#ifdef ORIGINAL_BEHAVIOUR
    /* NDW -- removed this for GMP compatibility */
    if (base == 8) {
	if (size_a != 0)
	    *--p = '0';
    } else if (base == 16) {
	*--p = 'x';
	*--p = '0';
    } else if (base != 10) {
	*--p = '#';
	*--p = '0' + base % 10;
	if (base > 10)
	    *--p = '0' + base / 10;
    }
#endif
    if (sign)
	*--p = sign;
    if (p != str) {
	char *q = str;
	huge_assert (p > q);
	do {
	} while ((*q++ = *p++) != '\0');
	q--;
    }
    return str;
}

Huge *huge_from_string (char *str, char **pend, int base)
{
    int sign = 1;
    Huge *z;

    while (*str != '\0' && strchr ("\t\n ", *str))
	str++;
    if (*str == '+')
	++str;
    else if (*str == '-') {
	++str;
	sign = -1;
    }
    while (*str != '\0' && strchr ("\t\n ", *str))
	str++;
    if (base == 0) {
	if (str[0] != '0')
	    base = 10;
	else if (str[1] == 'x' || str[1] == 'X')
	    base = 16;
	else
	    base = 8;
    }
    if (base == 16 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	str += 2;
    z = huge_new (0);
    for (; z != 0; ++str) {
	int k = -1;
	Huge *temp;

	if (*str <= '9')
	    k = *str - '0';
	else if (*str >= 'a')
	    k = *str - 'a' + 10;
	else if (*str >= 'A')
	    k = *str - 'A' + 10;
	if (k < 0 || k >= base)
	    break;
	temp = muladd1 (z, (digit) base, (digit) k);
	huge_free (z);
	z = temp;
    }
    if (sign < 0 && z != 0 && z->ob_size != 0)
	z->ob_size = -(z->ob_size);
    if (pend)
	*pend = str;
    return huge_normalize (z);
}

/* Long division with remainder, top-level routine */

static int _huge_divrem (Huge * a, Huge * b, Huge ** pdiv, Huge ** prem)
{
    int size_a = ABS (a->ob_size), size_b = ABS (b->ob_size);
    Huge *z;

    if (!size_b)
	huge_error ("divrem(): divide by zero");
    if (size_a < size_b ||
	(size_a == size_b &&
	 a->ob_digit[size_a - 1] < b->ob_digit[size_b - 1])) {
	/* |a| < |b|. */
	*pdiv = huge_new (0);
	*prem = huge_dup (a);
	return 0;
    }
    if (size_b == 1) {
	digit rem = 0;
	z = divrem1 (a, b->ob_digit[0], &rem);
	if (z == 0)
	    return -1;
	*prem = huge_from_long ((long) rem);
    } else {
	z = x_divrem (a, b, prem);
	if (z == 0)
	    return -1;
    }
    /* Set the signs.
       The quotient z has the sign of a*b;
       the remainder r has the sign of a,
       so a = b*z + r. */
    if ((a->ob_size < 0) != (b->ob_size < 0))
	z->ob_size = -(z->ob_size);
    if (a->ob_size < 0 && (*prem)->ob_size != 0)
	(*prem)->ob_size = -((*prem)->ob_size);
    *pdiv = z;
    return 0;
}

/* Unsigned long division with remainder -- the algorithm */

static Huge *x_divrem (Huge * v1, Huge * w1, Huge ** prem)
{
    int size_v = ABS (v1->ob_size), size_w = ABS (w1->ob_size);
    digit d = (digit) ((twodigits) BASE / (w1->ob_digit[size_w - 1] + 1));
    Huge *v = mul1 (v1, d);
    Huge *w = mul1 (w1, d);
    Huge *a;
    int j, k;

    if (v == 0 || w == 0) {
	huge_free (v);
	huge_free (w);
	return 0;
    }
    huge_assert (size_v >= size_w && size_w > 1);	/* Assert checks by div() */
    huge_assert (size_w == ABS (w->ob_size));	/* That's how d was calculated */

    size_v = ABS (v->ob_size);
    a = huge_new (size_v - size_w + 1);

    for (j = size_v, k = a->ob_size - 1; a != 0 && k >= 0; --j, --k) {
	digit vj = (j >= size_v) ? 0 : v->ob_digit[j];
	twodigits q;
	stwodigits carry = 0;
	int i;

	if (vj == w->ob_digit[size_w - 1])
	    q = MASK;
	else
	    q = (((twodigits) vj << SHIFT) + v->ob_digit[j - 1]) /
		w->ob_digit[size_w - 1];

	while (w->ob_digit[size_w - 2] * q >
	       ((
		    ((twodigits) vj << SHIFT)
		    + v->ob_digit[j - 1]
		    - q * w->ob_digit[size_w - 1]
		) << SHIFT)
	       + v->ob_digit[j - 2])
	    --q;

	for (i = 0; i < size_w && i + k < size_v; ++i) {
	    twodigits z = w->ob_digit[i] * q;
	    digit zz = (digit) (z >> SHIFT);
	    carry += v->ob_digit[i + k] - z
		+ ((twodigits) zz << SHIFT);
	    v->ob_digit[i + k] = carry & MASK;
	    carry = (carry >> SHIFT) - zz;
	}

	if (i + k < size_v) {
	    carry += v->ob_digit[i + k];
	    v->ob_digit[i + k] = 0;
	}
	if (carry == 0)
	    a->ob_digit[k] = (digit) q;
	else {
	    huge_assert (carry == -1);
	    a->ob_digit[k] = (digit) q - 1;
	    carry = 0;
	    for (i = 0; i < size_w && i + k < size_v; ++i) {
		carry += v->ob_digit[i + k] + w->ob_digit[i];
		v->ob_digit[i + k] = carry & MASK;
		carry >>= SHIFT;
	    }
	}
    }				/* for j, k */

    if (a == 0)
	*prem = 0;
    else {
	a = huge_normalize (a);
	*prem = divrem1 (v, d, &d);
	/* d receives the (unused) remainder */
	if (*prem == 0) {
	    huge_free (a);
	    a = 0;
	}
    }
    huge_free (v);
    huge_free (w);
    return a;
}

int huge_compare (Huge * a, Huge * b)
{
    int sign;

    if (a->ob_size != b->ob_size) {
	if (ABS (a->ob_size) == 0 && ABS (b->ob_size) == 0)
	    sign = 0;
	else
	    sign = a->ob_size - b->ob_size;
    } else {
	int i = ABS (a->ob_size);
	while (--i >= 0 && a->ob_digit[i] == b->ob_digit[i]);
	if (i < 0)
	    sign = 0;
	else {
	    sign = (int) a->ob_digit[i] - (int) b->ob_digit[i];
	    if (a->ob_size < 0)
		sign = -sign;
	}
    }
    return sign < 0 ? -1 : sign > 0 ? 1 : 0;
}

/* Add the absolute values of two long integers. */

static Huge *x_add (Huge * a, Huge * b)
{
    int size_a = ABS (a->ob_size), size_b = ABS (b->ob_size);
    Huge *z;
    int i;
    digit carry = 0;

    /* Ensure a is the larger of the two: */
    if (size_a < size_b) {
	{
	    Huge *temp = a;
	    a = b;
	    b = temp;
	}
	{
	    int size_temp = size_a;
	    size_a = size_b;
	    size_b = size_temp;
	}
    }
    z = huge_new (size_a + 1);
    for (i = 0; i < size_b; ++i) {
	carry += a->ob_digit[i] + b->ob_digit[i];
	z->ob_digit[i] = carry & MASK;
	/* The following assumes unsigned shifts don't
	   propagate the sign bit. */
	carry >>= SHIFT;
    }
    for (; i < size_a; ++i) {
	carry += a->ob_digit[i];
	z->ob_digit[i] = carry & MASK;
	carry >>= SHIFT;
    }
    z->ob_digit[i] = carry;
    return huge_normalize (z);
}

/* Subtract the absolute values of two integers. */

static Huge *x_sub (Huge * a, Huge * b)
{
    int size_a = ABS (a->ob_size), size_b = ABS (b->ob_size);
    Huge *z;
    int i;
    int sign = 1;
    digit borrow = 0;

    /* Ensure a is the larger of the two: */
    if (size_a < size_b) {
	sign = -1;
	{
	    Huge *temp = a;
	    a = b;
	    b = temp;
	}
	{
	    int size_temp = size_a;
	    size_a = size_b;
	    size_b = size_temp;
	}
    } else if (size_a == size_b) {
	/* Find highest digit where a and b differ: */
	i = size_a;
	while (--i >= 0 && a->ob_digit[i] == b->ob_digit[i]);
	if (i < 0)
	    return huge_new (0);
	if (a->ob_digit[i] < b->ob_digit[i]) {
	    sign = -1;
	    {
		Huge *temp = a;
		a = b;
		b = temp;
	    }
	}
	size_a = size_b = i + 1;
    }
    z = huge_new (size_a);
    for (i = 0; i < size_b; ++i) {
	/* The following assumes unsigned arithmetic
	   works module 2**N for some N>SHIFT. */
	borrow = a->ob_digit[i] - b->ob_digit[i] - borrow;
	z->ob_digit[i] = borrow & MASK;
	borrow >>= SHIFT;
	borrow &= 1;		/* Keep only one sign bit */
    }
    for (; i < size_a; ++i) {
	borrow = a->ob_digit[i] - borrow;
	z->ob_digit[i] = borrow & MASK;
	borrow >>= SHIFT;
    }
    huge_assert (borrow == 0);
    if (sign < 0)
	z->ob_size = -(z->ob_size);
    return huge_normalize (z);
}

Huge *huge_add (Huge * a, Huge * b)
{
    Huge *z;

    if (a->ob_size < 0) {
	if (b->ob_size < 0) {
	    z = x_add (a, b);
	    if (z != 0 && z->ob_size != 0)
		z->ob_size = -(z->ob_size);
	} else
	    z = x_sub (b, a);
    } else {
	if (b->ob_size < 0)
	    z = x_sub (a, b);
	else
	    z = x_add (a, b);
    }
    return (Huge *) z;
}

Huge *huge_sub (Huge * a, Huge * b)
{
    Huge *z;

    if (a->ob_size < 0) {
	if (b->ob_size < 0)
	    z = x_sub (a, b);
	else
	    z = x_add (a, b);
	if (z != 0 && z->ob_size != 0)
	    z->ob_size = -(z->ob_size);
    } else {
	if (b->ob_size < 0)
	    z = x_add (a, b);
	else
	    z = x_sub (a, b);
    }
    return (Huge *) z;
}

Huge *huge_mul (Huge * a, Huge * b)
{
    int size_a;
    int size_b;
    Huge *z;
    int i;

    size_a = ABS (a->ob_size);
    size_b = ABS (b->ob_size);
    z = huge_new (size_a + size_b);
    for (i = 0; i < z->ob_size; ++i)
	z->ob_digit[i] = 0;
    for (i = 0; i < size_a; ++i) {
	twodigits carry = 0;
	twodigits f = a->ob_digit[i];
	int j;
	for (j = 0; j < size_b; ++j) {
	    carry += z->ob_digit[i + j] + b->ob_digit[j] * f;
	    z->ob_digit[i + j] = (digit) (carry & MASK);
	    carry >>= SHIFT;
	}
	for (; carry != 0; ++j) {
	    huge_assert (i + j < z->ob_size);
	    carry += z->ob_digit[i + j];
	    z->ob_digit[i + j] = (digit) (carry & MASK);
	    carry >>= SHIFT;
	}
    }
    if (a->ob_size < 0)
	z->ob_size = -(z->ob_size);
    if (b->ob_size < 0)
	z->ob_size = -(z->ob_size);
    return (Huge *) huge_normalize (z);
}

/* The / and % operators are now defined in terms of divmod().
   The expression a mod b has the value a - b*floor(a/b).
   The huge_divrem function gives the remainder after division of
   |a| by |b|, with the sign of a.  This is also expressed
   as a - b*trunc(a/b), if trunc truncates towards zero.
   Some examples:
   a     b      a rem b         a mod b
   13    10      3               3
   -13   10     -3               7
   13   -10      3              -7
   -13  -10     -3              -3
   So, to get from rem to mod, we have to add b if a and b
   have different signs.  We then subtract one from the 'divisor'
   part of the outcome to keep the invariant intact. */

static int l_divmod (Huge * v, Huge * w, Huge ** pdiv, Huge ** pmod)
{
    Huge *divisor, *mod;

    if (_huge_divrem (v, w, &divisor, &mod) < 0)
	return -1;
    if ((mod->ob_size < 0 && w->ob_size > 0) ||
	(mod->ob_size > 0 && w->ob_size < 0)) {
	Huge *temp;
	Huge *one;
	temp = (Huge *) huge_add (mod, w);
	huge_free (mod);
	mod = temp;
	if (mod == 0) {
	    huge_free (divisor);
	    return -1;
	}
	one = huge_from_long (1L);
	if ((temp = (Huge *) huge_sub (divisor, one)) == 0) {
	    huge_free (mod);
	    huge_free (divisor);
	    huge_free (one);
	    return -1;
	}
	huge_free (one);
	huge_free (divisor);
	divisor = temp;
    }
    *pdiv = divisor;
    *pmod = mod;
    return 0;
}

Huge *huge_div (Huge * v, Huge * w)
{
    Huge *divisor, *mod;
    if (l_divmod (v, w, &divisor, &mod) < 0)
	return 0;
    huge_free (mod);
    return (Huge *) divisor;
}

Huge *huge_mod (Huge * v, Huge * w)
{
    Huge *divisor, *mod;
    if (l_divmod (v, w, &divisor, &mod) < 0)
	return 0;
    huge_free (divisor);
    return (Huge *) mod;
}

Huge *huge_divmod (Huge * v, Huge * w, Huge ** remainder)
{
    Huge *divisor, *mod;
    if (l_divmod (v, w, &divisor, &mod) < 0)
	return 0;
    if (remainder)
	*remainder = mod;
    return divisor;
}

Huge *huge_powmod (Huge * a, Huge * b, Huge * c)
{
    Huge *z = 0, *divisor = 0, *mod = 0;
    int size_b, i;

    a = huge_dup (a);
    size_b = b->ob_size;
    if (size_b < 0) {
	huge_error ("pow(): long integer to the negative power");
	return 0;
    }
    z = (Huge *) huge_from_long (1L);
    for (i = 0; i < size_b; ++i) {
	digit bi = b->ob_digit[i];
	int j;

	for (j = 0; j < SHIFT; ++j) {
	    Huge *temp = 0;

	    if (bi & 1) {
		temp = (Huge *) huge_mul (z, a);
		huge_free (z);
		if (c != 0 && temp != 0) {
		    l_divmod (temp, c, &divisor, &mod);
		    huge_free (divisor);
		    huge_free (temp);
		    temp = mod;
		}
		z = temp;
		if (z == 0)
		    break;
	    }
	    bi >>= 1;
	    if (bi == 0 && i + 1 == size_b)
		break;
	    temp = (Huge *) huge_mul (a, a);
	    huge_free (a);
	    if ((Huge *) c != 0 && temp != 0) {
		l_divmod (temp, c, &divisor, &mod);
		huge_free (divisor);
		huge_free (temp);
		temp = mod;
	    }
	    a = temp;
	    if (a == 0) {
		huge_free (z);
		z = 0;
		break;
	    }
	}
	if (a == 0 || z == 0)
	    break;
    }
    huge_free (a);
    if ((Huge *) c != 0 && z != 0) {
	l_divmod (z, c, &divisor, &mod);
	huge_free (divisor);
	huge_free (z);
	z = mod;
    }
    return (Huge *) z;
}

Huge *huge_pow (Huge * a, Huge * b)
{
    return huge_powmod (a, b, 0);
}

Huge *huge_invert (Huge * v)
{
    /* Implement ~x as -(x+1) */
    Huge *x;
    Huge *w;
    w = (Huge *) huge_from_long (1L);
    if (w == 0)
	return 0;
    x = (Huge *) huge_add (v, w);
    huge_free (w);
    if (x == 0)
	return 0;
    if (x->ob_size != 0)
	x->ob_size = -(x->ob_size);
    return (Huge *) x;
}

Huge *huge_neg (Huge * v)
{
    Huge *z;
    int i, n;
    n = ABS (v->ob_size);
    /* -0 == 0 */
    if (!n)
	return huge_dup (v);
    z = huge_new (n);
    for (i = 0; i < n; i++)
	z->ob_digit[i] = v->ob_digit[i];
    z->ob_size = -(v->ob_size);
    return (Huge *) z;
}

Huge *huge_abs (Huge * v)
{
    if (v->ob_size < 0)
	return huge_neg (v);
    else
	return huge_dup (v);
}

int huge_nonzero (Huge * v)
{
    if (!v)
	return 0;
    return v->ob_size != 0;
}

Huge *huge_rshift (Huge * a, int shiftby)
{
    Huge *z;
    int newsize, wordshift, loshift, hishift, i, j;
    digit lomask, himask;

    if (a->ob_size < 0) {
	/* Right shifting negative numbers is harder */
	Huge *a1, *a2, *a3;
	a1 = (Huge *) huge_invert (a);
	if (a1 == 0)
	    return 0;
	a2 = (Huge *) huge_rshift (a1, shiftby);
	huge_free (a1);
	if (a2 == 0)
	    return 0;
	a3 = (Huge *) huge_invert (a2);
	huge_free (a2);
	return (Huge *) a3;
    }
    if (shiftby < 0) {
	huge_error ("rshift(): negative shift count");
	return 0;
    }
    wordshift = shiftby / SHIFT;
    newsize = ABS (a->ob_size) - wordshift;
    if (newsize <= 0) {
	z = huge_new (0);
	return (Huge *) z;
    }
    loshift = shiftby % SHIFT;
    hishift = SHIFT - loshift;
    lomask = ((digit) 1 << hishift) - 1;
    himask = MASK ^ lomask;
    z = huge_new (newsize);
    if (a->ob_size < 0)
	z->ob_size = -(z->ob_size);
    for (i = 0, j = wordshift; i < newsize; i++, j++) {
	z->ob_digit[i] = (a->ob_digit[j] >> loshift) & lomask;
	if (i + 1 < newsize)
	    z->ob_digit[i] |=
		(a->ob_digit[j + 1] << hishift) & himask;
    }
    return (Huge *) huge_normalize (z);
}

Huge *huge_lshift (Huge * a, int shiftby)
{
    /* This version due to Tim Peters */
    Huge *z;
    int oldsize, newsize, wordshift, remshift, i, j;
    twodigits accum;

    if (shiftby < 0) {
	huge_error ("lshift(): negative shift count");
	return 0;
    }
    /* wordshift, remshift = divmod(shiftby, SHIFT) */
    wordshift = (int) shiftby / SHIFT;
    remshift = (int) shiftby - wordshift * SHIFT;

    oldsize = ABS (a->ob_size);
    newsize = oldsize + wordshift;
    if (remshift)
	++newsize;
    z = huge_new (newsize);
    if (a->ob_size < 0)
	z->ob_size = -(z->ob_size);
    for (i = 0; i < wordshift; i++)
	z->ob_digit[i] = 0;
    accum = 0;
    for (i = wordshift, j = 0; j < oldsize; i++, j++) {
	accum |= a->ob_digit[j] << remshift;
	z->ob_digit[i] = (digit) (accum & MASK);
	accum >>= SHIFT;
    }
    if (remshift)
	z->ob_digit[newsize - 1] = (digit) accum;
    else
	huge_assert (!accum);
    return (Huge *) huge_normalize (z);
}


/* Bitwise and/xor/or operations */

/* op = '&', '|', '^' */
static Huge *huge_bitwise (Huge * a, int op, Huge * b)
{
    digit maska, maskb;		/* 0 or MASK */
    int negz;
    int size_a, size_b, size_z;
    Huge *z;
    int i;
    digit diga, digb;
    Huge *v;

    if (a->ob_size < 0) {
	a = (Huge *) huge_invert (a);
	maska = MASK;
    } else {
	a = huge_dup (a);
	maska = 0;
    }
    if (b->ob_size < 0) {
	b = (Huge *) huge_invert (b);
	maskb = MASK;
    } else {
	b = huge_dup (b);
	maskb = 0;
    }

    size_a = a->ob_size;
    size_b = b->ob_size;
    size_z = MAX (size_a, size_b);
    z = huge_new (size_z);
    if (a == 0 || b == 0) {
	huge_free (a);
	huge_free (b);
	huge_free (z);
	return 0;
    }
    negz = 0;
    switch (op) {
    case '^':
	if (maska != maskb) {
	    maska ^= MASK;
	    negz = -1;
	}
	break;
    case '&':
	if (maska && maskb) {
	    op = '|';
	    maska ^= MASK;
	    maskb ^= MASK;
	    negz = -1;
	}
	break;
    case '|':
	if (maska || maskb) {
	    op = '&';
	    maska ^= MASK;
	    maskb ^= MASK;
	    negz = -1;
	}
	break;
    }

    for (i = 0; i < size_z; ++i) {
	diga = (i < size_a ? a->ob_digit[i] : 0) ^ maska;
	digb = (i < size_b ? b->ob_digit[i] : 0) ^ maskb;
	switch (op) {
	case '&':
	    z->ob_digit[i] = diga & digb;
	    break;
	case '|':
	    z->ob_digit[i] = diga | digb;
	    break;
	case '^':
	    z->ob_digit[i] = diga ^ digb;
	    break;
	}
    }

    huge_free (a);
    huge_free (b);
    z = huge_normalize (z);
    if (negz == 0)
	return (Huge *) z;
    v = huge_invert (z);
    huge_free (z);
    return v;
}

Huge *huge_and (Huge * a, Huge * b)
{
    return huge_bitwise (a, '&', b);
}

Huge *huge_xor (Huge * a, Huge * b)
{
    return huge_bitwise (a, '^', b);
}

Huge *huge_or (Huge * a, Huge * b)
{
    return huge_bitwise (a, '|', b);
}

char *huge_oct (Huge * v)
{
    return huge_format (v, 8);
}

char *huge_hex (Huge * v)
{
    return huge_format (v, 16);
}

char *huge_dec (Huge * v)
{
    return huge_format (v, 10);
}

void xhuge_log(Huge *h, char *msg, char *file, int line)
{
    static FILE *f = 0;
    char *p = 0;
    if (!f)
	f = fopen ("huge.log", "w");
    fprintf (f, "%s: %d:\n%s: %s\n", file, line, msg, p = huge_hex(h));
    fflush (f);
    if (p)
	free (p);
}



