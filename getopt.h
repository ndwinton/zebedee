#ifndef GETOPT_H_INCLUDED
#define GETOPT_H_INCLUDED

/* RCS ID $Id: getopt.h,v 1.1 2001-04-12 18:06:46 ndwinton Exp $ */

#ifdef	__cplusplus
extern "C" {
#endif

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;
extern int optreset;

extern int getopt(int nargc, char *const *nargv, const char *ostr);

#ifdef	__cplusplus
}
#endif

#endif
