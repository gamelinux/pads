/*
 * This source file is part of the bstring string library.  This code was
 * written by Paul Hsieh in 2002-2004, and is covered by the BSD open source 
 * license. Refer to the accompanying documentation for details on usage and 
 * license.
 */

/*
 * bstraux.h
 *
 * This file is not necessarily part of the core bstring library itself, but
 * is just an auxilliary module which includes miscellaneous or trivial 
 * functions.
 */

#ifndef BSTRAUX_INCLUDE
#define BSTRAUX_INCLUDE

#include "bstrlib.h"

#ifdef __cplusplus
extern "C" {
#endif

#define bstrDeclare(b)               bstring (b) = NULL; 
#define bstrFree(b)                  {if ((b) != NULL && (b)->slen >= 0 && (b)->mlen >= (b)->slen) { bdestroy (b); (b) = NULL; }}

/* Backward compatibilty with previous version of Bstrlib */
#define bAssign(a,b)                 ((bassign)((a), (b)))
#define bSubs(b,pos,len,a,c)         ((breplace)((b),(pos),(len),(a),(unsigned char)(c)))
#define bStrchr(b,c)                 ((bstrchr)((b),(c)))
#define bStrchrFast(b,c)             ((bstrchr)((b),(c)))
#define bCatCstr(b,s)                ((bcatcstr)((b), (s)))
#define bCatBlk(b,s,len)             ((bcatblk)((b),(s),(len)))
#define bCatStatic(b,s)              bCatBlk ((b), (s), sizeof (s) - 1)
#define bReplaceAll(b,find,repl,pos) ((bfindreplace)((b),(find),(repl),(pos)))
#define bUppercase(b)                ((btoupper)(b))
#define bLowercase(b)                ((btolower)(b))
#define bCaselessCmp(a,b)            ((bstricmp)(a,b))
#define bCaselessNCmp(a,b,n)         ((bstrnicmp)(a,b,n))

/* Unusual functions */
extern int bTrunc (bstring b, int n);
extern bstring bTail (bstring b, int n);
extern bstring bHead (bstring b, int n);
extern int bFill (bstring a, char c, int len);
extern int bReplicate (bstring b, int n);
extern int bReverse (bstring b);
extern int bInsertChrs (bstring b, int pos, int len, unsigned char c, unsigned char fill);

/* Spacing formatting */
extern int bJustifyLeft (bstring b, int space);
extern int bJustifyRight (bstring b, int width, int space);
extern int bJustifyMargin (bstring b, int width, int space);
extern int bJustifyCenter (bstring b, int width, int space);

/* Esoteric standards specific functions */
extern char * bStr2NetStr (const bstring b);
extern bstring bNetStr2Bstr (const char * buf);
extern bstring bBase64Encode (const bstring b);
extern bstring bBase64Decode (const bstring b);
extern bstring bUuDecode (const bstring src);
extern bstring bUuEncode (const bstring src);
extern bstring bYEncode (const bstring src);
extern bstring bYDecode (const bstring src);

#ifdef __cplusplus
}
#endif

#endif
