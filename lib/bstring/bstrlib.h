/*
 * This source file is part of the bstring string library.  This code was
 * written by Paul Hsieh in 2002-2004, and is covered by the BSD open source 
 * license. Refer to the accompanying documentation for details on usage and 
 * license.
 */

/*
 * bstrlib.c
 *
 * This file is the core module for implementing the bstring functions.
 */

#ifndef BSTRLIB_INCLUDE
#define BSTRLIB_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <string.h>
#include <limits.h>

#define BSTR_ERR (-1)
#define BSTR_OK (0)

typedef struct tagbstring * bstring;

/* Copy functions */
#define cstr2bstr bfromcstr
extern bstring bfromcstr (const char * str);
extern bstring blk2bstr (const void * blk, int len);
extern char * bstr2cstr (const bstring s, char z);
extern int bcstrfree (char * s);
extern bstring bstrcpy (const bstring b1);
extern int bassign (bstring a, const bstring b);

/* Destroy function */
extern int bdestroy (bstring b);

/* Space allocation hinting function */
extern int balloc (bstring s, int len);

/* Substring extraction */
extern bstring bmidstr (const bstring b, int left, int len);

/* Various standard manipulations */
extern int bconcat (bstring b0, const bstring b1);
extern int bconchar (bstring b0, char c);
extern int bcatcstr (bstring b, const char * s);
extern int bcatblk (bstring b, const unsigned char * s, int len);
extern int binsert (bstring s1, int pos, const bstring s2, unsigned char fill);
extern int binsertch (bstring s1, int pos, int len, unsigned char fill);
extern int breplace (bstring b1, int pos, int len, const bstring b2, unsigned char fill);
extern int bdelete (bstring s1, int pos, int len);
extern int bsetstr (bstring b0, int pos, const bstring b1, unsigned char fill);

/* Scan/search functions */
extern int bstricmp (const bstring b0, const bstring b1);
extern int bstrnicmp (const bstring b0, const bstring b1, int n);
extern int biseqcaseless (const bstring b0, const bstring b1);
extern int biseq (const bstring b0, const bstring b1);
extern int biseqcstr (const bstring b, const char * s);
extern int bstrcmp (const bstring b0, const bstring b1);
extern int bstrncmp (const bstring b0, const bstring b1, int n);
extern int binstr (const bstring s1, int pos, const bstring s2);
extern int binstrr (const bstring s1, int pos, const bstring s2);
extern int bstrchr (const bstring b, int c);
extern int bstrrchr (const bstring b, int c);
extern int binchr (const bstring b0, int pos, const bstring b1);
extern int binchrr (const bstring b0, int pos, const bstring b1);
extern int bninchr (const bstring b0, int pos, const bstring b1);
extern int bninchrr (const bstring b0, int pos, const bstring b1);
extern int bfindreplace (bstring b, const bstring find, const bstring repl, int pos);

struct bstrList {
    int qty;
    bstring entry[1];
};

/* String split and join functions */
extern struct bstrList * bsplit (const bstring str, unsigned char splitChar);
extern struct bstrList * bsplits (const bstring str, const bstring splitStr);
extern bstring bjoin (const struct bstrList * bl, const bstring sep);
extern int bstrListDestroy (struct bstrList * sl);
extern int bsplitcb (const bstring str, unsigned char splitChar, int pos,
	int (* cb) (void * parm, int ofs, int len), void * parm);
extern int bsplitscb (const bstring str, const bstring splitStr, int pos,
	int (* cb) (void * parm, int ofs, int len), void * parm);

/* Miscellaneous functions */
extern int bpattern (bstring b, int len);
extern int btoupper (bstring b);
extern int btolower (bstring b);
extern bstring bformat (const char * fmt, ...);
extern int bformata (bstring b, const char * fmt, ...);

typedef int (*bNgetc) (void *parm);
typedef size_t (* bNread) (void *buff, size_t elsize, size_t nelem, void *parm);

/* Input functions */
extern bstring bgets (bNgetc getcPtr, void * parm, char terminator);
extern bstring bread (bNread readPtr, void * parm);

/* Stream functions */
extern struct bStream * bsopen (bNread readPtr, void * parm);
extern void * bsclose (struct bStream * s);
extern int bsbufflength (struct bStream * s, int sz);
extern int bsreadln (bstring b, struct bStream * s, char terminator);
extern int bsreadlns (bstring r, struct bStream * s, const bstring term);
extern int bsread (bstring b, struct bStream * s, int n);
extern int bsreadlna (bstring b, struct bStream * s, char terminator);
extern int bsreadlnsa (bstring r, struct bStream * s, const bstring term);
extern int bsreada (bstring b, struct bStream * s, int n);
extern int bsunread (struct bStream * s, const bstring b);
extern int bspeek (bstring r, const struct bStream * s);
extern int bssplitscb (struct bStream * s, const bstring splitStr, 
	int (* cb) (void * parm, int ofs, const bstring entry), void * parm);
extern int bseof (const struct bStream * s);

struct tagbstring {
	int mlen;
	int slen;
	unsigned char * data;
};

/* Accessor macros */
#define blengthe(b, e)      (((b) == (void *)0 || (b)->slen < 0) ? (unsigned int)(e) : ((b)->slen))
#define blength(b)          (blengthe ((b), 0))
#define bdataofse(b, o, e)  (((b) == (void *)0 || (b)->data == (void*)0) ? (unsigned char *)(e) : ((b)->data) + (o))
#define bdataofs(b, o)      (bdataofse ((b), (o), (void *)0))
#define bdatae(b, e)        (bdataofse (b, 0, e))
#define bdata(b)            (bdataofs (b, 0))
#define bchare(b, p, e)     ((((unsigned)(p)) < (unsigned)blength(b)) ? ((b)->data[(p)]) : (e))
#define bchar(b, p)         bchare ((b), (p), '\0')

/* Static constant string initialization macro */
#define bsStatic(q)         {-__LINE__, sizeof(q)-1, (unsigned char *)(q)}

/* Reference building macros */
#define cstr2tbstr btfromcstr
#define btfromcstr(t,s) {                         \
    (t).data = (unsigned char *) (s);             \
    (t).slen = (int) (strlen) ((char *)(t).data); \
    (t).mlen = -1;                                \
}
#define blk2tbstr(t,s,l) {            \
    (t).slen = l;                     \
    (t).mlen = -1;                    \
    (t).data = (unsigned char *) (s); \
}

/* Write protection macros */
#define bwriteprotect(t) { if ((t).mlen >=  0) (t).mlen = -1; }
#define bwriteallow(t)   { if ((t).mlen == -1) (t).mlen = (t).slen + ((t).slen == 0); }

#ifdef __cplusplus
}
#endif


#endif
