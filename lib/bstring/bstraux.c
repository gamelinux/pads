/*
 * This source file is part of the bstring string library.  This code was
 * written by Paul Hsieh in 2002-2004, and is covered by the BSD open source 
 * license. Refer to the accompanying documentation for details on usage and 
 * license.
 */

/*
 * bstraux.c
 *
 * This file is not necessarily part of the core bstring library itself, but
 * is just an auxilliary module which includes miscellaneous or trivial 
 * functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "bstrlib.h"
#include "bstraux.h"

/*  int bTrunc (bstring b, int n)
 *
 *  Truncate the bstring to at most n characters.
 */
int bTrunc (bstring b, int n) {
	if (b == NULL || n < 0 || b->mlen < b->slen) return -__LINE__;
	if (b->slen > n) {
		b->slen = n;
		b->data[n] = '\0';	/* Required for Clib interoperability */
	}
	return 0;
}

/*  bstring bTail (bstring b, int n)
 *
 *  Return with a string of the last n characters of b.
 */
bstring bTail (bstring b, int n) {
	if (b == NULL || n < 0 || b->mlen < b->slen) return NULL;
	if (n >= b->slen) return bstrcpy (b);
	return bmidstr (b, b->slen - n, n);
}

/*  bstring bHead (bstring b, int n)
 *
 *  Return with a string of the first n characters of b.
 */
bstring bHead (bstring b, int n) {
	if (b == NULL || n < 0 || b->mlen < b->slen) return NULL;
	if (n >= b->slen) return bstrcpy (b);
	return bmidstr (b, 0, n);
}

/*  int bFill (bstring a, char c, int len)
 *
 *  Fill a given bstring with the character in parameter c, for a length n.
 */
int bFill (bstring a, char c, int len) {
	if (a == NULL || len < 0 || a->mlen < a->slen) return -__LINE__;
	a->slen = 0;
	return bsetstr (a, len, NULL, c);
}

/*  int bReplicate (bstring b, int n)
 *
 *  Replicate the contents of b end to end n times and replace it in b.
 */
int bReplicate (bstring b, int n) {
	return bpattern (b, n * b->slen);
}

/*  int bReverse (bstring b)
 *
 *  Reverse the contents of b in place.
 */
int bReverse (bstring b) {
int i, n, m;
unsigned char t;

	if (b == NULL || b->slen < 2 || b->mlen < b->slen) return -__LINE__;
	n = b->slen;
	m = ((unsigned)n) >> 1;
	n--;
	for (i=0; i < m; i++) {
		t = b->data[n - i];
		b->data[n - i] = b->data[i];
		b->data[i] = t;
	}
	return 0;
}

/*  int bInsertChrs (bstring b, int pos, int len, unsigned char c, unsigned char fill)
 *
 *  Insert a repeated sequence of a given character into the string at 
 *  position pos for a length len.
 */
int bInsertChrs (bstring b, int pos, int len, unsigned char c, unsigned char fill) {
	if (b == NULL || b->slen < 0 || b->mlen < b->slen || pos < 0 || len <= 0) return -__LINE__;

	if (pos > b->slen 
	 && 0 > bsetstr (b, pos, NULL, fill)) return -__LINE__;

	if (0 > balloc (b, b->slen + len)) return -__LINE__;
	if (pos < b->slen) memmove (b->data + pos + len, b->data + pos, b->slen - pos);
	memset (b->data + pos, c, len);
	b->slen += len;
	b->data[b->slen] = '\0';
	return BSTR_OK;
}

/*  int bJustifyLeft (bstring b, int space)
 *
 *  Left justify a string.
 */
int bJustifyLeft (bstring b, int space) {
int j, i, s, t;
unsigned char c = (unsigned char) space;

	if (b == NULL || b->slen < 0 || b->mlen < b->slen) return -__LINE__;
	if (space != (int) c) return BSTR_OK;

	for (s=j=i=0; i < b->slen; i++) {
		t = s;
		s = c != (b->data[j] = b->data[i]);
		j += (t|s);
	}
	if (j > 0 && b->data[j-1] == c) j--;

	b->data[j] = '\0';
	b->slen = j;
	return BSTR_OK;
}

/*  int bJustifyRight (bstring b, int width, int space)
 *
 *  Right justify a string to within a given width.
 */
int bJustifyRight (bstring b, int width, int space) {
int ret;
	if (width <= 0) return -__LINE__;
	if (0 > (ret = bJustifyLeft (b, space))) return ret;
	if (b->slen <= width)
		return bInsertChrs (b, 0, width - b->slen, (unsigned char) space, (unsigned char) space);
	return BSTR_OK;
}

/*  int bJustifyCenter (bstring b, int width, int space)
 *
 *  Center a string's non-white space characters to within a given width by
 *  inserting whitespaces at the beginning.
 */
int bJustifyCenter (bstring b, int width, int space) {
int ret;
	if (width <= 0) return -__LINE__;
	if (0 > (ret = bJustifyLeft (b, space))) return ret;
	if (b->slen <= width)
		return bInsertChrs (b, 0, (width - b->slen + 1) >> 1, (unsigned char) space, (unsigned char) space);
	return BSTR_OK;
}

/*  int bJustifyMargin (bstring b, int width, int space)
 *
 *  Stretch a string to flush against left and right margins by evenly
 *  distributing additional white space between words.  If the line is too
 *  long to be margin justified, it is left justified.
 */
int bJustifyMargin (bstring b, int width, int space) {
struct bstrList * sl;
int i, l, c;

	if (NULL == (sl = bsplit (b, (unsigned char) space))) return -__LINE__;
	for (l=c=i=0; i < sl->qty; i++) {
		if (sl->entry[i]->slen > 0) {
			c ++;
			l += sl->entry[i]->slen;
		}
	}

	if (l + c >= width || c < 2) {
		bstrListDestroy (sl);
		return bJustifyLeft (b, space);
	}

	b->slen = 0;
	for (i=0; i < sl->qty; i++) {
		if (sl->entry[i]->slen > 0) {
			if (b->slen > 0) {
				int s = (width - l + (c / 2)) / c;
				bInsertChrs (b, b->slen, s, (unsigned char) space, (unsigned char) space);
				l += s;
			}
			bconcat (b, sl->entry[i]);
			c--;
			if (c <= 0) break;
		}
	}

	bstrListDestroy (sl);
	return BSTR_OK;
}

/*  char * bStr2NetStr (const bstring b)
 *
 *  Convert a bstring to a netstring.  See 
 *  http://cr.yp.to/proto/netstrings.txt for a description of netstrings.
 *  Note: 1) The value returned should be freed with a call to free() at the
 *           point when it will no longer be referenced to avoid a memory 
 *           leak.
 *        2) If the returned value is non-NULL, then it also '\0' terminated
 *           in the character position one past the "," terminator.
 */
char * bStr2NetStr (const bstring b) {
bstring s;
unsigned char * buff;

	if (b == NULL || b->data == NULL || b->slen < 0) return NULL;
	if (NULL == (s = bformat ("%d:", b->slen))
	 || bconcat (s, b) == BSTR_ERR || bconchar (s, ',') == BSTR_ERR) {
		bdestroy (s);
		return NULL;
	}
	buff = s->data;
	free (s);
	return (char *) buff;
}

/*  bstring bNetStr2Bstr (const char * buf)
 *
 *  Convert a netstring to a bstring.  See 
 *  http://cr.yp.to/proto/netstrings.txt for a description of netstrings.
 *  Note that the terminating "," *must* be present, however a following '\0'
 *  is *not* required.
 */
bstring bNetStr2Bstr (const char * buff) {
int i, x;
bstring b;
	if (buff == NULL) return NULL;
	x = 0;
	for (i=0; buff[i] != ':'; i++) {
		unsigned int v = buff[i] - '0';
		if (v > 9 || x > ((INT_MAX - (signed int)v) / 10)) return NULL;
		x = (x * 10) + v;
	}

	/* This thing has to be properly terminated */
	if (buff[i + 1 + x] != ',') return NULL;

	if (NULL == (b = bfromcstr (""))) return NULL;
	if (balloc (b, x + 1) != BSTR_OK)  {
		bdestroy (b);
		return NULL;
	}
	memcpy (b->data, buff + i + 1, x);
	b->data[x] = '\0';
	b->slen = x;
	return b;
}

static unsigned char b64ETable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*  bstring bBase64Encode (const bstring b)
 *
 *  Generate a base64 encoding.
 */
bstring bBase64Encode (const bstring b) {
int i, c0, c1, c2, c3;
bstring out;

	if (b == NULL || b->slen < 0 || b->data == NULL) return NULL;

	out = bfromcstr ("");
	for (i=0; i + 2 < b->slen; i += 3) {
		if (i && ((i % 57) == 0)) {
			if (bconchar (out, '\015') < 0 || bconchar (out, '\012') < 0) {
				bdestroy (out);
				return NULL;
			}
		}
		c0 = b->data[i] >> 2;
		c1 = ((b->data[i] << 4) |
			  (b->data[i+1] >> 4)) & 0x3F;
		c2 = ((b->data[i+1] << 2) |
			  (b->data[i+2] >> 6)) & 0x3F;
		c3 = b->data[i+2] & 0x3F;
		if (bconchar (out, b64ETable[c0]) < 0 ||
			bconchar (out, b64ETable[c1]) < 0 ||
			bconchar (out, b64ETable[c2]) < 0 ||
			bconchar (out, b64ETable[c3]) < 0) {
			bdestroy (out);
			return NULL;
		}
	}

	if (i && ((i % 57) == 0)) {
		if (bconchar (out, '\015') < 0 || bconchar (out, '\012') < 0) {
			bdestroy (out);
			return NULL;
		}
	}

	switch (i + 2 - b->slen) {
		case 0:	c0 = b->data[i] >> 2;
				c1 = ((b->data[i] << 4) |
					  (b->data[i+1] >> 4)) & 0x3F;
				c2 = (b->data[i+1] << 2) & 0x3F;
			if (bconchar (out, b64ETable[c0]) < 0 ||
				bconchar (out, b64ETable[c1]) < 0 ||
				bconchar (out, b64ETable[c2]) < 0 ||
				bconchar (out, '=') < 0) {
				bdestroy (out);
				return NULL;
			}
			break;
		case 1:	c0 =  b->data[i] >> 2;
				c1 = (b->data[i] << 4) & 0x3F;
			if (bconchar (out, b64ETable[c0]) < 0 ||
				bconchar (out, b64ETable[c1]) < 0 ||
				bconchar (out, '=') < 0 ||
				bconchar (out, '=') < 0) {
				bdestroy (out);
				return NULL;
			}
			break;
		case 2: break;
	}

	return out;
}

#define B64_PAD (-2)
#define B64_ERR (-1)

static int base64DecodeSymbol (unsigned char alpha) {
   if      ((alpha >= 'A') && (alpha <= 'Z')) return (int)(alpha - 'A');
   else if ((alpha >= 'a') && (alpha <= 'z'))
        return 26 + (int)(alpha - 'a');
   else if ((alpha >= '0') && (alpha <= '9'))
        return 52 + (int)(alpha - '0');
   else if (alpha == '+') return 62;
   else if (alpha == '/') return 63;
   else if (alpha == '=') return B64_PAD;
   else                   return B64_ERR;
}

/*  bstring bBase64Decode (const bstring b)
 *
 *  Decode a base64 block of data.  All MIME headers are assumed to have been
 *  removed.
 */
bstring bBase64Decode (const bstring b) {
int i, v;
unsigned char c0, c1, c2;
bstring out;

	if (b == NULL || b->slen < 0 || b->data == NULL) return NULL;
	out = bfromcstr ("");
	i = 0;
	for (;;) {
		do {
			if (i >= b->slen) return out;
			if (b->data[i] == '=') {
				bdestroy (out);
				return NULL;
			}
			v = base64DecodeSymbol (b->data[i]);
			i++;
		} while (v < 0);
		c0 = (unsigned char) (v << 2);
		do {
			if (i >= b->slen || b->data[i] == '=') {
				bdestroy (out);
				return NULL;
			}
			v = base64DecodeSymbol (b->data[i]);
			i++;
		} while (v < 0);
		c0 |= (unsigned char) (v >> 4);
		c1  = (unsigned char) (v << 4);
		do {
			if (i >= b->slen) {
				bdestroy (out);
				return NULL;
			}
			if (b->data[i] == '=') {
				i++;
				if (i >= b->slen || b->data[i] != '=' || bconchar (out, c0) < 0) {
					bdestroy (out);
					return NULL;
				}
				return out;
			}
			v = base64DecodeSymbol (b->data[i]);
			i++;
		} while (v < 0);
		c1 |= (unsigned char) (v >> 2);
		c2  = (unsigned char) (v << 6);
		do {
			if (i >= b->slen) {
				bdestroy (out);
				return NULL;
			}
			if (b->data[i] == '=') {
				if (bconchar (out, c0) < 0 || bconchar (out, c1) < 0) {
					bconchar (out, c0);
					return NULL;
				}
				return out;
			}
			v = base64DecodeSymbol (b->data[i]);
			i++;
		} while (v < 0);
		c2 |= (unsigned char) (v);
		if (bconchar (out, c0) < 0 ||
			bconchar (out, c1) < 0 ||
			bconchar (out, c2) < 0) {
			bconchar (out, c0);
			return NULL;
		}
	}
}

#define UU_DECODE_BYTE(b) (((b) == (signed int)'`') ? 0 : (b) - (signed int)' ')

struct bUuInOut {
	bstring src, dst;
};

static int bUuDecLine (void * parm, int ofs, int len) {
struct bUuInOut * io = (struct bUuInOut *) parm;
bstring s = io->src;
bstring t = io->dst;
int i, llen;

	if (len == 0) return 0;
	llen = UU_DECODE_BYTE (s->data[ofs]);

	if (((unsigned) llen) > 45) return -__LINE__;
	if (len > (i = (int) ((4/3.0)*llen + 1.5))) len = i;

	for (i=1; i < len; i += 4) {
		int c0, c1, c2, c3;

		c0 =                 UU_DECODE_BYTE (s->data[ofs + i + 0]);
		c1 = (i + 1 < len) ? UU_DECODE_BYTE (s->data[ofs + i + 1]) : -1;
		c2 = (i + 2 < len) ? UU_DECODE_BYTE (s->data[ofs + i + 2]) : -1;
		c3 = (i + 3 < len) ? UU_DECODE_BYTE (s->data[ofs + i + 3]) : -1;

		if (((unsigned) (c0|c1) >= 0x40) || c2 >= 0x40 || c3 >= 0x40) return -__LINE__;

		if (bconchar (t, (char)((c0 << 2) | ((c1 >> 4) & 0x03))) < 0) return -__LINE__;
		if ((unsigned) c2 < 0x40) {
			if (bconchar (t, (char)((c1 << 4) | ((c2 >> 2) & 0x0F))) < 0) return -__LINE__;
			if ((unsigned) c3 < 0x40) if (bconchar (t, (char)((c2 << 6) | (c3 & 0x3F))) < 0) return -__LINE__;
		}
	}
	return 0;
}

/*  bstring bUuDecode (const bstring src)
 *
 *  Performs a UUDecode of a block of data.  It is assumed that the "begin"
 *  and "end" lines have already been stripped off.  The potential security
 *  problem of writing the filename in the begin line is something that is
 *  beyond the scope of a portable library.
 */
#ifdef _MSC_VER
#pragma warning(disable:4204)
#endif
bstring bUuDecode (const bstring src) {
struct tagbstring ws = bsStatic ("\r\n");
struct bUuInOut io;

	if (src == NULL || src->slen < 0 || src->data == NULL) return NULL;
	io.src = src;
	io.dst = bfromcstr ("");
	if (bsplitscb (src, &ws, 0, bUuDecLine, &io) < 0) bstrFree (io.dst);
	return io.dst;
}

#define UU_MAX_LINELEN 45
#define UU_ENCODE_BYTE(b) (char) (((b) == 0) ? '`' : ((b) + ' '))

/*  bstring bUuEncode (const bstring src)
 *
 *  Performs a UUEncode of a block of data.  The "begin" and "end" lines are 
 *  not appended.
 */
bstring bUuEncode (const bstring src) {
bstring out;
int i, j, jm;
unsigned int c0, c1, c2;
	if (src == NULL || src->slen < 0 || src->data == NULL) return NULL;
	if ((out = bfromcstr ("")) == NULL) return NULL;
	for (i=0; i < src->slen; i += UU_MAX_LINELEN) {
		if ((jm = i + UU_MAX_LINELEN) > src->slen) jm = src->slen;
		if (bconchar (out, UU_ENCODE_BYTE (jm - i)) < 0) {
			bstrFree (out);
			break;
		}
		for (j = i; j < jm; j += 3) {
			c0 = bchar (src, j    );
			c1 = bchar (src, j + 1);
			c2 = bchar (src, j + 2);
			if (bconchar (out, UU_ENCODE_BYTE ( (c0 & 0xFC) >> 2)) < 0 ||
				bconchar (out, UU_ENCODE_BYTE (((c0 & 0x03) << 4) | ((c1 & 0xF0) >> 4))) < 0 ||
				bconchar (out, UU_ENCODE_BYTE (((c1 & 0x0F) << 2) | ((c2 & 0xC0) >> 6))) < 0 ||
				bconchar (out, UU_ENCODE_BYTE ( (c2 & 0x3F))) < 0) {
					bstrFree (out);
					goto End;
				}
		}
		if (bconchar (out, '\r') < 0 || bconchar (out, '\n') < 0) {
			bstrFree (out);
			break;
		}
	}
	End:;
	return out;
}

/*  bstring bYEncode (const bstring src)
 *
 *  Performs a YEncode of a block of data.  No header or tail info is 
 *  appended.  See: http://www.yenc.org/whatis.htm and 
 *  http://www.yenc.org/yenc-draft.1.3.txt
 */
bstring bYEncode (const bstring src) {
int i;
bstring out;
unsigned char c;

	if (src == NULL || src->slen < 0 || src->data == NULL) return NULL;
	if ((out = bfromcstr ("")) == NULL) return NULL;
	for (i=0; i < src->slen; i++) {
		c = (unsigned char)(src->data[i] + 42);
		if (c == '=' || c == '\0' || c == '\r' || c == '\n') {
			if (0 > bconchar (out, '=')) {
				bdestroy (out);
				return NULL;
			}
			c += (unsigned char) 64;
		}
		if (0 > bconchar (out, c)) {
			bdestroy (out);
			return NULL;
		}
	}
	return out;
}

/*  bstring bYDecode (const bstring src)
 *
 *  Performs a YDecode of a block of data.  See: 
 *  http://www.yenc.org/whatis.htm and http://www.yenc.org/yenc-draft.1.3.txt
 */
bstring bYDecode (const bstring src) {
int i;
bstring out;
unsigned char c;

	if (src == NULL || src->slen < 0 || src->data == NULL) return NULL;
	if ((out = bfromcstr ("")) == NULL) return NULL;
	for (i=0; i < src->slen; i++) {
		c = src->data[i];
		if (c == '=') {
			i++;
			if (i >= src->slen) {
				bdestroy (out);
				return NULL;
			}
			c = (unsigned char) (src->data[i] - 64);
		} else {
			if (c == '\0') {
				bdestroy (out);
				return NULL;
			}

			/* Extraneous CR/LFs are to be ignored. */
			if (c == '\r' || c == '\n') continue;
		}
		if (0 > bconchar (out, (char)(c - (unsigned char) 42))) {
			bdestroy (out);
			return NULL;
		}
	}
	return out;
}

