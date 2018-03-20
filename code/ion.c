/*==================================================================================================
  File: ion.c
  Creation Date: 2018-03-13
  Creator: Michael Campagnaro
  Notice: (C) Copyright 2018 by Jelly Pixel, Inc. All Rights Reserved.
  ================================================================================================*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include "types.h"

#define internal static
#define global_variable static

#define MAX(a, b) ((a) >= (b) ? (a) : (b))

internal void *
xrealloc(void *ptr, size_t num_bytes) {
    ptr = realloc(ptr, num_bytes);
    if (!ptr) {
        perror("xrealloc failed");
        assert(0);
        exit(1);
    }
    return ptr;
}

internal void *
xmalloc(size_t num_bytes) {
    void *ptr = malloc(num_bytes);
    if (!ptr) {
        perror("xmalloc failed");
        exit(1);
    }
    return ptr;
}

internal void
Fatal(char *format, ...) {
    va_list args;
    va_start(args, format);
    // Unsafe for now, but we'll replace it with a stretchy buffer string builder eventually...
    printf("FATAl: ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
    exit(1);
}

typedef struct BufHdr {
    size_t len;
    size_t cap;
    char buf[];
} BufHdr;

// TIL: You can use commas inside the macro as a replacement for semicolons,
// when a semicolon would present problems. You can verify this by replacing
// some commas in the stretchy buffer macros and see that it breaks the
// compiler.

#define _BufHdr(b) ((BufHdr *)((char *)(b) - offsetof(BufHdr, buf)))
#define _BufFits(b, n) (BufLen(b) + (n) <= BufCap(b))
#define _BufFit(b, n) (_BufFits((b), (n)) ? 0 : ((b) = _BufGrow((b), BufLen(b) + (n), sizeof(*(b)))))

#define BufLen(b) ((b) ? _BufHdr(b)->len : 0)
#define BufCap(b) ((b) ? _BufHdr(b)->cap : 0)
#define BufPush(b, ...) (_BufFit((b), 1), (b)[_BufHdr(b)->len++] = (__VA_ARGS__))
#define BufFree(b) ((b) ? (free(_BufHdr(b)), (b) = NULL) : 0)

internal void *
_BufGrow(void *buf, size_t new_len, size_t elem_size) {
    // @document The regrowth strategy.
    //
    // From stream: How about using a buffer regrow factor of 1.5? It's
    // apparently better for heaps because the next allocation is smaller than
    // the sum of the previous ones, unlike for 2
    //
    // Another stream comment: The grow strategy i'm considering: just reserve
    // the theoretical maximum amount that you want for the buffer and take
    // advantage of the fact that the kernel will not make pages resident until
    // you touch them (:
    size_t new_cap = MAX(1 + 2 * BufCap(buf), new_len);
    assert(new_len <= new_cap);
    size_t new_size = offsetof(BufHdr, buf) + new_cap * elem_size;
    BufHdr *new_hdr;
    if (buf) {
        new_hdr = xrealloc(_BufHdr(buf), new_size);
    } else {
        new_hdr = xmalloc(new_size);
        new_hdr->len = 0;
    }
    new_hdr->cap = new_cap;
    return new_hdr->buf; // or new_hdr + 1
}

internal void
BufTest() {
    s32 *buf = NULL;
    assert(BufLen(buf) == 0);
    enum { N = 1024 };
    for (u32 i = 0; i < N; i++) {
        BufPush(buf, i);
    }
    assert(BufLen(buf) == N);
    for (u32 i = 0; i < BufLen(buf); i++) {
        assert(buf[i] == i);
    }
    BufFree(buf);
    assert(buf == NULL);
    assert(BufLen(buf) == 0);
}

typedef struct InternStr {
    size_t len;
    char *str;
} InternStr;

global_variable InternStr *interns; // stretchy buf; static = initialized to 0 by default.

/* Interesting note from James Widman:
 *
 * @pervognsen re string interning: something I like to do is,
 * instead of using a _pointer_ to a canonicalized string, I use the _offset_
 * from the base address of the storage area for interned strings. That way,
 * the opaque value can be stable across runs (if you store and load
 * canonicalized strings between runs).
 */

internal char *
StrInternRange(char *start, char *end) {
    // Slower version that uses a stretchy buffer instead of a hash table. Can drop in a hash table
    // later since that's an implementation detail.

    size_t len = end - start;
    for (size_t i = 0; i < BufLen(interns); ++i) {
        if ((interns[i].len == len) && strncmp(interns[i].str, start, len) == 0) {
            return interns[i].str;
        }
    }

    // Allocate memory for storage as opposed to making the str member in the
    // InternStr struct an empty array, i.e. char str[0]. You would get a flat,
    // ordered array of memory, but the intern pointers would change when the
    // stretchy buffer grows (realloc). We want the pointers to be stable so we
    // handle the allocation with malloc. You can speed this up by allocating
    // the strings out of a big linear array, like an arena, but for now this
    // works.
    char *str = xmalloc(len + 1); // We want to store c-strings in the buffer, so +1 for null-terminator.
    memcpy(str, start, len);
    str[len] = 0;
    BufPush(interns, (InternStr){len, str});
    return str;
}

internal char *
StrIntern(char *str) {
    return StrInternRange(str, str + strlen(str));
}

internal void
StrInternTest() {
    char a[] = "hello";
    char b[] = "hello";
    assert(a != b);
    char *pa = StrIntern(a);
    char *pb = StrIntern(b);
    assert(pa == pb);

    char c[] = "foo";
    assert(StrIntern(c) != pa);

    char d[] = "hello!";
    char *pd = StrIntern(d);
    assert(pd != pa);
}

typedef enum TokenKind {
    TOKEN_INT = 128, // Reserve first 128 ascii values?
    TOKEN_NAME,
    // ...
} TokenKind;

typedef struct Token {
    TokenKind kind;
    // All tokens contain the string literal that it represents.
    char *start;
    char *end;
    union {
        s32 val;
        char *name; // Interned name for an identifier.
    };
} Token;

// @warning This returns a pointer to a static internal buffer, so it'll be overwritten next call.
internal char *
TokenKindName(TokenKind kind) {
    static char buf[256];
    switch(kind) {
        case TOKEN_INT: {
            sprintf(buf, "integer");
        } break;
        case TOKEN_NAME: {
            sprintf(buf, "name");
        } break;
        default: {
            if (kind < 128 && isprint(kind)) {
                sprintf(buf, "'%c'", kind);
            } else {
                sprintf(buf, "<ASCII %d>", kind);
            }
        }
    }
    return buf;
}

Token token;
char *stream;

char *keyword_if;
char *keyword_for;
char *keyword_while;

internal void
InitKeywords() {
    keyword_if = StrIntern("if");
    keyword_for = StrIntern("for");
    keyword_while = StrIntern("while");
}

/*
 * The tokenizer uses a big switch statement because it's fast. The other way
 * of doing it would be using if statements to test if the byte is alphabetical
 * or numeric. We want this to be fast because it's often the case that the
 * lexer becomes the bottleneck for a simple language compiler. The tokenizer
 * is working one byte at a time so you want it to process data quickly. A
 * switch statement will compile to one indirect jmp operation based on the
 * switch's dispatch value. And it does that using a table. There are often
 * some range checks, which you may be able to avoid, but it's probably not
 * that bad for our use case.
 */

// e.g. 1234 (x+y) translates into '1234' '(' 'x' '+' 'y' ')'
internal void
NextToken() {
    token.start = stream; // It may not be null-terminated!
    switch (*stream) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9': {
            s32 val = 0;
            while(isdigit(*stream)) {
                val *= 10; // Shifts everything over every time we see a new digit.
                val += *stream++ - '0';
            }
            token.kind = TOKEN_INT;
            token.val = val;
        } break;

        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g': case 'h': case 'i':
        case 'j': case 'k': case 'l': case 'm': case 'n': case 'o': case 'p': case 'q': case 'r':
        case 's': case 't': case 'u': case 'v': case 'w': case 'x': case 'y': case 'z': case 'A':
        case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': case 'H': case 'I': case 'J':
        case 'K': case 'L': case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R': case 'S':
        case 'T': case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z': case '_': {
            while (isalnum(*stream) || *stream == '_') {
                stream++;
            }
            token.kind = TOKEN_NAME;
            token.name = StrInternRange(token.start, stream);
        } break;
        default: {
            token.kind = *stream++;
        } break;
    }
    token.end = stream;
}

inline void
InitStream(char *str) {
    stream = str;
    NextToken();
}

inline void
PrintToken(Token token) {
    switch(token.kind) {
        case TOKEN_INT: {
            printf("TOKEN INT: %d\n", token.val);
        } break;
        case TOKEN_NAME: {
            printf("TOKEN NAME: %.*s (intern &%p)\n", (int)(token.end - token.start), token.start, token.name);
        } break;
        default: {
            printf("TOKEN '%c'\n", token.kind);
        } break;
    }
}

inline b32
IsToken(TokenKind kind) {
    return token.kind == kind;
}

inline b32
IsTokenName(char *name) {
    return token.kind == TOKEN_NAME && token.name == name;
}

inline b32
MatchToken(TokenKind kind) {
    if (IsToken(kind)) {
        NextToken();
        return true;
    } else {
        return false;
    }
}

inline b32
ExpectToken(TokenKind kind) {
    if (IsToken(kind)) {
        NextToken();
        return true;
    } else {
        Fatal("Expected token: %s, got %s", TokenKindName(kind), TokenKindName(token.kind));
        return false;
    }
}

internal void
LexTest() {
    char *source = "XY+(XY)1234+42_HELLO1,23+foo!Yeah...93";
    InitStream(source);
    while (token.kind) {
        //PrintToken(token);
        NextToken();
    }
}

/* Grammar in order of precedence:
 *
 * expr3 = INT | '(' expr ')'
 * expr2 = [- + ~]expr2 | expr3     (unary is right-associative)
 * expr1 = expr2 ([/ * << >>] expr2)*   (left-associative)
 * expr0 = expr1 ([+ -] expr1)*   (left-associative)
 * expr  = expr0
 *
 */

s32 ParseExpr();

internal s32
ParseExpr3() {
    s32 result;

    if (IsToken(TOKEN_INT)) {
        printf("%d", token.val);
        result = token.val;
        NextToken();
    }
    else if (MatchToken('(')) {
        printf("(");
        result = ParseExpr();
        ExpectToken(')');
        printf(")");
    }
    else {
        Fatal("Expected integer or '(', got %s", TokenKindName(token.kind));
        result = 0;
    }

    return result;
}

internal s32
ParseExpr2() {
    // Right associative
    s32 result;
    if (IsToken('-') || IsToken('+') || IsToken('~')) {
        char op = token.kind;
        printf("%c", op);
        NextToken();
        s32 rval = ParseExpr2();
        if (op == '-') {
            result = -rval;
        } else if (op == '~') {
            result = ~rval;
        } else {
            assert(op == '+');
            result = rval;
        }
    } else {
        result = ParseExpr3();
    }

    return result;
}

internal s32
ParseExpr1() {
    // Left associative
    s32 result = ParseExpr2();
    while (IsToken('*') || IsToken('/') || IsToken('<') || IsToken('>')) {
        char op = token.kind;
        printf("%c", op);
        NextToken();

        if (op == '<' || op == '>') {
            if (IsToken(op)) {
                printf("%c", op);
                NextToken();
            }
            else {
                Fatal("Expected token '%c', but got %s", op, TokenKindName(token.kind));
                return 0;
            }
        }

        s32 rval = ParseExpr2();
        if (op == '*') {
            result *= rval;
        } else if (op == '/') {
            assert(rval != 0);
            result /= rval;
        } else if (op == '<') {
            result = result << rval;
        } else {
            assert(op == '>');
            result = result >> rval;
        }
    }

    return result;
}

internal s32
ParseExpr0() {
    // Left associative
    s32 result = ParseExpr1();
    while (IsToken('+') || IsToken('-')) {
        char op = token.kind;
        printf("%c", op);
        NextToken();

        s32 rval = ParseExpr1();
        // Left-fold
        if (op == '+') {
            result += rval;
        } else {
            assert(op == '-');
            result -= rval;
        }
    }

    return result;
}

internal s32
ParseExpr() {
    return ParseExpr0();
}

inline s32
ParseExprStr(char *str) {
    InitStream(str);
    printf("\nParse test for \"%s\":\n  ", str);
    s32 result = ParseExpr();
    printf(" = %d\n", result);
    return result;
}

#define TEST_EXPR(x, r) assert(ParseExprStr(#x) == (r))

internal void
ParseTest() {
    TEST_EXPR(1, 1);
    TEST_EXPR(-5, -5);
    TEST_EXPR((1), 1);
    TEST_EXPR((1+2), 3);
    TEST_EXPR(1-2-3, -4);
    TEST_EXPR(2*3+4*5, 26);
    TEST_EXPR(2*(3+4)*5, 70);
    TEST_EXPR(2+-3, -1);
    TEST_EXPR(-(3+8-2), -9);
    TEST_EXPR((10/5)*((2-5)+(25/5)), 4);

    TEST_EXPR(-----3, -3);
    TEST_EXPR(---(-3), 3);

    TEST_EXPR(+3, 3);
    TEST_EXPR(-+3, -3);
    TEST_EXPR(+-3, -3);

    TEST_EXPR(~1, -2);
    TEST_EXPR(~-2, 1);
    TEST_EXPR(~0, -1);

    TEST_EXPR(2<<4, 32);
    TEST_EXPR(32>>2, 8);

    // @improve Have a way to test for expected failures, such as a divide by 0.
    //TEST_EXPR(1/0, 3);
}

#undef TEST_EXPR

int main(int argc, char **argv) {
    BufTest();
    LexTest();
    StrInternTest();
    InitKeywords();

    ParseTest();

    return 0;
}
