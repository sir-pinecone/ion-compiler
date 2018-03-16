/*==================================================================================================
  File: ion.c
  Creation Date: 2018-03-13
  Creator: Michael Campagnaro
  Notice: (C) Copyright 2018 by Jelly Pixel, Inc. All Rights Reserved.
  ================================================================================================*/

#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include "types.h"

#define internal static
#define global_variable static

#define MAX(a, b) ((a) >= (b) ? (a) : (b))

void *
xrealloc(void *ptr, size_t num_bytes) {
    ptr = realloc(ptr, num_bytes);
    if (!ptr) {
        perror("xrealloc failed");
        assert(0);
        exit(1);
    }
    return ptr;
}

void *
xmalloc(size_t num_bytes) {
    void *ptr = malloc(num_bytes);
    if (!ptr) {
        perror("xmalloc failed");
        exit(1);
    }
    return ptr;
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
        u64 val;
    };
} Token;

Token token;
char *stream;

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
    token.start = stream; // Not null-terminated at the moment!
    switch (*stream) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9': {
            u64 val = 0;
            while(isdigit(*stream)) {
                val *= 10; // Shifts everything over every time we see a new digit.
                val += *stream++ - '0';
            }
            token.kind = TOKEN_INT;
            token.val = val;
        } break;

        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
        case 'g':
        case 'h':
        case 'i':
        case 'j':
        case 'k':
        case 'l':
        case 'm':
        case 'n':
        case 'o':
        case 'p':
        case 'q':
        case 'r':
        case 's':
        case 't':
        case 'u':
        case 'v':
        case 'w':
        case 'x':
        case 'y':
        case 'z':
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
        case 'G':
        case 'H':
        case 'I':
        case 'J':
        case 'K':
        case 'L':
        case 'M':
        case 'N':
        case 'O':
        case 'P':
        case 'Q':
        case 'R':
        case 'S':
        case 'T':
        case 'U':
        case 'V':
        case 'W':
        case 'X':
        case 'Y':
        case 'Z':
        case '_': {
            while (isalnum(*stream) || *stream == '_') {
                stream++;
            }
            token.kind = TOKEN_NAME;
        } break;
        default: {
            token.kind = *stream++;
        } break;
    }
    token.end = stream;
}

inline void
PrintToken(Token token) {
    switch(token.kind) {
        case TOKEN_INT: {
            printf("TOKEN INT: %llu\n", token.val);
        } break;
        case TOKEN_NAME: {
            printf("TOKEN NAME: %.*s\n", (int)(token.end - token.start), token.start);
        } break;
        default: {
            printf("TOKEN '%c'\n", token.kind);
        } break;
    }
}

internal LexTest() {
    char *source = "+()1234+42_HELLO1,23+foo!Yeah...93";
    stream = source;
    NextToken();
    while (token.kind) {
        PrintToken(token);
        NextToken();
    }
}

int main(int argc, char **argv) {
    BufTest();
    LexTest();
    return 0;
}
