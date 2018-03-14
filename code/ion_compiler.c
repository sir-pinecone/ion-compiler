/*==================================================================================================
  File: ion_compiler.c
  Creation Date: 2018-03-13
  Creator: Michael Campagnaro
  Notice: (C) Copyright 2018 by Jelly Pixel, Inc. All Rights Reserved.
  ================================================================================================*/

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>

#define internal static
#define global_variable static

#define MAX(a, b) ((a) >= (b) ? (a) : (b))

typedef struct BufHdr {
    size_t len;
    size_t cap;
    char buf[0];
} BufHdr;

#define buf__hdr(b) ((BufHdr *)((char *)b - offsetof(BufHdr, b)))
#define buf__fits(b, n) (BufLen(b) + (n) <= BufCap(b))
#define buf__fit(b, n) (buf__fits(b, n) ? 0 : ((b) = __BufGrow((b), BufLen(b) + (n), sizeof(*(b)))))

#define BufLen(b) ((b) ? buf__hdr(b)->len : 0)
#define BufCap(b) ((b) ? buf__hdr(b)->cap : 0)
#define BufPush(b, x) (buf__fit(b, 1), b[BufLen(b)] = (x), buf__hdr(b)->len++)
#define BufFree(b) ((b) ? free(buf__hdr(b)) : 0)

internal void *
__BufGrow(void *buf, size_t new_len, size_t elem_size) {
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
        new_hdr = realloc(buf__hdr(buf), new_size);
    } else {
        new_hdr = malloc(new_size);
        new_hdr->len = 0;
    }
    new_hdr->cap = new_cap;
    return new_hdr->buf; // or new_hdr + 1
}

internal void
BufTest() {
    int *buf = NULL;
    enum { N = 1024 };
    for (int i = 0; i < N; i++) {
        BufPush(buf, i);
    }
    assert(BufLen(buf) == N);
    for (int i = 0; i < BufLen(buf); i++) {
        assert(buf[i] == i);
    }
    BufFree(buf);
}

typedef enum TokenKind {
    TOKEN_INT = 128, // Reserve first 128 ascii values?
    TOKEN_NAME,
    // ...
} TokenKind;

typedef struct Token {
    TokenKind kind;
    union {
        uint64_t val;
        struct {
            char *start;
            char *end;
        };
    };
} Token;

Token token;
char *stream;

// e.g. 1234 (x+y) translates into '1234' '(' 'x' '+' 'y' ')'
internal void
NextToken() {
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
            uint64_t val = 0;
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
            char *start = stream;
            while (isalnum(*stream) || *stream == '_') {
                stream++;
            }
            token.kind = TOKEN_NAME;
            token.start = start; // Not null-terminated at the moment!
            token.end = stream;
        } break;
        default: {
            token.kind = *stream++;
        } break;
    }
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
