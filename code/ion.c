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
fatal(char *format, ...) {
    va_list args;
    va_start(args, format);
    // Unsafe for now, but we'll replace it with a stretchy buffer string builder eventually...
    printf("FATAl: ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
    exit(1);
}

// Stetchy buffers

typedef struct BufHdr {
    size_t len;
    size_t cap;
    char buf[];
} BufHdr;

// TIL: You can use commas inside the macro as a replacement for semicolons,
// when a semicolon would present problems. You can verify this by replacing
// some commas in the stretchy buffer macros and see that it breaks the
// compiler.

#define _buf_hdr(b) ((BufHdr *)((char *)(b) - offsetof(BufHdr, buf)))
#define _buf_fits(b, n) (buf_count(b) + (n) <= buf_cap(b))
#define _buf_fit(b, n) (_buf_fits((b), (n)) ? 0 : ((b) = _buf_grow((b), buf_count(b) + (n), sizeof(*(b)))))

#define buf_count(b) ((b) ? _buf_hdr(b)->len : 0)
#define buf_cap(b) ((b) ? _buf_hdr(b)->cap : 0)
#define buf_end(b) ((b) + buf_count(b))
#define buf_push(b, ...) (_buf_fit((b), 1), (b)[_buf_hdr(b)->len++] = (__VA_ARGS__))
#define buf_free(b) ((b) ? (free(_buf_hdr(b)), (b) = NULL) : 0)

internal void *
_buf_grow(void *buf, size_t new_len, size_t elem_size) {
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

    // Protect against an overflow. This is derived from: 1 + 2 * buf_cap(buf) < SIZE_MAX
    // because we can't assert that as is. Since SIZE_MAX is the
    // largest possible value, if the lhs was to overflow then it would wrap
    // around to a small(er) value and that would be less than SIZE_MAX.
    assert(buf_cap(buf) <= (SIZE_MAX - 1) / 2);

    size_t new_cap = MAX(1 + 2 * buf_cap(buf), new_len);
    assert(new_len <= new_cap);
    assert(new_cap <= (SIZE_MAX - offsetof(BufHdr, buf)) / elem_size); // Overflow check.

    size_t new_size = offsetof(BufHdr, buf) + new_cap * elem_size;

    BufHdr *new_hdr;
    if (buf) {
        new_hdr = xrealloc(_buf_hdr(buf), new_size);
    } else {
        new_hdr = xmalloc(new_size);
        new_hdr->len = 0;
    }
    new_hdr->cap = new_cap;
    return new_hdr->buf; // or new_hdr + 1
}

internal void
buf_test() {
    i32 *buf = NULL;
    assert(buf_count(buf) == 0);
    i32 n = 1024;
    for (u32 i = 0; i < n; i++) {
        buf_push(buf, i);
    }
    assert(buf_count(buf) == n);
    for (u32 i = 0; i < buf_count(buf); i++) {
        assert(buf[i] == i);
    }
    buf_free(buf);
    assert(buf == NULL);
    assert(buf_count(buf) == 0);
}

typedef struct Intern {
    size_t len;
    char *str;
} Intern;

global_variable Intern *interns; // stretchy buf; static = initialized to 0 by default.

/* Interesting note from James Widman:
 *
 * @pervognsen re string interning: something I like to do is,
 * instead of using a _pointer_ to a canonicalized string, I use the _offset_
 * from the base address of the storage area for interned strings. That way,
 * the opaque value can be stable across runs (if you store and load
 * canonicalized strings between runs).
 */

internal char *
str_intern_range(char *start, char *end) {
    // Slower version that uses a stretchy buffer instead of a hash table. Can drop in a hash table
    // later since that's an implementation detail.

    size_t len = end - start;
    for (Intern *it = interns;
         it != buf_end(interns);
         ++it) {
        if ((it->len == len) && (strncmp(it->str, start, len) == 0)) {
            return it->str;
        }
    }

    // Allocate memory for storage as opposed to making the str member in the
    // Intern struct an empty array, i.e. char str[0]. You would get a flat,
    // ordered array of memory, but the intern pointers would change when the
    // stretchy buffer grows (realloc). We want the pointers to be stable so we
    // handle the allocation with malloc. You can speed this up by allocating
    // the strings out of a big linear array, like an arena, but for now this
    // works.
    char *str = xmalloc(len + 1); // We want to store c-strings in the buffer, so +1 for null-terminator.
    memcpy(str, start, len);
    str[len] = 0;
    buf_push(interns, (Intern){len, str});
    return str;
}

internal char *
str_intern(char *str) {
    return str_intern_range(str, str + strlen(str));
}

internal void
str_intern_test() {
    char a[] = "hello";
    assert(strcmp(a, str_intern(a)) == 0);
    assert(str_intern(a) == str_intern(a));
    assert(str_intern(str_intern(a)) == str_intern(a));

    char b[] = "hello";
    assert(a != b);
    assert(str_intern(a) == str_intern(b));

    char c[] = "hello!";
    assert(str_intern(a) != str_intern(c));

    char d[] = "hell";
    assert(str_intern(a) != str_intern(d));
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
        i32 val;
        char *name; // Interned name for an identifier.
    };
} Token;

internal size_t
copy_token_kind_str(char *dest, size_t dest_size, TokenKind kind) {
    size_t copied = 0;
    switch(kind) {
        case 0: {
            copied = snprintf(dest, dest_size, "end of file");
        } break;

        case TOKEN_INT: {
            copied = snprintf(dest, dest_size, "integer");
        } break;

        case TOKEN_NAME: {
            copied = snprintf(dest, dest_size, "name");
        } break;

        default: {
            if (kind < 128 && isprint(kind)) {
                copied = snprintf(dest, dest_size, "'%c'", kind);
            } else {
                copied = snprintf(dest, dest_size, "<ASCII %d>", kind);
            }
        }
    }
    return copied;
}

// @warning This returns a pointer to a static internal buffer, so it'll be overwritten next call.
internal char *
temp_token_kind_str(TokenKind kind) {
    static char buf[256];
    size_t n = copy_token_kind_str(buf, sizeof(buf), kind);
    assert(n + 1 <= sizeof(buf)); // +1 for null terminator, which is not included in the snprintf return.
    return buf;
}

Token token;
char *stream;

char *keyword_if;
char *keyword_for;
char *keyword_while;

internal void
init_keywords() {
    keyword_if = str_intern("if");
    keyword_for = str_intern("for");
    keyword_while = str_intern("while");
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
next_token() {
    token.start = stream; // It may not be null-terminated!
    switch (*stream) {
        case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9': {
            i32 val = 0;
            while(isdigit(*stream)) {
                val *= 10; // Shifts everything over every time we see a new digit.
                val += *stream++ - '0';
            }
            token.kind = TOKEN_INT;
            token.val = val;
        } break;

        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g': case 'h': case 'i':
        case 'j': case 'k': case 'l': case 'm': case 'n': case 'o': case 'p': case 'q': case 'r':
        case 's': case 't': case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': case 'H': case 'I':
        case 'J': case 'K': case 'L': case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R':
        case 'S': case 'T': case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
        case '_': {
            while (isalnum(*stream) || *stream == '_') {
                stream++;
            }
            token.kind = TOKEN_NAME;
            token.name = str_intern_range(token.start, stream);
        } break;
        default: {
            token.kind = *stream++;
        } break;
    }
    token.end = stream;
}

inline void
init_stream(char *str) {
    stream = str;
    next_token();
}

inline void
print_token(Token token) {
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
is_token(TokenKind kind) {
    return token.kind == kind;
}

inline b32
is_token_name(char *name) {
    return token.kind == TOKEN_NAME && token.name == name;
}

inline b32
match_token(TokenKind kind) {
    if (is_token(kind)) {
        next_token();
        return true;
    } else {
        return false;
    }
}

inline b32
expect_token(TokenKind kind) {
    if (is_token(kind)) {
        next_token();
        return true;
    } else {
        char buf[256];
        copy_token_kind_str(buf, sizeof(buf), kind);
        fatal("Expected token %s, got %s instead", buf, temp_token_kind_str(token.kind));
        return false;
    }
}

#define assert_token(x) assert(match_token(x))
#define assert_token_name(x) assert(token.name == str_intern(x) && match_token(TOKEN_NAME))
#define assert_token_int(x) assert(token.val == (x) && match_token(TOKEN_INT))
#define assert_token_eof() assert(is_token(0))

internal void
lex_test() {
    char *source = "XY+(XY)1234+42_HELLO1,23+foo!Yeah...93";
    init_stream(source);
    assert_token_name("XY");
    assert_token('+');
    assert_token('(');
    assert_token_name("XY");
    assert_token(')');
    assert_token_int(1234);
    assert_token('+');
    assert_token_int(42);
    assert_token_name("_HELLO1");
    assert_token(',');
    assert_token_int(23);
    assert_token('+');
    assert_token_name("foo");
    assert_token('!');
    assert_token_name("Yeah");
    assert_token('.');
    assert_token('.');
    assert_token('.');
    assert_token_int(93);
    assert_token_eof();
}

#undef assert_token
#undef assert_token_name
#undef assert_token_int
#undef assert_token_eof

#if 0
 // Grammar in order of precedence:

  factor = INT | '(' expr ')'
  unary  = [-+~]unary | factor         (unary is right-associative)
  term   = unary ([*/%<<>>&] unary)*   (left-associative)
  expr   = term ([+-|^] term)*         (left-associative)
#endif

i32 parse_expr();

internal i32
parse_factor() {
    i32 result;

    if (is_token(TOKEN_INT)) {
        printf("%d", token.val);
        result = token.val;
        next_token();
    }
    else if (match_token('(')) {
        printf("(");
        result = parse_expr();
        expect_token(')');
        printf(")");
    }
    else {
        fatal("Expected integer or '(', got %s instead", temp_token_kind_str(token.kind));
        result = 0;
    }

    return result;
}

internal i32
parse_unary() {
    // Right associative
    i32 result;
    if (is_token('-') || is_token('+') || is_token('~')) {
        char op = token.kind;
        printf("%c", op);
        next_token();
        i32 rval = parse_unary();
        if (op == '-') {
            result = -rval;
        } else if (op == '~') {
            result = ~rval;
        } else {
            assert(op == '+');
            result = rval;
        }
    } else {
        result = parse_factor();
    }

    return result;
}

internal i32
parse_term() {
    // Left associative
    i32 result = parse_unary();
    while (is_token('*') || is_token('/') || is_token('<') || is_token('>') ||
           is_token('%') || is_token('&')) {
        char op = token.kind;
        printf("%c", op);
        next_token();

        // @improve Move this logic into the lexer so that we can represent it with a token value instead.
        if (op == '<' || op == '>') {
            if (is_token(op)) {
                printf("%c", op);
                next_token();
            }
            else {
                fatal("Expected token '%c', got %s instead", op, token_kind_str(token.kind));
                return 0;
            }
        }

        i32 rval = parse_unary();
        if (op == '*') {
            result *= rval;
        } else if (op == '/') {
            assert(rval != 0);
            result /= rval;
        } else if (op == '%') {
            result %= rval;
        } else if (op == '&') {
            result &= rval;
        } else if (op == '<') {
            result = result << rval;
        } else {
            assert(op == '>');
            result = result >> rval;
        }
    }

    return result;
}

internal i32
parse_expr() {
    // Left associative
    i32 result = parse_term();
    while (is_token('+') || is_token('-') || is_token('|') || is_token('^')) {
        char op = token.kind;
        printf("%c", op);
        next_token();

        i32 rval = parse_term();
        // Left-fold
        if (op == '+') {
            result += rval;
        } else if (op == '-') {
            result -= rval;
        } else if (op == '|') {
            result |= rval;
        } else {
            assert(op == '^');
            result ^= rval;
        }
    }

    return result;
}

inline i32
parse_expr_str(char *str) {
    init_stream(str);
    printf("\nParse test for \"%s\":\n  ", str);
    i32 result = parse_expr();
    printf(" = %d\n", result);
    return result;
}

#define TEST_EXPR(x, r) assert(parse_expr_str(#x) == (r))

internal void
parse_test() {
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

    TEST_EXPR(2^10, 8);
    TEST_EXPR(10^-4, -10);
    TEST_EXPR(-10^-4, 10);

    TEST_EXPR(2|10, 10);
    TEST_EXPR(10|-4, -2);
    TEST_EXPR(-10|-4, -2);

    TEST_EXPR(8%3, 2);
    TEST_EXPR(9%1, 0);

    TEST_EXPR(22&12, 4);
    TEST_EXPR(22&-4, 20);

    TEST_EXPR(2<<4, 32);
    TEST_EXPR(32>>2, 8);

    // @improve Have a way to test for expected failures, such as a divide by 0.
    //TEST_EXPR(1/0, 3);
}

#undef TEST_EXPR

int main(int argc, char **argv) {
    buf_test();
    lex_test();
    str_intern_test();
    init_keywords();

    parse_test();

    return 0;
}
