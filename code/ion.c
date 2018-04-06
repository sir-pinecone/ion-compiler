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
#include <math.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include "types.h"

#define internal static
#define global_variable static

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#define ARRAY_COUNT(array) (sizeof(array) / sizeof((array)[0]))

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

internal void
syntax_error(char *format, ...) {
    va_list args;
    va_start(args, format);
    // Unsafe for now, but we'll replace it with a stretchy buffer string builder eventually...
    printf("Syntax Error: ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
    fflush(stdout);
}

internal void
fatal_syntax_error(char *format, ...) {
    va_list args;
    va_start(args, format);
    // Unsafe for now, but we'll replace it with a stretchy buffer string builder eventually...
    printf("Fatal Syntax Error: ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
    exit(1);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Stetchy buffers
////////////////////////////////////////////////////////////////////////////////////////////////////

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
#define _buf_maybe_pop(b) (_buf_hdr(b)->len ? (b)[--_buf_hdr(b)->len] : 0)

#define buf_count(b) ((b) ? _buf_hdr(b)->len : 0)
#define buf_cap(b) ((b) ? _buf_hdr(b)->cap : 0)
#define buf_end(b) ((b) + buf_count(b))
#define buf_fit(b, n) ((n) <= buf_cap(b) ? 0 : ((b) = _buf_grow((b), (n), sizeof(*(b)))))
#define buf_push(b, ...) (buf_fit((b), 1 + buf_count(b)), (b)[_buf_hdr(b)->len++] = (__VA_ARGS__))
#define buf_pop(b) ((b) ? (_buf_maybe_pop((b))) : 0)
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

    size_t new_cap = MAX(64, MAX(1 + 2 * buf_cap(buf), new_len));
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
    for (size_t i = 0; i < buf_count(buf); i++) {
        assert(buf[i] == i);
    }
    buf_free(buf);
    assert(buf == NULL);
    assert(buf_count(buf) == 0);

    for (u32 i = 1; i < n; i++) {
        buf_push(buf, i);
    }
    i32 size = buf_count(buf);
    for (i32 i = n - 1; i > 0; --i) {
        i32 val = buf_pop(buf);
        --size;
        assert(val == i);
        assert(size == buf_count(buf));
    }
    assert(buf_count(buf) == 0);
    assert(buf_pop(buf) == 0);
    assert(buf_pop(buf) == 0);

    buf_push(buf, 1);
    assert(buf_count(buf) == 1);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// String Interning
////////////////////////////////////////////////////////////////////////////////////////////////////

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

////////////////////////////////////////////////////////////////////////////////////////////////////
// Lexer
////////////////////////////////////////////////////////////////////////////////////////////////////

typedef enum TokenKind {
    TOKEN_EOF,
    TOKEN_COLON,
    TOKEN_DBL_COLON,
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_LBRACE,
    TOKEN_RBRACE,
    TOKEN_LBRACKET,
    TOKEN_RBRACKET,
    TOKEN_COMMA,
    TOKEN_DOT,
    TOKEN_QUESTION,
    TOKEN_SEMICOLON,
    TOKEN_PROC_RETURN,
    // TOKEN_KEYWORD,
    TOKEN_INT,     // @improve Add i32 & i64 support.
    TOKEN_FLOAT,   // @improve Add f32 & f64 support.
    TOKEN_STR,
    TOKEN_NAME,
    // Unary precedence
    TOKEN_EXP,     // @question Want this still?
    TOKEN_NEG,
    TOKEN_NOT,
    // Multiplicative precedence
    TOKEN_MUL,
    TOKEN_DIV,
    TOKEN_MOD,
    TOKEN_AND,
    TOKEN_LSHIFT,
    TOKEN_RSHIFT,
    // Additive precedence
    TOKEN_ADD,
    TOKEN_SUB,
    TOKEN_XOR,
    TOKEN_OR,
    // @incomplete Comparitative precedence
    TOKEN_EQ,
    TOKEN_NOT_EQ,
    TOKEN_LT,
    TOKEN_GT,
    TOKEN_LT_EQ,
    TOKEN_GT_EQ,
    TOKEN_AND_AND,
    TOKEN_OR_OR,
    // @incomplete Assignment operators
    TOKEN_ASSIGN,
    TOKEN_ADD_ASSIGN,
    TOKEN_SUB_ASSIGN,
    TOKEN_OR_ASSIGN,
    TOKEN_AND_ASSIGN,
    TOKEN_XOR_ASSIGN,
    TOKEN_LSHIFT_ASSIGN,
    TOKEN_RSHIFT_ASSIGN,
    TOKEN_MUL_ASSIGN,
    TOKEN_DIV_ASSIGN,
    TOKEN_MOD_ASSIGN,
    TOKEN_INC,
    TOKEN_DEC,
    TOKEN_COLON_ASSIGN
} TokenKind;

typedef enum TokenMod {
    TOKENMOD_NONE,
    TOKENMOD_HEX,
    TOKENMOD_BIN,
    TOKENMOD_OCT,
    TOKENMOD_CHAR,
} TokenMod;

char *token_kind_names[] = {
    [TOKEN_EOF]           = "EOF",
    [TOKEN_COLON]         = ":",
    [TOKEN_DBL_COLON]     = "::",
    [TOKEN_LPAREN]        = "(",
    [TOKEN_RPAREN]        = ")",
    [TOKEN_LBRACE]        = "{",
    [TOKEN_RBRACE]        = "}",
    [TOKEN_LBRACKET]      = "[",
    [TOKEN_RBRACKET]      = "]",
    [TOKEN_COMMA]         = ",",
    [TOKEN_DOT]           = ".",
    [TOKEN_QUESTION]      = "?",
    [TOKEN_SEMICOLON]     = ";",
    [TOKEN_PROC_RETURN]   = "->",
    //[TOKEN_KEYWORD]     = ???
    [TOKEN_INT]           = "integer",
    [TOKEN_FLOAT]         = "float",
    [TOKEN_NAME]          = "name",
    [TOKEN_STR]           = "string",
    [TOKEN_EXP]           = "**",
    [TOKEN_NEG]           = "~",
    [TOKEN_NOT]           = "!",
    [TOKEN_MUL]           = "*",
    [TOKEN_DIV]           = "/",
    [TOKEN_MOD]           = "%",
    [TOKEN_AND]           = "&",
    [TOKEN_LSHIFT]        = "<<",
    [TOKEN_RSHIFT]        = ">>",
    [TOKEN_ADD]           = "+",
    [TOKEN_SUB]           = "-",
    [TOKEN_XOR]           = "^",
    [TOKEN_OR]            = "|",
    [TOKEN_EQ]            = "==",
    [TOKEN_NOT_EQ]        = "! =",
    [TOKEN_LT]            = "<",
    [TOKEN_GT]            = ">",
    [TOKEN_LT_EQ]         = "<=",
    [TOKEN_GT_EQ]         = ">=",
    [TOKEN_AND_AND]       = "&&",
    [TOKEN_OR_OR]         = "||",
    [TOKEN_ASSIGN]        = "=",
    [TOKEN_ADD_ASSIGN]    = "+=",
    [TOKEN_SUB_ASSIGN]    = "-=",
    [TOKEN_OR_ASSIGN]     = "|=",
    [TOKEN_AND_ASSIGN]    = "&=",
    [TOKEN_XOR_ASSIGN]    = "^=",
    [TOKEN_LSHIFT_ASSIGN] = "<<=",
    [TOKEN_RSHIFT_ASSIGN] = ">>=",
    [TOKEN_MUL_ASSIGN]    = "*=",
    [TOKEN_DIV_ASSIGN]    = "/=",
    [TOKEN_MOD_ASSIGN]    = "%=",
    [TOKEN_INC]           = "++",
    [TOKEN_DEC]           = "--",
    [TOKEN_COLON_ASSIGN]  = ":=",
};

typedef struct Token {
    TokenKind kind;
    TokenMod mod;
    // All tokens contain the string literal that it represents.
    char *start;
    char *end;
    union {
        u64 int_val;
        f64 float_val;
        char *str_val;
        char *name; // Interned name for an identifier.
    };
} Token;

Token token;
char *stream;

// @warning This returns a pointer to a static internal buffer, so it'll be overwritten next call.
internal char *
token_kind_name(TokenKind kind) {
    if (kind < ARRAY_COUNT(token_kind_names)) {
        return token_kind_names[kind];
    }
    else {
        return "<unknown>";
    }
}

internal char *
token_info() {
    if (token.kind == TOKEN_NAME) { // @incomplete token_keyword
        return token.name;
    }
    else {
        return token_kind_name(token.kind);
    }
}

char char_to_digit[256] = {
    ['0'] = 0,
    ['1'] = 1,
    ['2'] = 2,
    ['3'] = 3,
    ['4'] = 4,
    ['5'] = 5,
    ['6'] = 6,
    ['7'] = 7,
    ['8'] = 8,
    ['9'] = 9,
    ['a'] = 10, ['A'] = 10,
    ['b'] = 11, ['B'] = 11,
    ['c'] = 12, ['C'] = 12,
    ['d'] = 13, ['D'] = 13,
    ['e'] = 14, ['E'] = 14,
    ['f'] = 15, ['F'] = 15,
};

char escape_to_digit[256] = {
    ['n'] = '\n',
    ['r'] = '\r',
    ['v'] = '\v',
    ['t'] = '\t',
    ['b'] = '\b',
    ['a'] = '\a',
    ['"'] = '\"',
    ['\\'] = '\\',
    ['0'] = 0,
};

internal void
scan_char() {
    assert(*stream == '\'');
    ++stream;

    char val = 0;
    if (*stream == '\'') {
        fatal_syntax_error("Char literal cannot be empty");
        ++stream;
    } else if (*stream == '\n') {
        fatal_syntax_error("Char literal cannot contain a newline");
    } else if (*stream == '\\') {
        ++stream;
        val = escape_to_digit[*stream];
        if (val == 0 && *stream != '0') {
            syntax_error("Invalid escape char literal '\\%c'", *stream);
        }
        ++stream;
    } else {
        val = *stream;
        ++stream;
    }

    if (*stream != '\'') {
        fatal_syntax_error("Expected closing char literal quote, but got '%c' instead", *stream);
    }

    ++stream;

    token.kind = TOKEN_INT;
    token.mod = TOKENMOD_CHAR;
    token.int_val = val;
}

internal void
scan_str() {
    assert(*stream == '"');
    ++stream;
    char *str = NULL;
    while (*stream && *stream != '"') {
        char val = *stream;
        if (val == '\n') {
            syntax_error("String literal cannot contain a newline. Invalid string value: %.*s\\n\n", (int)(stream - token.start - 1), str);
            ++stream;
            continue;
        }
        if (val == '\\') {
            ++stream;
            val = escape_to_digit[*stream];
            if (val == 0 && *stream != '0') {
                syntax_error("Invalid string escape literal '\\%c'", *stream);
            }
        }
        buf_push(str, val);
        ++stream;
    }

    if (*stream) {
        assert(*stream == '"');
        ++stream;
    } else {
        fatal_syntax_error("Unexpected end of file within string literal:\n%s\n", token.start);
    }

    token.kind = TOKEN_STR;
    token.str_val = str_intern_range(str, buf_end(str));
}

internal void
scan_int() {
    u64 base = 10;
    if (*stream == '0') {
        ++stream;
        if (*stream && isalnum(*stream)) {
            if (tolower(*stream) == 'x') {
                ++stream;
                token.mod = TOKENMOD_HEX;
                base = 16; // Hex.
            }
            else if (tolower(*stream) == 'b') {
                ++stream;
                token.mod = TOKENMOD_BIN;
                base = 2;
            }
            else if (isdigit(*stream)) {
                token.mod = TOKENMOD_OCT;
                base = 8; // Octal.
            }
            else {
                syntax_error("Invalid integer literal suffix '%c'!", *stream);
                ++stream;
            }
        }
    }

    u64 val = 0;
    for (;;) {
        u64 digit = char_to_digit[*stream];

        if (digit == 0 && *stream != '0') break;
        if (digit >= base) {
            fatal_syntax_error("Digit '%c' out of range for base %llu!", *stream, base);
            digit = 0;
        }

        ++stream;
        if (val > (UINT64_MAX - digit) / base) {
            syntax_error("Integer literal overflow!");
            while (digit = char_to_digit[*stream] && (digit != 0 || *stream != '0')) {
                ++stream;
            }
            val = 0;
        }
        else {
            val = val * base + digit;
        }
    }

    token.kind = TOKEN_INT;
    token.int_val = val;
}

// FLOAT = [0-9]*[.][0-9]*([eE][+-]?[0-9]+)?
internal void
scan_float() {
    char *start = stream;
    while (isdigit(*stream)) {
        ++stream;
    }
    if (*stream == '.') {
        ++stream;
    }
    else if (tolower(*stream) == 'e') {
        ++stream;
        if (*stream == '+' || *stream == '-') {
            ++stream;
        }
        if (!isdigit(*stream)) {
            syntax_error("Expected digit after float literal exponent. Found '%c' instead!", *stream);
        }
    }
    else {
        syntax_error("Expected '.' or 'e' in float literal. Found '%c' instead!", *stream);
    }

    while (isdigit(*stream)) {
        ++stream;
    }

    char *end = stream;
    f64 val = strtod(start, NULL);
    if (val == HUGE_VAL || val == -HUGE_VAL) {
        syntax_error("Float literal overflow!");
    }

    token.kind = TOKEN_FLOAT;
    token.float_val = val;
}

#define CASE1(c1, k1) \
    case c1: { \
        token.kind = k1; \
        ++stream; \
    } break;

#define CASE2(c1, k1, c2, k2) \
    case c1: { \
        token.kind = k1; \
        ++stream; \
        if (*stream == c2) { \
            token.kind = k2; \
            ++stream; \
        } \
    } break;

#define CASE3(c1, k1, c2, k2, c3, k3) \
    case c1: { \
        token.kind = k1; \
        ++stream; \
        if (*stream == c2) { \
            token.kind = k2; \
            ++stream; \
        } else if (*stream == c3) { \
            token.kind = k3; \
            ++stream; \
        } \
    } break;

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
repeat:
    token.start = stream; // It may not be null-terminated!
    token.mod = 0;

    switch (*stream) {
        case ' ': case '\r': case '\n': case '\t': case '\v': {
            while (isspace(*stream)) {
                stream++;
            }
            goto repeat;
        } break;

        case '\'': {
            scan_char();
        } break;

        case '"': {
            scan_str();
        } break;

        case '.': {
            scan_float();
        } break;

        case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9': {
            while (isdigit(*stream)) {
                ++stream;
            }
            char c = *stream;
            stream = token.start;
            if (c == '.' || c == 'e') {
                scan_float();
            } else {
                scan_int();
            }
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

        case '<': {
            token.kind = TOKEN_LT;
            ++stream;
            if (*stream == '<') {
                token.kind = TOKEN_LSHIFT;
                ++stream;
                if (*stream == '=') {
                    token.kind = TOKEN_LSHIFT_ASSIGN;
                    ++stream;
                }
            }
            else if (*stream == '=') {
                token.kind = TOKEN_LT_EQ;
                ++stream;
            }
        } break;

        case '>': {
            token.kind = TOKEN_GT;
            ++stream;
            if (*stream == '>') {
                token.kind = TOKEN_RSHIFT;
                ++stream;
                if (*stream == '=') {
                    token.kind = TOKEN_RSHIFT_ASSIGN;
                    ++stream;
                }
            }
            else if (*stream == '=') {
                token.kind = TOKEN_GT_EQ;
                ++stream;
            }
        } break;

        case '-': {
            token.kind = TOKEN_SUB;
            ++stream;
            if (*stream == '-') {
                token.kind = TOKEN_DEC;
                ++stream;
            }
            else if (*stream == '=') {
                token.kind = TOKEN_SUB_ASSIGN;
                ++stream;
            }
            else if (*stream == '>') {
                token.kind = TOKEN_PROC_RETURN;
                ++stream;
            }
        } break;

        CASE1('\0', TOKEN_EOF)
        CASE1('(', TOKEN_LPAREN)
        CASE1(')', TOKEN_RPAREN)
        CASE1('{', TOKEN_LBRACE)
        CASE1('}', TOKEN_RBRACE)
        CASE1('[', TOKEN_LBRACKET)
        CASE1(']', TOKEN_RBRACKET)
        CASE1(',', TOKEN_COMMA)
        CASE1('?', TOKEN_QUESTION)
        CASE1(';', TOKEN_SEMICOLON)
        CASE1('~', TOKEN_NEG)
        //CASE1('.', TOKEN_DOT)

        CASE2('=', TOKEN_ASSIGN, '=', TOKEN_EQ)
        CASE2('!', TOKEN_NOT,    '=', TOKEN_NOT_EQ)
        CASE2('^', TOKEN_XOR,    '=', TOKEN_XOR_ASSIGN)
        CASE2('/', TOKEN_DIV,    '=', TOKEN_DIV_ASSIGN)
        CASE2('%', TOKEN_MOD,    '=', TOKEN_MOD_ASSIGN)

        CASE3(':', TOKEN_COLON, ':', TOKEN_DBL_COLON, '=', TOKEN_COLON_ASSIGN)
        CASE3('*', TOKEN_MUL,   '*', TOKEN_EXP,       '=', TOKEN_MUL_ASSIGN)
        CASE3('+', TOKEN_ADD,   '+', TOKEN_INC,       '=', TOKEN_ADD_ASSIGN)
        CASE3('&', TOKEN_AND,   '&', TOKEN_AND_AND,   '=', TOKEN_AND_ASSIGN)
        CASE3('|', TOKEN_OR,    '|', TOKEN_OR_OR,     '=', TOKEN_OR_ASSIGN)

        default: {
            syntax_error("Unrecognized stream character: %c!", *stream);
            ++stream;
            goto repeat;
        } break;
    }
    token.end = stream;
}

#undef CASE1
#undef CASE2
#undef CASE3

inline void
init_stream(char *str) {
    stream = str;
    next_token();
}

inline void
print_token(Token token) {
    switch(token.kind) {
        case TOKEN_INT: {
            printf("TOKEN INT: %llu\n", token.int_val);
        } break;
        case TOKEN_FLOAT: {
            printf("TOKEN FLOAT: %f\n", token.float_val);
        } break;
        case TOKEN_NAME: {
            printf("TOKEN NAME: %.*s (intern &%p)\n", (int)(token.end - token.start), token.start, token.name);
        } break;
        case TOKEN_LSHIFT: {
            printf("TOKEN LSHIFT\n");
        } break;
        case TOKEN_RSHIFT: {
            printf("TOKEN RSHIFT\n");
        } break;
        case TOKEN_EXP: {
            printf("TOKEN EXPONENT\n");
        } break;
        default: {
            printf("TOKEN '%c'\n", token.kind);
        } break;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Parser
////////////////////////////////////////////////////////////////////////////////////////////////////

inline b32
is_token(TokenKind kind) {
    return token.kind == kind;
}

inline b32
is_token_name(char *name) {
    return token.kind == TOKEN_NAME && token.name == name;
}

inline b32
is_token_mod(TokenMod mod) {
    return token.mod == mod;
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
        fatal("Expected token %s, got %s instead", token_kind_name(kind), token_info());
        return false;
    }
}

inline b32
match_token_with_mod(TokenKind kind, TokenMod mod) {
    if (is_token(kind) && is_token_mod(mod)) {
        next_token();
        return true;
    } else {
        return false;
    }
}

inline b32
expect_token_with_mod(TokenKind kind, TokenMod mod) {
    if (is_token(kind) && is_token_mod(mod)) {
        next_token();
        return true;
    } else {
        fatal("Expected token %s with mod %d, got kind %s with mod %d instead", token_kind_name(kind), mod, token_info(), token.mod);
        return false;
    }
}

#define assert_token(x)       assert(match_token(x))
#define assert_token_name(x)  assert(token.name == str_intern(x) && match_token(TOKEN_NAME))
#define assert_token_int(x)   assert(token.int_val == (x) && match_token(TOKEN_INT))
#define assert_token_int_mod(x, mod) assert(token.int_val == (x) && match_token_with_mod(TOKEN_INT, mod))
#define assert_token_float(x) assert(token.float_val == (x) && match_token(TOKEN_FLOAT))
#define assert_token_char(x)  assert(token.int_val == (x) && match_token_with_mod(TOKEN_INT, TOKENMOD_CHAR))
#define assert_token_str(x)   assert(token.str_val == str_intern(x) && match_token(TOKEN_STR))
#define assert_token_eof()    assert(is_token(TOKEN_EOF))

internal void
lex_test() {
    //
    // Operator tests
    //
    init_stream("< << <= <<= : := = == + ++ += ! != :: ->");
    assert_token(TOKEN_LT);
    assert_token(TOKEN_LSHIFT);
    assert_token(TOKEN_LT_EQ);
    assert_token(TOKEN_LSHIFT_ASSIGN);
    assert_token(TOKEN_COLON);
    assert_token(TOKEN_COLON_ASSIGN);
    assert_token(TOKEN_ASSIGN);
    assert_token(TOKEN_EQ);
    assert_token(TOKEN_ADD);
    assert_token(TOKEN_INC);
    assert_token(TOKEN_ADD_ASSIGN);
    assert_token(TOKEN_NOT);
    assert_token(TOKEN_NOT_EQ);
    assert_token(TOKEN_DBL_COLON);
    assert_token(TOKEN_PROC_RETURN);
    assert_token_eof();

    //
    // Integer tests
    //

    // Decimals
    init_stream("18446744073709551615 42 0 666");
    assert_token_int_mod(18446744073709551615ull, TOKENMOD_NONE); // Verify that UINT64_MAX doesn't trigger an overflow.
    assert_token_int_mod(42, TOKENMOD_NONE);
    assert_token_int_mod(0, TOKENMOD_NONE);
    assert_token_int_mod(666, TOKENMOD_NONE);
    assert_token_eof();

    // Hex
    init_stream("0xFFFFFFFFFFFFFFFF 0x8 0xF 0x5Cf9A 0XA 0x0000000004");
    assert_token_int_mod(0xFFFFFFFFFFFFFFFF, TOKENMOD_HEX); // Verify that UINT64_MAX doesn't trigger an overflow.
    assert_token_int_mod(8, TOKENMOD_HEX);
    assert_token_int_mod(15, TOKENMOD_HEX);
    assert_token_int_mod(0X5CF9A, TOKENMOD_HEX);
    assert_token_int_mod(0xA, TOKENMOD_HEX);
    assert_token_int_mod(4, TOKENMOD_HEX);
    assert_token_eof();

    // Octal
    init_stream("01777777777777777777777 010 01234567 00 000001");
    assert_token_int_mod(01777777777777777777777, TOKENMOD_OCT); // Verify that UINT64_MAX doesn't trigger an overflow.
    assert_token_int_mod(010, TOKENMOD_OCT);
    assert_token_int_mod(01234567, TOKENMOD_OCT);
    assert_token_int_mod(00, TOKENMOD_OCT);
    assert_token_int_mod(000001, TOKENMOD_OCT);
    assert_token_eof();

    // Binary
    init_stream("0b1111111111111111111111111111111111111111111111111111111111111111 0b0001 0b10000 0b01111");
    assert_token_int_mod(18446744073709551615ull, TOKENMOD_BIN); // Verify that UINT64_MAX doesn't trigger an overflow.
    assert_token_int_mod(1, TOKENMOD_BIN);
    assert_token_int_mod(16, TOKENMOD_BIN);
    assert_token_int_mod(0xF, TOKENMOD_BIN);
    assert_token_eof();

    //
    // Float tests
    //
    init_stream("3.14 .123 42. 2e5 4e-3 88.987654321");
    assert_token_float(3.14);
    assert_token_float(.123);
    assert_token_float(42.);
    assert_token_float(2e5);
    assert_token_float(4e-3);
    assert_token_float(88.987654321);
    assert_token_eof();

    //
    // Char literal tests
    //
    init_stream("'a' '\\n' '\\b' '\"' '\\\\' '0'");
    assert_token_char('a');
    assert_token_char('\n');
    assert_token_char('\b');
    assert_token_char('\"');
    assert_token_char('\\');
    assert_token_char('0');
    assert_token_eof();

    //
    // String tests
    //
    init_stream("\"\" \"  \" \"bob\" \"Michael was a wild man!\" \"yes\\nthis\\nis\\na\\nbroken\\nstring\"");
    assert_token_str("");
    assert_token_str("  ");
    assert_token_str("bob");
    assert_token_str("Michael was a wild man!");
    assert_token_str("yes\nthis\nis\na\nbroken\nstring");
    assert_token_eof();

    init_stream("\"\\\\\"  \"\\\\z\\n\" \"\\\"z\\\"\\n\" \"\\\\\\\"z\\\\\\\"\\n\" \"\\t\\b\\a\"");
    assert_token_str("\\");
    assert_token_str("\\z\n");
    assert_token_str("\"z\"\n");
    assert_token_str("\\\"z\\\"\n");
    assert_token_str("\t\b\a");
    assert_token_eof();

    //
    // Misc tests
    //
    init_stream("XY+(XY) 1234 - 42_HELLO1,23*foo!Yeah93<<8+8>>2+2**4");
    assert_token_name("XY");
    assert_token(TOKEN_ADD);
    assert_token(TOKEN_LPAREN);
    assert_token_name("XY");
    assert_token(TOKEN_RPAREN);
    assert_token_int(1234);
    assert_token(TOKEN_SUB);
    assert_token_int(42);
    assert_token_name("_HELLO1");
    assert_token(TOKEN_COMMA);
    assert_token_int(23);
    assert_token(TOKEN_MUL);
    assert_token_name("foo");
    assert_token(TOKEN_NOT);
    assert_token_name("Yeah93");
    assert_token(TOKEN_LSHIFT);
    assert_token_int(8);
    assert_token(TOKEN_ADD);
    assert_token_int(8);
    assert_token(TOKEN_RSHIFT);
    assert_token_int(2);
    assert_token(TOKEN_ADD);
    assert_token_int(2);
    assert_token(TOKEN_EXP);
    assert_token_int(4);
    assert_token_eof();

}

#undef assert_token
#undef assert_token_name
#undef assert_token_int
#undef assert_token_int_mod
#undef assert_token_float
#undef assert_token_char
#undef assert_token_str
#undef assert_token_eof

#if 0
 // Grammar in order of precedence:

  factor = INT | '(' expr ')'
  unary  = [-+~]unary | factor         (unary is right-associative)
  term   = unary ([*/%<<>>&] unary)*   (left-associative)
  expr   = term ([+-|^] term)*         (left-associative)
#endif

i64 parse_expr();

internal i64
parse_factor() {
    i64 result;
    if (is_token(TOKEN_INT)) {
        printf("%llu", token.int_val);
        result = token.int_val;
        next_token();
    }
    else if (match_token(TOKEN_LPAREN)) {
        printf(token_kind_names[TOKEN_LPAREN]);
        result = parse_expr();
        expect_token(TOKEN_RPAREN);
        printf(token_kind_names[TOKEN_RPAREN]);
    }
    else {
        fatal("Expected integer or '%s', got %s instead",
              token_kind_name(TOKEN_LPAREN), token_kind_name(token.kind));
        result = 0;
    }
    return result;
}

internal i64
parse_power() {
    // Exponentiation binds very tightly, so 2 + 3**2 * 4 == 2 + ((3**2) * 4)
    i64 result = parse_factor();
    while (is_token(TOKEN_EXP)) {
        printf(token_kind_name(TOKEN_EXP));
        next_token();
        i64 power = parse_factor();
        i64 base = result;
        result = 1;
        for (u64 i = 0; i < power; ++i) {
            result *= base;
        }
    }
    return result;
}

internal i64
parse_unary() {
    // Right associative
    i64 result;
    if (is_token(TOKEN_SUB) || is_token(TOKEN_DEC) || is_token(TOKEN_ADD) || is_token(TOKEN_NEG)) {
        TokenKind op = token.kind;
        printf(token_kind_name(op));
        next_token();
        i64 rval = parse_unary();
        if (op == TOKEN_SUB) {
            result = -rval;
        }
        else if (op == TOKEN_DEC) {
            result = rval - 1;
        }
        else if (op == TOKEN_NEG) {
            result = ~rval;
        }
        else {
            assert(op == TOKEN_ADD);
            result = rval;
        }
    }
    else {
        result = parse_power();
    }
    return result;
}

internal i64
parse_term() {
    // Left associative
    i64 result = parse_unary();
    while (is_token(TOKEN_MUL) || is_token(TOKEN_DIV) || is_token(TOKEN_MOD) || is_token(TOKEN_AND) ||
           is_token(TOKEN_LSHIFT) || is_token(TOKEN_RSHIFT)) {
        TokenKind op = token.kind;
        next_token();
        i64 rval = parse_unary();
        if (op == TOKEN_LSHIFT) {
            result = result << rval;
        }
        else if (op == TOKEN_RSHIFT) {
            result = result >> rval;
        }
        else {
            printf(token_kind_name(op));
            if (op == TOKEN_MUL) {
                result *= rval;
            }
            else if (op == TOKEN_DIV) {
                assert(rval != 0);
                result /= rval;
            }
            else if (op == TOKEN_MOD) {
                result %= rval;
            }
            else if (op == TOKEN_AND) {
                result &= rval;
            }
        }
    }
    return result;
}

internal i64
parse_expr() {
    // Left associative
    i64 result = parse_term();
    while (is_token(TOKEN_ADD) || is_token(TOKEN_SUB) || is_token(TOKEN_OR) || is_token(TOKEN_XOR)) {
        TokenKind op= token.kind;
        printf(token_kind_name(op));
        next_token();
        i64 rval = parse_term();
        // Left-fold
        if (op == TOKEN_ADD) {
            result += rval;
        }
        else if (op == TOKEN_SUB) {
            result -= rval;
        }
        else if (op == TOKEN_OR) {
            result |= rval;
        }
        else {
            assert(op == TOKEN_XOR);
            result ^= rval;
        }
    }
    return result;
}

inline i64
parse_expr_str(char *str) {
    init_stream(str);
    printf("\nParse test for \"%s\":\n  ", str);
    i64 result = parse_expr();
    printf(" = %lld\n", result);
    return result;
}

#define assert_expr(x) assert(parse_expr_str(#x) == (x))
#define assert_expr_with_result(x, r) assert(parse_expr_str(#x) == (r))

internal void
parse_test() {
    assert_expr(1);
    assert_expr(-5);
    assert_expr((1));
    assert_expr((1 + 2));
    assert_expr(1 - 2 - 3);
    assert_expr(2 * 3 + 4 *5);
    assert_expr(2 * (3 + 4) * 5);
    assert_expr(2 + -3);
    assert_expr(-(3 + 8 - 2));
    assert_expr((10 / 5) * ((2 - 5) + (25 / 5)));

    assert_expr_with_result(--3, 2);
    assert_expr_with_result(--0, -1);
    assert_expr_with_result(---5, -6);   // (--(-5))
    assert_expr_with_result(---(-3), 2); // (--(-(-3)))
    assert_expr_with_result(-----3, -5); // (-- (-- (-3)))

    assert_expr(+3);
    assert_expr(-+3);
    assert_expr(+-3);

    assert_expr(~1);
    assert_expr(~-2);
    assert_expr(~0);

    assert_expr(2^10);
    assert_expr(10^-4);
    assert_expr(-10^-4);

    assert_expr(2 | 10);
    assert_expr(10 | -4);
    assert_expr(-10 | -4);

    assert_expr(8 % 3);
    assert_expr(9 % 1);

    assert_expr(22 & 12);
    assert_expr(22 & -4);

    assert_expr(2 << 4);
    assert_expr(32 >> 2);

    assert_expr_with_result(2 ** 5, (2 * 2 * 2 * 2 * 2));
    assert_expr_with_result(3 + 2 ** 5 * 4, (3 + (2 * 2 * 2 * 2 * 2) * 4));
    assert_expr_with_result(2 ** 1, 2);
    assert_expr_with_result(2 ** 0, 1);

    // @improve Have a way to test for expected failures, such as a divide by 0.
    //assert_expr(1/0);
}

#undef assert_expr
#undef assert_expr_with_result

internal void
run_tests() {
    buf_test();
    lex_test();
    str_intern_test();
    parse_test();
}

int main(int argc, char **argv) {
    run_tests();
    return 0;
}
