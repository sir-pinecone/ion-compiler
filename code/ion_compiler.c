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

int main(int argc, char **argv) {
    BufTest();
    return 0;
}
