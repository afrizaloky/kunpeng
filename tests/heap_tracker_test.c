#include "heap_tracker.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
int main(void)
{
    unsigned char *p = heap_calloc(4, 8);
    CHECK(p && (uintptr_t)p % _Alignof(max_align_t) == 0);
    for (size_t i = 0; i < 32; ++i) CHECK(p[i] == 0);
    memset(p, 0x5a, 32);
    size_t first = heap_totals.live;
    CHECK(first > 32);
    CHECK(heap_calloc(SIZE_MAX, 2) == NULL);
    CHECK(heap_malloc(SIZE_MAX) == NULL);
    heap_fail_next();
    CHECK(heap_realloc(p, 64) == NULL);
    CHECK(heap_totals.live == first && p[31] == 0x5a);
    unsigned char *q = heap_realloc(p, 64);
    CHECK(q && q != p && q[31] == 0x5a);
    CHECK(heap_totals.peak == first + heap_totals.live);
    q = heap_realloc(q, 8);
    CHECK(q && q[7] == 0x5a);
    CHECK(heap_realloc(q, 0) == NULL && heap_totals.live == 0);
    p = heap_realloc(NULL, 16);
    CHECK(p);
    heap_free(p);
    heap_free(NULL);
    p = heap_calloc(0, SIZE_MAX);
    CHECK(p);
    heap_free(p);
    heap_fail_next();
    CHECK(heap_calloc(2, 4) == NULL && heap_totals.live == 0);
    puts("heap tracker semantics passed");
    return 0;
}
