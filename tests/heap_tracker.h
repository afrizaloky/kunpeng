#ifndef HEAP_TRACKER_H
#define HEAP_TRACKER_H
#include <stddef.h>
struct heap_totals { size_t live, peak, allocations, engine_allocations; };
extern struct heap_totals heap_totals;
void *heap_malloc(size_t size);
void *heap_calloc(size_t count, size_t size);
void *heap_realloc(void *pointer, size_t size);
void heap_free(void *pointer);
void heap_fail_next(void);
void *heap_crypto_malloc(size_t size, const char *file, int line);
void *heap_crypto_realloc(void *pointer, size_t size, const char *file, int line);
void heap_crypto_free(void *pointer, const char *file, int line);
void *heap_engine_calloc(size_t count, size_t size);
#endif
