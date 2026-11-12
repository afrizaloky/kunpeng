#include "heap_tracker.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Count requested payload plus our aligned header, not libc arena overhead.
 * Serialized test only; moving realloc deliberately counts both live blocks. */
union allocation { max_align_t alignment; size_t size; };
struct heap_totals heap_totals;
static int fail_next;
void heap_fail_next(void) { fail_next = 1; }
void *heap_malloc(size_t size)
{
    if (size > SIZE_MAX - sizeof(union allocation)) return NULL;
    size_t total = sizeof(union allocation) + size;
    if (total > SIZE_MAX - heap_totals.live) return NULL;
    if (fail_next) { fail_next = 0; return NULL; }
    union allocation *block = malloc(total);
    if (!block) return NULL;
    block->size = total;
    heap_totals.live += total;
    if (heap_totals.live > heap_totals.peak) heap_totals.peak = heap_totals.live;
    ++heap_totals.allocations;
    return block + 1;
}
void heap_free(void *pointer)
{
    if (!pointer) return;
    union allocation *block = (union allocation *)pointer - 1;
    heap_totals.live -= block->size;
    free(block);
}
void *heap_calloc(size_t count, size_t size)
{
    if (size && count > SIZE_MAX / size) return NULL;
    size_t bytes = count * size;
    void *pointer = heap_malloc(bytes);
    if (pointer) memset(pointer, 0, bytes);
    return pointer;
}
void *heap_realloc(void *pointer, size_t size)
{
    if (!pointer) return heap_malloc(size);
    if (!size) { heap_free(pointer); return NULL; }
    union allocation *block = (union allocation *)pointer - 1;
    size_t old_size = block->size - sizeof(*block);
    void *replacement = heap_malloc(size);
    if (!replacement) return NULL;
    memcpy(replacement, pointer, old_size < size ? old_size : size);
    heap_free(pointer);
    return replacement;
}
void *heap_crypto_malloc(size_t size, const char *file, int line)
{
    (void)file; (void)line;
    return heap_malloc(size);
}
void *heap_crypto_realloc(void *pointer, size_t size, const char *file, int line)
{
    (void)file; (void)line;
    return heap_realloc(pointer, size);
}
void heap_crypto_free(void *pointer, const char *file, int line)
{
    (void)file; (void)line;
    heap_free(pointer);
}
void *heap_engine_calloc(size_t count, size_t size)
{
    void *pointer = heap_calloc(count, size);
    if (pointer) ++heap_totals.engine_allocations;
    return pointer;
}
