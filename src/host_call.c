#include "host_call.h"
#include <stdlib.h>
#include <string.h>

struct host_call_segment {
    struct host_call_segment *next;
    size_t size;
    unsigned char bytes[];
};
static uint32_t get32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | p[3];
}
static void put32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8); p[3] = (unsigned char)v;
}
int host_call_encode(unsigned char *header, const host_call_chunk *c)
{
    if (!header || !c || !c->operation || !c->id || c->final > 1 || c->length > HOST_CALL_PAYLOAD_CAP ||
        c->offset > HOST_CALL_OBJECT_CAP || c->length > HOST_CALL_OBJECT_CAP - c->offset ||
        (c->status != HOST_CALL_OK && c->status != HOST_CALL_HOST_ERROR)) return -1;
    put32(header, HOST_CALL_VERSION); put32(header + 4, c->operation);
    put32(header + 8, c->id); put32(header + 12, c->offset);
    put32(header + 16, c->status); put32(header + 20, c->final);
    put32(header + 24, c->length);
    put32(header + 28, c->final ? c->offset + c->length : 0);
    return 0;
}
int host_call_decode(const unsigned char *wire, size_t size, host_call_chunk *c)
{
    if (!wire || !c || size < HOST_CALL_HEADER_SIZE || size > HOST_CALL_COMMAND_CAP ||
        get32(wire) != HOST_CALL_VERSION) return -1;
    c->operation = get32(wire + 4); c->id = get32(wire + 8);
    c->offset = get32(wire + 12);
    uint32_t status = get32(wire + 16);
    if (status > HOST_CALL_HOST_ERROR) return -1;
    c->status = (host_call_status)status;
    c->final = get32(wire + 20); c->length = get32(wire + 24);
    if (!c->operation || !c->id || c->final > 1 || c->length != size - HOST_CALL_HEADER_SIZE ||
        c->offset > HOST_CALL_OBJECT_CAP || c->length > HOST_CALL_OBJECT_CAP - c->offset ||
        get32(wire + 28) != (c->final ? c->offset + c->length : 0)) return -1;
    return 0;
}
void host_call_release(host_call *t)
{
    if (!t) return;
    while (t->first) {
        host_call_segment *next = t->first->next;
        t->budget->capacity -= t->first->size;
        memset(t->first->bytes, 0, t->first->size);
        free(t->first); t->first = next;
    }
    t->last = NULL; t->size = 0; t->chunks = 0;
    t->state = HOST_CALL_IDLE;
}
int host_call_begin(host_call *t, host_call_budget *budget, uint32_t op, uint32_t id)
{
    if (!t) return -1;
    host_call_release(t);
    if (!budget || !op || !id || budget->capacity > HOST_CALL_BUDGET_CAP) {
        t->state = HOST_CALL_FAILED;
        return -1;
    }
    t->budget = budget; t->operation = op; t->id = id;
    t->state = HOST_CALL_RECEIVING;
    return 0;
}
int host_call_receive(host_call *t, const unsigned char *wire, size_t size)
{
    host_call_chunk c;
    unsigned char *owned = NULL;
    if (!t) return -1;
    if (!wire || size < HOST_CALL_HEADER_SIZE || size > HOST_CALL_COMMAND_CAP) goto failed;
    /* Command scratch is bounded separately from retained payload capacity. */
    owned = malloc(size);
    if (!owned) goto failed;
    memcpy(owned, wire, size);
    if (host_call_decode(owned, size, &c) || t->state != HOST_CALL_RECEIVING ||
        c.operation != t->operation ||
        c.id == 0 || c.id != t->id || c.offset != t->size ||
        c.status != HOST_CALL_OK || t->chunks >= HOST_CALL_MAX_CHUNKS ||
        (!c.final && c.length < HOST_CALL_MIN_CHUNK) ||
        t->size > HOST_CALL_OBJECT_CAP || c.length > HOST_CALL_OBJECT_CAP - t->size ||
        !t->budget || t->budget->capacity > HOST_CALL_BUDGET_CAP ||
        c.length > HOST_CALL_BUDGET_CAP - t->budget->capacity) goto failed;
    if (c.length) {
        t->budget->capacity += c.length;
        host_call_segment *s = malloc(sizeof(*s) + c.length);
        if (!s) { t->budget->capacity -= c.length; goto failed; }
        s->next = NULL; s->size = c.length;
        memcpy(s->bytes, owned + HOST_CALL_HEADER_SIZE, c.length);
        if (t->last) t->last->next = s; else t->first = s;
        t->last = s; t->size += c.length;
    }
    ++t->chunks;
    if (c.final) t->state = HOST_CALL_COMPLETE;
    free(owned);
    return 0;
failed:
    free(owned); host_call_release(t); t->state = HOST_CALL_FAILED;
    return -1;
}
const unsigned char *host_call_slice(const host_call *t, size_t offset, size_t *size)
{
    *size = 0;
    if (t->state != HOST_CALL_COMPLETE) return NULL;
    for (host_call_segment *s = t->first; s; s = s->next) {
        if (offset < s->size) { *size = s->size - offset; return s->bytes + offset; }
        offset -= s->size;
    }
    return NULL;
}
