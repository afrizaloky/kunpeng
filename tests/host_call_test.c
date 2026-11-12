#include "host_call.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static int append(host_call *call, size_t length, unsigned final)
{
    unsigned char wire[HOST_CALL_COMMAND_CAP];
    host_call_chunk c = {call->operation, call->id, (uint32_t)call->size,
        (uint32_t)length, HOST_CALL_OK, final};
    assert(host_call_encode(wire, &c) == 0);
    for (size_t i = 0; i < length; ++i) wire[HOST_CALL_HEADER_SIZE + i] = (unsigned char)((call->size + i) % 251);
    return host_call_receive(call, wire, HOST_CALL_HEADER_SIZE + length);
}
static void fill(host_call *call, size_t length)
{
    while (length > HOST_CALL_PAYLOAD_CAP) {
        assert(append(call, HOST_CALL_PAYLOAD_CAP, 0) == 0);
        length -= HOST_CALL_PAYLOAD_CAP;
    }
    assert(append(call, length, 1) == 0);
}
static void roundtrips(void)
{
    const size_t sizes[] = {0, 1, 129, 65504, 65536, HOST_CALL_OBJECT_CAP};
    const uint32_t ops[] = {37, 0xfedcba98u};
    for (size_t op = 0; op < 2; ++op) for (size_t n = 0; n < sizeof(sizes)/sizeof(*sizes); ++n) {
        host_call_budget budget = {0}; host_call call = {0};
        assert(host_call_begin(&call, &budget, ops[op], 99) == 0);
        fill(&call, sizes[n]);
        assert(call.state == HOST_CALL_COMPLETE && call.size == sizes[n]);
        size_t offset = 0;
        while (offset < call.size) {
            size_t available;
            const unsigned char *bytes = host_call_slice(&call, offset, &available);
            assert(bytes && available);
            for (size_t i = 0; i < available; ++i) assert(bytes[i] == (offset + i) % 251);
            offset += available;
        }
        assert(budget.capacity == sizes[n]);
        assert(append(&call, 0, 1) != 0); /* replay discards completed payload */
        assert(budget.capacity == 0 && call.state == HOST_CALL_FAILED);
        host_call_release(&call);
    }
}
static void malformed(void)
{
    for (unsigned field = 0; field < 8; ++field) {
        host_call_budget budget = {0}; host_call call = {0};
        unsigned char wire[HOST_CALL_HEADER_SIZE] = {0};
        host_call_chunk c = {7, 9, HOST_CALL_MIN_CHUNK, 0, HOST_CALL_OK, 1};
        assert(host_call_begin(&call, &budget, 7, 9) == 0);
        assert(append(&call, HOST_CALL_MIN_CHUNK, 0) == 0);
        size_t available = 123;
        assert(host_call_slice(&call, 0, &available) == NULL && available == 0);
        assert(host_call_encode(wire, &c) == 0);
        wire[field * 4 + 3] ^= 2;
        assert(host_call_receive(&call, wire, sizeof(wire)) != 0);
        assert(call.state == HOST_CALL_FAILED && budget.capacity == 0);
        host_call_release(&call);
    }
    host_call_budget budget = {0}; host_call call = {0};
    assert(host_call_begin(&call, &budget, 0, 1) != 0);
    assert(host_call_begin(&call, &budget, 1, 0) != 0);
    assert(host_call_begin(&call, &budget, 7, 9) == 0);
    assert(append(&call, 1, 0) != 0);
    assert(host_call_begin(&call, &budget, 7, 10) == 0);
    for (unsigned i = 0; i < 64; ++i) assert(append(&call, HOST_CALL_MIN_CHUNK, 0) == 0);
    assert(append(&call, 0, 1) == 0); /* 65th empty final at exactly 1 MiB */
    assert(call.chunks == 65 && call.size == HOST_CALL_OBJECT_CAP);
    host_call_release(&call);
    assert(host_call_begin(&call, &budget, 7, 11) == 0);
    for (unsigned i = 0; i < 64; ++i) assert(append(&call, HOST_CALL_MIN_CHUNK, 0) == 0);
    unsigned char wire[HOST_CALL_HEADER_SIZE + 1] = {0};
    host_call_chunk c = {7, 11, HOST_CALL_OBJECT_CAP, 1, HOST_CALL_OK, 1};
    assert(host_call_encode(wire, &c) != 0);
    assert(host_call_receive(&call, wire, sizeof(wire)) != 0);
    assert(budget.capacity == 0);
}
static void shared_budget(void)
{
    host_call_budget budget = {0}; host_call calls[3] = {{0}};
    for (unsigned i = 0; i < 3; ++i) assert(host_call_begin(&calls[i], &budget, 47, i + 1) == 0);
    fill(&calls[0], HOST_CALL_OBJECT_CAP); fill(&calls[1], HOST_CALL_OBJECT_CAP);
    assert(budget.capacity == HOST_CALL_BUDGET_CAP);
    assert(append(&calls[2], 1, 1) != 0 && budget.capacity == HOST_CALL_BUDGET_CAP);
    host_call_release(&calls[0]);
    assert(host_call_begin(&calls[2], &budget, 92, 4) == 0);
    fill(&calls[2], HOST_CALL_OBJECT_CAP);
    host_call_release(&calls[1]); host_call_release(&calls[2]);
    assert(budget.capacity == 0);
}
int main(void) { roundtrips(); malformed(); shared_budget(); return 0; }
