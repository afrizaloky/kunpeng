#ifndef HOST_CALL_H
#define HOST_CALL_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define HOST_CALL_HEADER_SIZE 32u
#define HOST_CALL_COMMAND_CAP 65536u
#define HOST_CALL_PAYLOAD_CAP (HOST_CALL_COMMAND_CAP - HOST_CALL_HEADER_SIZE)
#define HOST_CALL_OBJECT_CAP 1048576u
#define HOST_CALL_BUDGET_CAP 2097152u
#define HOST_CALL_MIN_CHUNK 16384u
#define HOST_CALL_MAX_CHUNKS 65u
#define HOST_CALL_VERSION 1u

typedef enum { HOST_CALL_OK = 0, HOST_CALL_HOST_ERROR = 1 } host_call_status;
typedef enum { HOST_CALL_IDLE, HOST_CALL_RECEIVING, HOST_CALL_COMPLETE,
    HOST_CALL_FAILED } host_call_state;
typedef struct {
    uint32_t operation, id, offset, length;
    host_call_status status;
    unsigned final;
} host_call_chunk;
typedef struct host_call_segment host_call_segment;
typedef struct { size_t capacity; } host_call_budget;
typedef struct {
    host_call_budget *budget;
    host_call_segment *first, *last;
    uint32_t operation, id;
    size_t size;
    unsigned chunks;
    host_call_state state;
} host_call;
/* All wire integers are big endian u32, in order: version, operation, id,
 * offset, status, final (0/1), payload length, actual final length (0 otherwise).
 * Encoder writes the header only; caller appends exactly chunk.length bytes. */
int host_call_encode(unsigned char *header, const host_call_chunk *chunk);
int host_call_decode(const unsigned char *wire, size_t size, host_call_chunk *chunk);
/* Zero initialize transfer and budget before first use. Budget counts retained
 * payload only, excluding segment headers and one bounded command scratch copy.
 * Caller serializes contexts sharing a budget. IDs must be fresh per session;
 * replay within a begun transfer is rejected; session ID allocation is adapter-owned. */
int host_call_begin(host_call *transfer, host_call_budget *budget,
    uint32_t operation, uint32_t id);
/* Copies the entire bounded command before decoding. Any failure discards all
 * segments. The budget is externally serialized and outlives every transfer. */
int host_call_receive(host_call *transfer, const unsigned char *wire, size_t size);
void host_call_release(host_call *transfer);
/* Complete objects only. Returned slices remain stable until release. */
const unsigned char *host_call_slice(const host_call *transfer, size_t offset, size_t *size);
#ifdef __cplusplus
}
#endif
#endif
