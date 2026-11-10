#ifndef TLS_ENGINE_H
#define TLS_ENGINE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_IO_CAPACITY 65536
#define TLS_FLAG_HANDSHAKE 1u
#define TLS_FLAG_MORE_OUTPUT 2u
#define TLS_FLAG_CLOSED 4u

typedef struct tls_identity tls_identity;
typedef struct tls_connection tls_connection;
/* Fill every requested byte with secure randomness; return 0, negative on error.
 * The callback and context must remain valid until identity destruction. */
typedef int (*tls_random_fn)(void *, unsigned char *, size_t);

/* Creates a fresh P-256 identity inside the caller's trusted address space.
 * Ephemeral per-TA-instance identity is intentional: no private-key export or
 * persistence. Self-signed localhost certificate: demo validity 2024--2049.
 * Caller owns each returned object; output object is NULL on failure.
 * Calls sharing an identity (including RNG) must be externally serialized.
 * Destroy all its connections before destroying an identity. */
int tls_identity_create(tls_identity **identity, tls_random_fn random, void *context);
void tls_identity_destroy(tls_identity *identity);
/* Public PEM only. written includes its terminating NUL. On insufficient
 * capacity, returns negative and reports the required capacity in written. */
int tls_identity_certificate(tls_identity *identity, unsigned char *out,
                             size_t capacity, size_t *written);
int tls_connection_create(tls_connection **connection, tls_identity *identity);
void tls_connection_destroy(tls_connection *connection);
/* Ciphertext only. Input is copied into an owned queue before TLS processing;
 * input larger than remaining queue capacity is rejected atomically. Buffers
 * need remain valid only for this call (input/output may overlap). NULL buffers
 * are permitted only with zero corresponding size/capacity. written and flags
 * are required. Each queue is bounded by TLS_IO_CAPACITY. No request plaintext
 * is exported; at most 4096 header bytes ending CRLFCRLF trigger a fixed reply.
 *
 * HANDSHAKE means handshake has completed (sticky). MORE_OUTPUT means queued
 * ciphertext remains: call again with zero input to drain, also after errors.
 * CLOSED means no further TLS processing will occur; queued output may remain.
 * 0 means success/needs more I/O; negative means invalid input, bounds, or TLS
 * failure. Even on TLS failure, written/flags and output are valid and alerts
 * must be forwarded. Do not resubmit accepted input after a TLS failure.
 * Bounds/argument failures do not consume input or advance TLS. A fatal TLS
 * error is sticky; destruction is the only reset. No concurrent object calls. */
int tls_connection_process(tls_connection *connection,
                           const unsigned char *input, size_t input_size,
                           unsigned char *output, size_t capacity,
                           size_t *written, unsigned int *flags);

#ifdef __cplusplus
}
#endif
#endif
