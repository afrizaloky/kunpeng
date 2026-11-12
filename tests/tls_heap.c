#include "../include/tls_engine.h"
#include "../include/tls_protocol.h"
#include "heap_tracker.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); ERR_print_errors_fp(stderr); exit(1); } } while (0)

struct pair {
    tls_connection *server;
    SSL *client;
    unsigned int flags;
    int established, closed;
    size_t used;
    char response[256];
};
struct policy { const char *offered, *negotiated; int version; };
static int random_bytes(void *context, unsigned char *out, size_t size)
{
    (void)context;
    while (size) {
        ssize_t n = getrandom(out, size, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        out += n;
        size -= (size_t)n;
    }
    return 0;
}
static void retry(SSL *client, int result)
{
    int error = SSL_get_error(client, result);
    CHECK(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
}
static void exchange(struct pair *pair, size_t capacity)
{
    unsigned char bytes[TLS_IO_CAPACITY];
    size_t written = 0;
    int count = BIO_read(SSL_get_wbio(pair->client), bytes, sizeof(bytes));
    if (count < 0) CHECK(BIO_should_retry(SSL_get_wbio(pair->client)));
    CHECK(tls_connection_process(pair->server, bytes, count > 0 ? (size_t)count : 0,
                                bytes, capacity, &written, &pair->flags) == 0);
    CHECK(written <= capacity);
    if (written) CHECK(BIO_write(SSL_get_rbio(pair->client), bytes, (int)written) == (int)written);
}
static void cohort(tls_identity *identity, SSL_CTX *context, const struct policy *policy)
{
    struct pair pairs[TLS_MAX_SESSIONS] = {0};
    for (size_t i = 0; i < TLS_MAX_SESSIONS; ++i) {
        struct pair *p = &pairs[i];
        p->client = SSL_new(context);
        BIO *in = BIO_new(BIO_s_mem()), *out = BIO_new(BIO_s_mem());
        CHECK(p->client && in && out);
        SSL_set_bio(p->client, in, out);
        SSL_set_connect_state(p->client);
        CHECK(SSL_set1_host(p->client, "localhost"));
        CHECK(SSL_set_tlsext_host_name(p->client, "localhost"));
        CHECK(tls_connection_create(&p->server, identity) == 0);
    }
    size_t ready = 0;
    for (unsigned round = 0; round < 20000 && ready < TLS_MAX_SESSIONS; ++round) {
        for (size_t i = 0; i < TLS_MAX_SESSIONS; ++i) {
            struct pair *p = &pairs[i];
            if (!p->established) {
                int result = SSL_do_handshake(p->client);
                if (result != 1) retry(p->client, result);
                exchange(p, TLS_IO_CAPACITY - 1);
                if (SSL_is_init_finished(p->client) && (p->flags & TLS_FLAG_HANDSHAKE)) {
                    p->established = 1;
                    ++ready;
                }
            }
        }
    }
    CHECK(ready == TLS_MAX_SESSIONS);
    /* All eight states remain live before any application request is sent. */
    char headers[4096];
    memset(headers, 'a', sizeof(headers));
    memcpy(headers, "GET / HTTP/1.1\r\nX: ", 19);
    memcpy(headers + sizeof(headers) - 4, "\r\n\r\n", 4);
    for (unsigned request = 0; request < 3; ++request) {
    if (request == 2) {
        memcpy(headers, "GET / HTTP/1.1\r\nConnection: close\r\nX: ", 38);
    }
    for (size_t i = 0; i < TLS_MAX_SESSIONS; ++i) {
        pairs[i].used = 0;
        pairs[i].closed = 0;
        SSL *client = pairs[i].client;
        CHECK(SSL_version(client) == policy->version);
        const char *group = SSL_group_to_name(client, SSL_get_negotiated_group(client));
        CHECK(group && strcmp(group, policy->negotiated) == 0);
        CHECK(SSL_get_verify_result(client) == X509_V_OK);
        X509 *peer = SSL_get1_peer_certificate(client);
        CHECK(peer && X509_check_host(peer, "localhost", 0, 0, NULL) == 1);
        X509_free(peer);
        CHECK(SSL_write(client, headers, sizeof(headers)) == sizeof(headers));
    }
    size_t closed = 0;
    for (unsigned round = 0; round < 20000 && closed < TLS_MAX_SESSIONS; ++round) {
        for (size_t i = 0; i < TLS_MAX_SESSIONS; ++i) {
            struct pair *p = &pairs[i];
            if (p->closed) continue;
            /* Alternate near-limit command output with tiny bounded drains. */
            exchange(p, round % 2 ? 7 : TLS_IO_CAPACITY - 1);
            int result = SSL_read(p->client, p->response + p->used,
                                  (int)(sizeof(p->response) - p->used));
            if (result > 0) {
                p->used += (size_t)result;
                CHECK(p->used < sizeof(p->response));
                if (request != 2 && p->used == sizeof("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nHello from the TEE!\n") - 1) {
                    CHECK(!(p->flags & TLS_FLAG_CLOSED));
                    p->closed = 1;
                    ++closed;
                }
            } else if (SSL_get_error(p->client, result) == SSL_ERROR_ZERO_RETURN) {
                CHECK(p->flags & TLS_FLAG_CLOSED);
                p->closed = 1;
                ++closed;
            } else retry(p->client, result);
        }
    }
    CHECK(closed == TLS_MAX_SESSIONS);
    const char *expected = request == 2
        ? "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nHello from the TEE!\n"
        : "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nHello from the TEE!\n";
    for (size_t i = 0; i < TLS_MAX_SESSIONS; ++i) {
        CHECK(pairs[i].used == strlen(expected));
        CHECK(memcmp(pairs[i].response, expected, strlen(expected)) == 0);
    }
    }
    for (size_t i = 0; i < TLS_MAX_SESSIONS; ++i) {
        tls_connection_destroy(pairs[i].server);
        SSL_free(pairs[i].client);
    }
}
int main(int argc, char **argv)
{
    /* Must precede every other OpenSSL call, including error/version APIs. */
    CHECK(CRYPTO_set_mem_functions(heap_crypto_malloc, heap_crypto_realloc, heap_crypto_free));
    CHECK(argc == 2);
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(argv[1], &end, 10);
    CHECK(!errno && argv[1][0] >= '1' && argv[1][0] <= '9' && *end == '\0');
    CHECK(parsed <= SIZE_MAX);
    size_t budget = (size_t)parsed;
    tls_identity *identity = NULL;
    CHECK(tls_identity_create(&identity, random_bytes, NULL) == 0);
    unsigned char pem[2048];
    size_t size = 0;
    CHECK(tls_identity_certificate(identity, pem, sizeof(pem), &size) == 0);
    BIO *source = BIO_new_mem_buf(pem, (int)size);
    CHECK(source);
    X509 *certificate = PEM_read_bio_X509(source, NULL, NULL, NULL);
    CHECK(certificate);
    BIO_free(source);
    static const struct policy policies[] = {
        {"P-256", "secp256r1", TLS1_2_VERSION},
        {"X25519MLKEM768", "X25519MLKEM768", TLS1_3_VERSION},
        {"SecP256r1MLKEM768", "SecP256r1MLKEM768", TLS1_3_VERSION},
        {"SecP384r1MLKEM1024", "SecP384r1MLKEM1024", TLS1_3_VERSION},
        {"ffdhe4096", "ffdhe4096", TLS1_3_VERSION},
        {"ffdhe6144", "ffdhe6144", TLS1_3_VERSION},
        {"ffdhe8192", "ffdhe8192", TLS1_3_VERSION}
    };
    for (size_t i = 0; i < sizeof(policies) / sizeof(policies[0]); ++i) {
        SSL_CTX *context = SSL_CTX_new(TLS_client_method());
        CHECK(context);
        CHECK(SSL_CTX_set_min_proto_version(context, policies[i].version));
        CHECK(SSL_CTX_set_max_proto_version(context, policies[i].version));
        CHECK(SSL_CTX_set1_groups_list(context, policies[i].offered));
        SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
        CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(context), certificate));
        for (unsigned repeat = 0; repeat < 2; ++repeat) cohort(identity, context, &policies[i]);
        SSL_CTX_free(context);
        printf("cohorts=2 sessions=%u group=%s version=0x%x peak=%zu\n",
               TLS_MAX_SESSIONS, policies[i].negotiated, policies[i].version, heap_totals.peak);
    }
    X509_free(certificate);
    tls_identity_destroy(identity);
    CHECK(heap_totals.engine_allocations == 2 + TLS_MAX_SESSIONS * 2 * 7);
    OPENSSL_cleanup();
    printf("native-only %s peak=%zu live_after_cleanup=%zu allocations=%zu engine_allocations=%zu budget=%zu headroom_limit=%zu\n",
           OPENSSL_VERSION_TEXT, heap_totals.peak, heap_totals.live, heap_totals.allocations,
           heap_totals.engine_allocations, budget, budget / 2);
    puts("scope: OpenSSL callbacks (global startup + clients + server) and direct engine calloc/free; aligned tracker headers included; no baseline subtraction; excludes libc fragmentation, CA/runtime and stack. Provisional regression headroom, not TA target proof.");
    if (heap_totals.peak > budget / 2) {
        fprintf(stderr, "heap budget exceeded: peak=%zu limit=%zu\n", heap_totals.peak, budget / 2);
        return 2;
    }
    CHECK(heap_totals.live == 0);
    return 0;
}
