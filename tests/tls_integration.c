#include "../include/tls_engine.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); ERR_print_errors_fp(stderr); exit(1); } } while (0)

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

#ifdef TLS_ENGINE_TEST_BIO_CAPACITY
static size_t saturated_drains;
#endif

static int exchange(tls_connection *server, SSL *client, unsigned int *flags)
{
#ifdef TLS_ENGINE_TEST_BIO_CAPACITY
    unsigned char input[TLS_ENGINE_TEST_BIO_CAPACITY];
    size_t capacity = sizeof(input);
#else
    unsigned char input[13];
    size_t capacity = 7;
#endif
    size_t written = 0;
    int count = BIO_read(SSL_get_wbio(client), input, sizeof(input));
    if (count < 0) CHECK(BIO_should_retry(SSL_get_wbio(client)));
    int result = tls_connection_process(server, input, count > 0 ? (size_t)count : 0,
                                        input, capacity, &written, flags);
#ifdef TLS_ENGINE_TEST_BIO_CAPACITY
    while (result == 0 && written == capacity) {
        CHECK(*flags & TLS_FLAG_MORE_OUTPUT);
        ++saturated_drains;
        CHECK(BIO_write(SSL_get_rbio(client), input, (int)written) == (int)written);
        result = tls_connection_process(server, NULL, 0, input, capacity, &written, flags);
    }
#endif
    if (written) CHECK(BIO_write(SSL_get_rbio(client), input, (int)written) == (int)written);
    return result;
}

struct request_case {
    const char *bytes;
    size_t size;
    int accepted;
};

/* SIZE_OK: shared wire-level fixture keeps protocol cases on the same assertions. */
struct session_policy {
    SSL_CTX *context;
    int version;
    const char *cipher;
    const char *group;
};

static void session(tls_identity *identity, const struct session_policy *policy, const struct request_case *request)
{
    static const char expected[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nHello from the TEE!\n";
    tls_connection *server = NULL;
    SSL *client = SSL_new(policy->context);
    BIO *incoming = BIO_new(BIO_s_mem()), *outgoing = BIO_new(BIO_s_mem());
    CHECK(client && incoming && outgoing);
    SSL_set_bio(client, incoming, outgoing);
    SSL_set_connect_state(client);
    CHECK(SSL_set1_host(client, "localhost") == 1);
    CHECK(SSL_set_tlsext_host_name(client, "localhost") == 1);
    CHECK(tls_connection_create(&server, identity) == 0);
    unsigned int flags = 0;
    size_t written = 99;
    CHECK(tls_connection_process(server, NULL, 0, NULL, 0, &written, &flags) == 0);
    CHECK(written == 0 && flags == 0);
    unsigned char oversized[TLS_IO_CAPACITY + 1] = {0};
    CHECK(tls_connection_process(server, oversized, sizeof(oversized), NULL, 0, &written, &flags) < 0);
    int complete = 0;
    for (unsigned int i = 0; i < 20000; ++i) {
        int result = SSL_do_handshake(client);
        if (result == 1) { complete = 1; break; }
        int error = SSL_get_error(client, result);
        CHECK(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
        long before = BIO_ctrl_pending(outgoing) + BIO_ctrl_pending(incoming);
        CHECK(exchange(server, client, &flags) == 0);
        CHECK(before > 0 || BIO_ctrl_pending(incoming) > 0 || (flags & TLS_FLAG_MORE_OUTPUT));
    }
    CHECK(complete);
    CHECK(SSL_version(client) == policy->version);
    CHECK(strcmp(SSL_get_cipher_name(client), policy->cipher) == 0);
    const char *group = SSL_group_to_name(client, SSL_get_negotiated_group(client));
    if (group == NULL || strcmp(group, policy->group) != 0)
        fprintf(stderr, "negotiated group %s, expected %s\n", group ? group : "(none)", policy->group);
    CHECK(group != NULL && strcmp(group, policy->group) == 0);
    CHECK(SSL_get_verify_result(client) == X509_V_OK);
    X509 *peer = SSL_get1_peer_certificate(client);
    CHECK(peer != NULL);
    CHECK(X509_check_host(peer, "localhost", 0, 0, NULL) == 1);
    X509_free(peer);
    for (size_t offset = 0; offset < request->size;) {
        int result = SSL_write(client, request->bytes + offset, 1);
        CHECK(result == 1);
        offset++;
    }
    char response[1024];
    size_t used = 0;
    int closed = 0;
    for (unsigned int i = 0; i < 20000; ++i) {
        long before = BIO_ctrl_pending(outgoing) + BIO_ctrl_pending(incoming);
        int server_result = exchange(server, client, &flags);
        if (server_result < 0) {
            CHECK(!request->accepted);
            CHECK(flags & TLS_FLAG_CLOSED);
            CHECK(used == 0);
            closed = 1;
            break;
        }
        int result = SSL_read(client, response + used, (int)(sizeof(response) - used));
        if (result > 0) { used += (size_t)result; CHECK(used < sizeof(response)); continue; }
        int error = SSL_get_error(client, result);
        if (error == SSL_ERROR_ZERO_RETURN) { closed = 1; break; }
        CHECK(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
        CHECK(before > 0 || BIO_ctrl_pending(incoming) > 0 || (flags & TLS_FLAG_MORE_OUTPUT));
    }
    CHECK(closed);
    if (request->accepted) {
        CHECK(used == sizeof(expected) - 1);
        CHECK(memcmp(response, expected, used) == 0);
    } else {
        CHECK(used == 0);
        CHECK(flags & TLS_FLAG_CLOSED);
    }
    CHECK(flags & TLS_FLAG_HANDSHAKE);
    tls_connection_destroy(server);
    SSL_free(client);
}

static int failing_random(void *context, unsigned char *out, size_t size)
{
    (void)context;
    (void)out;
    (void)size;
    return -1;
}

struct random_control { int fail; size_t calls; };

static int controlled_random(void *context, unsigned char *out, size_t size)
{
    struct random_control *control = context;
    ++control->calls;
    return control->fail ? -1 : random_bytes(NULL, out, size);
}

static void random_isolation(void)
{
    struct random_control first = {0}, second = {0};
    tls_identity *a = NULL, *b = NULL;
    tls_connection *server = NULL;
    unsigned char bytes[4096];
    size_t written;
    unsigned int flags;
    CHECK(tls_identity_create(&a, controlled_random, &first) == 0);
    CHECK(tls_identity_create(&b, controlled_random, &second) == 0);
    first.fail = 1;
    size_t first_calls = first.calls, second_calls = second.calls;
    CHECK(RAND_bytes(bytes, 32) == 1);
    CHECK(first.calls == first_calls && second.calls == second_calls);
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    SSL *client = SSL_new(context);
    CHECK(context && client);
    SSL_set_bio(client, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
    SSL_set_connect_state(client);
    CHECK(SSL_do_handshake(client) < 0);
    int count = BIO_read(SSL_get_wbio(client), bytes, sizeof(bytes));
    CHECK(count > 0);
    unsigned char hello[4096];
    memcpy(hello, bytes, (size_t)count);
    CHECK(tls_connection_create(&server, a) == 0);
    int error = tls_connection_process(server, bytes, (size_t)count, NULL, 0, &written, &flags);
    CHECK(error < 0 && (flags & TLS_FLAG_CLOSED));
    CHECK(first.calls > first_calls && second.calls == second_calls);
    CHECK(tls_connection_process(server, NULL, 0, bytes, sizeof(bytes), &written, &flags) == error);
    tls_connection_destroy(server);
    CHECK(tls_connection_create(&server, b) == 0);
    CHECK(tls_connection_process(server, hello, (size_t)count, NULL, 0, &written, &flags) == 0);
    CHECK(second.calls > second_calls && (flags & TLS_FLAG_MORE_OUTPUT));
    CHECK(RAND_bytes(bytes, 32) == 1);
    tls_connection_destroy(server);
    SSL_free(client);
    SSL_CTX_free(context);
    tls_identity_destroy(a);
    tls_identity_destroy(b);
}

int main(void)
{
    random_isolation();
    tls_identity *identity = NULL;
    CHECK(tls_identity_create(&identity, failing_random, NULL) < 0);
    CHECK(identity == NULL);
    CHECK(tls_identity_create(&identity, random_bytes, NULL) == 0);
    unsigned char pem[4096];
    size_t size = 0;
    CHECK(tls_identity_certificate(identity, pem, 0, &size) < 0);
    CHECK(size > 1 && size <= 2048);
    size_t required = size;
    CHECK(tls_identity_certificate(identity, pem, required - 1, &size) < 0);
    CHECK(size == required);
    CHECK(tls_identity_certificate(identity, pem, sizeof(pem), &size) == 0);
    CHECK(pem[size - 1] == 0);
    BIO *source = BIO_new_mem_buf(pem, (int)size);
    CHECK(source);
    X509 *certificate = PEM_read_bio_X509(source, NULL, NULL, NULL);
    CHECK(certificate);
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    CHECK(context);
    CHECK(SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION));
    CHECK(SSL_CTX_set_max_proto_version(context, TLS1_2_VERSION));
    CHECK(SSL_CTX_set1_groups_list(context, "P-256"));
    const struct session_policy baseline = {
        context, TLS1_2_VERSION, "ECDHE-ECDSA-AES128-GCM-SHA256", "secp256r1"
    };
    SSL_CTX *hybrid = SSL_CTX_new(TLS_client_method());
    CHECK(hybrid);
    CHECK(SSL_CTX_set_min_proto_version(hybrid, TLS1_3_VERSION));
    CHECK(SSL_CTX_set_max_proto_version(hybrid, TLS1_3_VERSION));
    SSL_CTX_set_verify(hybrid, SSL_VERIFY_PEER, NULL);
    CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(hybrid), certificate) == 1);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(context), certificate) == 1);
    X509_free(certificate);
    BIO_free(source);
    static const char valid[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    static const char nul_method[] = "GE\0T / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    static const char nul_header[] = "GET / HTTP/1.1\r\nHo\0st: localhost\r\n\r\n";
    char maximum[4096];
    memset(maximum, 'a', sizeof(maximum));
    memcpy(maximum, "GET / HTTP/1.1\r\nX: ", 19);
    memcpy(maximum + sizeof(maximum) - 4, "\r\n\r\n", 4);
    char excessive[4097];
    memset(excessive, 'a', sizeof(excessive));
    memcpy(excessive, "GET / HTTP/1.1\r\nX: ", 19);
    memcpy(excessive + sizeof(excessive) - 4, "\r\n\r\n", 4);
    const struct request_case requests[] = {
        {valid, sizeof(valid) - 1, 1},
        {nul_method, sizeof(nul_method) - 1, 0},
        {nul_header, sizeof(nul_header) - 1, 0},
        {maximum, sizeof(maximum), 1},
        {excessive, sizeof(excessive), 0},
        {"GET / HTTP/1.1\r\n Fold: bad\r\n\r\n", sizeof("GET / HTTP/1.1\r\n Fold: bad\r\n\r\n") - 1, 0},
    };
    for (unsigned int i = 0; i < 3; ++i) session(identity, &baseline, &requests[0]);
    for (size_t i = 1; i < sizeof(requests) / sizeof(requests[0]); ++i)
        session(identity, &baseline, &requests[i]);
    const char *groups[] = {
        "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
        "x25519", "x448", "secp256r1", "secp384r1", "secp521r1", "ffdhe3072"
    };
    const char *suites[] = {
        "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        CHECK(SSL_CTX_set1_groups_list(hybrid, groups[i]));
        CHECK(SSL_CTX_set_ciphersuites(hybrid, suites[0]));
        const struct session_policy policy = {hybrid, TLS1_3_VERSION, suites[0], groups[i]};
        session(identity, &policy, &requests[0]);
    }
    CHECK(SSL_CTX_set1_groups_list(hybrid, "X25519MLKEM768"));
    for (size_t i = 1; i < sizeof(suites) / sizeof(suites[0]); ++i) {
        CHECK(SSL_CTX_set_ciphersuites(hybrid, suites[i]));
        const struct session_policy policy = {hybrid, TLS1_3_VERSION, suites[i], "X25519MLKEM768"};
        session(identity, &policy, &requests[0]);
    }
    CHECK(SSL_CTX_set_ciphersuites(hybrid, suites[0]));
    CHECK(SSL_CTX_set1_groups_list(hybrid, "*X25519:X25519MLKEM768"));
    const struct session_policy preferred = {hybrid, TLS1_3_VERSION, suites[0], "X25519MLKEM768"};
    session(identity, &preferred, &requests[0]);
    const char *excluded[] = {"ffdhe2048"};
    for (size_t i = 0; i < sizeof(excluded) / sizeof(excluded[0]); ++i) {
        CHECK(SSL_CTX_set1_groups_list(hybrid, excluded[i]));
        SSL *client = SSL_new(hybrid);
        CHECK(client);
        SSL_set_bio(client, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
        SSL_set_connect_state(client);
        tls_connection *server = NULL;
        CHECK(tls_connection_create(&server, identity) == 0);
        unsigned int rejected_flags = 0;
        int rejected = 0;
        for (unsigned int step = 0; step < 20000; ++step) {
            int result = SSL_do_handshake(client);
            CHECK(result != 1);
            int error = SSL_get_error(client, result);
            CHECK(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
            if (exchange(server, client, &rejected_flags) < 0) { rejected = 1; break; }
        }
        CHECK(rejected && (rejected_flags & TLS_FLAG_CLOSED));
        CHECK(!(rejected_flags & TLS_FLAG_HANDSHAKE));
        tls_connection_destroy(server);
        SSL_free(client);
    }
    SSL_CTX_free(hybrid);
    tls_connection *broken = NULL;
    CHECK(tls_connection_create(&broken, identity) == 0);
    /* A handshake record containing an illegal first handshake message. */
    const unsigned char malformed[] = {22, 3, 3, 0, 4, 2, 0, 0, 0};
    unsigned char output[64];
    unsigned int flags = 0;
    int failure = tls_connection_process(broken, malformed, sizeof(malformed), NULL, 0, &size, &flags);
    CHECK(failure < 0 && size == 0);
    CHECK((flags & (TLS_FLAG_CLOSED | TLS_FLAG_MORE_OUTPUT)) ==
          (TLS_FLAG_CLOSED | TLS_FLAG_MORE_OUTPUT));
    size_t alert_size = 0;
    do {
        CHECK(alert_size < sizeof(output));
        CHECK(tls_connection_process(broken, NULL, 0, output + alert_size, 1, &size, &flags) == failure);
        CHECK(size == 1 && (flags & TLS_FLAG_CLOSED));
        alert_size += size;
    } while (flags & TLS_FLAG_MORE_OUTPUT);
    CHECK(alert_size == 7 && output[0] == 21 && output[5] == 2);
    CHECK(tls_connection_process(broken, NULL, 0, output, sizeof(output), &size, &flags) == failure);
    CHECK(size == 0 && flags == TLS_FLAG_CLOSED);
    tls_connection_destroy(broken);
    CHECK(tls_connection_create(&broken, identity) == 0);
    tls_connection_destroy(broken);
    tls_identity_destroy(identity);
    SSL_CTX_free(context);
#ifdef TLS_ENGINE_TEST_BIO_CAPACITY
    CHECK(saturated_drains > 0);
#endif
    puts("native OpenSSL integration passed (not a TEE test)");
    return 0;
}
