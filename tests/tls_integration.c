#include "../include/tls_engine.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
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

static int exchange(tls_connection *server, SSL *client, unsigned int *flags)
{
    unsigned char input[13], output[7];
    size_t written = 0;
    int count = BIO_read(SSL_get_wbio(client), input, sizeof(input));
    if (count < 0) CHECK(BIO_should_retry(SSL_get_wbio(client)));
    int result = tls_connection_process(server, input, count > 0 ? (size_t)count : 0,
                                        output, sizeof(output), &written, flags);
    if (written) CHECK(BIO_write(SSL_get_rbio(client), output, (int)written) == (int)written);
    return result;
}

struct request_case {
    const char *bytes;
    size_t size;
    int accepted;
};

static void session(tls_identity *identity, SSL_CTX *context, const struct request_case *request)
{
    static const char expected[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nHello from the TEE!\n";
    tls_connection *server = NULL;
    SSL *client = SSL_new(context);
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
    CHECK(SSL_version(client) == TLS1_2_VERSION);
    CHECK(strcmp(SSL_get_cipher_name(client), "ECDHE-ECDSA-AES128-GCM-SHA256") == 0);
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

int main(void)
{
    tls_identity *identity = NULL;
    CHECK(tls_identity_create(&identity, failing_random, NULL) < 0);
    CHECK(identity == NULL);
    CHECK(tls_identity_create(&identity, random_bytes, NULL) == 0);
    unsigned char pem[4096];
    size_t size = 0;
    CHECK(tls_identity_certificate(identity, pem, 0, &size) < 0);
    CHECK(size > 0 && size <= sizeof(pem));
    CHECK(tls_identity_certificate(identity, pem, sizeof(pem), &size) == 0);
    BIO *source = BIO_new_mem_buf(pem, (int)size);
    CHECK(source);
    X509 *certificate = PEM_read_bio_X509(source, NULL, NULL, NULL);
    CHECK(certificate);
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    CHECK(context);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(context), certificate) == 1);
    X509_free(certificate);
    BIO_free(source);
    static const char valid[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    static const char nul_method[] = "GE\0T / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    static const char nul_header[] = "GET / HTTP/1.1\r\nHo\0st: localhost\r\n\r\n";
    const struct request_case requests[] = {
        {valid, sizeof(valid) - 1, 1},
        {nul_method, sizeof(nul_method) - 1, 0},
        {nul_header, sizeof(nul_header) - 1, 0},
    };
    for (unsigned int i = 0; i < 3; ++i) session(identity, context, &requests[0]);
    for (size_t i = 1; i < sizeof(requests) / sizeof(requests[0]); ++i)
        session(identity, context, &requests[i]);
    tls_connection *broken = NULL;
    CHECK(tls_connection_create(&broken, identity) == 0);
    const unsigned char malformed[] = {0xff, 3, 3, 0, 1, 0};
    unsigned char output[64];
    unsigned int flags = 0;
    CHECK(tls_connection_process(broken, malformed, sizeof(malformed), output, sizeof(output), &size, &flags) < 0);
    CHECK(flags & TLS_FLAG_CLOSED);
    tls_connection_destroy(broken);
    CHECK(tls_connection_create(&broken, identity) == 0);
    tls_connection_destroy(broken);
    tls_identity_destroy(identity);
    SSL_CTX_free(context);
    puts("native OpenSSL/mbedTLS integration passed (not a TEE test)");
    return 0;
}
