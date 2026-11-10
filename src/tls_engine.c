#include "tls_engine.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "The trusted random provider requires OpenSSL 3.5 or newer"
#endif

#define ENGINE_INVALID (-1)
#define ENGINE_BOUNDS (-2)
#define ENGINE_HTTP (-3)
#define ENGINE_TLS (-4)

#ifndef TLS_ENGINE_TEST_BIO_CAPACITY
#define TLS_ENGINE_TEST_BIO_CAPACITY TLS_IO_CAPACITY
#endif
_Static_assert(TLS_ENGINE_TEST_BIO_CAPACITY > 0 &&
               TLS_ENGINE_TEST_BIO_CAPACITY <= TLS_IO_CAPACITY, "bounded BIO capacity");

/* SIZE_OK: identity and bounded TLS state machine share one public engine module. */
struct tls_identity {
    OSSL_LIB_CTX *library;
    OSSL_PROVIDER *provider;
    OSSL_PROVIDER *defaults;
    SSL_CTX *config;
    tls_random_fn random;
    void *random_context;
    unsigned char pem[2048];
    size_t pem_size;
};

struct tls_connection {
    SSL *ssl;
    BIO *network;
    unsigned char headers[4096];
    size_t header_size;
    size_t response_offset;
    int handshake;
    int write_pending;
    int state; /* 0: handshake/headers, 1: response, 2: close, 3: closed */
    int error;
};

static const unsigned char response[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n"
    "Connection: close\r\n\r\nHello from the TEE!\n";

/* Each built-in provider belongs to exactly one identity's library context.
 * Its holder is bound before any cryptographic operation can request bytes. */
static int trusted_random(void *context, int which, void *out, size_t size,
                          unsigned int strength)
{
    tls_identity *identity = *(tls_identity **)context;
    (void)which;
    if (identity == NULL || strength > 256) { return 0; }
    if (identity->random(identity->random_context, out, size) == 0) { return 1; }
    OPENSSL_cleanse(out, size);
    return 0;
}

static void random_teardown(void *context) { free(context); }

static int random_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **context)
{
    static const OSSL_DISPATCH dispatch[] = {
        { OSSL_FUNC_PROVIDER_RANDOM_BYTES, (void (*)(void))trusted_random },
        { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))random_teardown },
        { 0, NULL }
    };
    (void)handle;
    (void)in;
    *context = calloc(1, sizeof(tls_identity *));
    *out = dispatch;
    return *context != NULL;
}

void tls_identity_destroy(tls_identity *identity)
{
    if (identity == NULL) { return; }
    SSL_CTX_free(identity->config);
    OSSL_PROVIDER_unload(identity->provider);
    OSSL_PROVIDER_unload(identity->defaults);
    OSSL_LIB_CTX_free(identity->library);
    OPENSSL_cleanse(identity, sizeof(*identity));
    free(identity);
}

int tls_identity_create(tls_identity **out, tls_random_fn random, void *context)
{
    tls_identity *identity;
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    EVP_MD_CTX *signer = NULL;
    BIO *pem = NULL;
    BIGNUM *number = NULL;
    unsigned char serial[16];
    int ok = 0;
    if (out == NULL) { return ENGINE_INVALID; }
    *out = NULL;
    if (random == NULL) { return ENGINE_INVALID; }
    identity = calloc(1, sizeof(*identity));
    if (identity == NULL) { return ENGINE_TLS; }
    identity->random = random;
    identity->random_context = context;
    identity->library = OSSL_LIB_CTX_new();
    if (identity->library == NULL ||
        !OSSL_PROVIDER_add_builtin(identity->library, "trusted-random", random_provider_init)) { goto done; }
    identity->provider = OSSL_PROVIDER_load(identity->library, "trusted-random");
    if (identity->provider == NULL) { goto done; }
    *(tls_identity **)OSSL_PROVIDER_get0_provider_ctx(identity->provider) = identity;
    if (!RAND_set1_random_provider(identity->library, identity->provider)) { goto done; }
    identity->defaults = OSSL_PROVIDER_load(identity->library, "default");
    if (identity->defaults == NULL) { goto done; }
    key = EVP_PKEY_Q_keygen(identity->library, NULL, "EC", "prime256v1");
    certificate = X509_new_ex(identity->library, NULL);
    signer = EVP_MD_CTX_new();
    pem = BIO_new(BIO_s_mem());
    if (key == NULL || certificate == NULL || signer == NULL || pem == NULL ||
        !RAND_bytes_ex(identity->library, serial, sizeof(serial), 128)) { goto done; }
    serial[0] = (unsigned char)((serial[0] & 0x7fu) | 1u);
    number = BN_bin2bn(serial, sizeof(serial), NULL);
    if (number == NULL || !BN_to_ASN1_INTEGER(number, X509_get_serialNumber(certificate)) ||
        !X509_set_version(certificate, 2) || !X509_set_pubkey(certificate, key) ||
        !ASN1_TIME_set_string(X509_getm_notBefore(certificate), "20240101000000Z") ||
        !ASN1_TIME_set_string(X509_getm_notAfter(certificate), "20491231235959Z") ||
        !X509_NAME_add_entry_by_txt(X509_get_subject_name(certificate), "CN", MBSTRING_ASC,
                                   (const unsigned char *)"localhost", -1, -1, 0) ||
        !X509_set_issuer_name(certificate, X509_get_subject_name(certificate))) { goto done; }
    const int extensions[] = { NID_basic_constraints, NID_key_usage, NID_subject_alt_name };
    const char *values[] = { "critical,CA:FALSE", "critical,digitalSignature", "DNS:localhost" };
    for (size_t i = 0; i < 3; ++i) {
        X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, NULL, extensions[i], values[i]);
        if (extension == NULL) { goto done; }
        int added = X509_add_ext(certificate, extension, -1);
        X509_EXTENSION_free(extension);
        if (!added) { goto done; }
    }
    if (!EVP_DigestSignInit_ex(signer, NULL, "SHA256", identity->library, NULL, key, NULL) ||
        !X509_sign_ctx(certificate, signer) || !PEM_write_bio_X509(pem, certificate)) { goto done; }
    size_t length = BIO_ctrl_pending(pem);
    if (length >= sizeof(identity->pem) ||
        BIO_read(pem, identity->pem, (int)length) != (int)length) { goto done; }
    identity->pem_size = length + 1;
    identity->config = SSL_CTX_new_ex(identity->library, NULL, TLS_server_method());
    if (identity->config == NULL ||
        !SSL_CTX_set_min_proto_version(identity->config, TLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(identity->config, TLS1_2_VERSION) ||
        !SSL_CTX_set_cipher_list(identity->config, "ECDHE-ECDSA-AES128-GCM-SHA256") ||
        !SSL_CTX_set1_groups_list(identity->config, "P-256") ||
        !SSL_CTX_use_certificate(identity->config, certificate) ||
        !SSL_CTX_use_PrivateKey(identity->config, key)) { goto done; }
    SSL_CTX_set_options(identity->config, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_session_cache_mode(identity->config, SSL_SESS_CACHE_OFF);
    ok = 1;
done:
    OPENSSL_cleanse(serial, sizeof(serial));
    BN_free(number);
    BIO_free(pem);
    EVP_MD_CTX_free(signer);
    X509_free(certificate);
    EVP_PKEY_free(key);
    if (!ok) { tls_identity_destroy(identity); return ENGINE_TLS; }
    *out = identity;
    return 0;
}

int tls_identity_certificate(tls_identity *identity, unsigned char *out,
                             size_t capacity, size_t *written)
{
    if (written == NULL) { return ENGINE_INVALID; }
    *written = 0;
    if (identity == NULL || (out == NULL && capacity != 0)) { return ENGINE_INVALID; }
    *written = identity->pem_size;
    if (capacity < identity->pem_size) { return ENGINE_BOUNDS; }
    if (out == NULL) { return ENGINE_INVALID; }
    memcpy(out, identity->pem, identity->pem_size);
    return 0;
}

void tls_connection_destroy(tls_connection *connection)
{
    if (connection == NULL) { return; }
    SSL_free(connection->ssl);
    BIO_free(connection->network);
    OPENSSL_cleanse(connection, sizeof(*connection));
    free(connection);
}

int tls_connection_create(tls_connection **out, tls_identity *identity)
{
    tls_connection *connection;
    BIO *transport = NULL;
    if (out == NULL) { return ENGINE_INVALID; }
    *out = NULL;
    if (identity == NULL) { return ENGINE_INVALID; }
    connection = calloc(1, sizeof(*connection));
    if (connection == NULL) { return ENGINE_TLS; }
    connection->ssl = SSL_new(identity->config);
    if (connection->ssl == NULL ||
        !BIO_new_bio_pair(&transport, TLS_ENGINE_TEST_BIO_CAPACITY,
                          &connection->network, TLS_IO_CAPACITY)) {
        tls_connection_destroy(connection);
        return ENGINE_TLS;
    }
    SSL_set_bio(connection->ssl, transport, transport);
    SSL_set_accept_state(connection->ssl);
    *out = connection;
    return 0;
}

/* Token method/field names, visible target, HTTP/1.0 or 1.1, no obs-fold. */
static int token(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           (c != 0 && strchr("!#$%&'*+-.^_`|~", (int)c) != NULL);
}

static int valid_headers(const unsigned char *data, size_t size)
{
    size_t i = 0;
    size_t start;
    while (i < size && token(data[i])) { ++i; }
    if (i == 0 || i >= size || data[i++] != ' ') { return 0; }
    start = i;
    while (i < size && data[i] > 0x20 && data[i] < 0x7f) { ++i; }
    if (i == start || i >= size || data[i++] != ' ') { return 0; }
    if (size - i < 10 || memcmp(data + i, "HTTP/1.", 7) != 0 ||
        (data[i + 7] != '0' && data[i + 7] != '1') ||
        data[i + 8] != '\r' || data[i + 9] != '\n') { return 0; }
    i += 10;
    while (size - i > 2) {
        start = i;
        while (i < size && token(data[i])) { ++i; }
        if (i == start || i >= size || data[i++] != ':') { return 0; }
        while (i < size && data[i] != '\r') {
            if ((data[i] < 0x20 && data[i] != '\t') || data[i] == 0x7f) { return 0; }
            ++i;
        }
        if (size - i < 2 || data[i + 1] != '\n') { return 0; }
        i += 2;
    }
    return size - i == 2 && data[i] == '\r' && data[i + 1] == '\n';
}

static int ssl_result(tls_connection *connection, int result)
{
    int error = SSL_get_error(connection->ssl, result);
    connection->write_pending = error == SSL_ERROR_WANT_WRITE;
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ? 0 : ENGINE_TLS;
}

static int advance(tls_connection *connection)
{
    int ret;
    for (;;) {
        ERR_clear_error();
        if (!connection->handshake) {
            ret = SSL_do_handshake(connection->ssl);
            if (ret != 1) { return ssl_result(connection, ret); }
            connection->handshake = 1;
        }
        if (connection->state == 0) {
            unsigned char byte;
            ret = SSL_read(connection->ssl, &byte, 1);
            if (ret <= 0) {
                if (SSL_get_error(connection->ssl, ret) == SSL_ERROR_ZERO_RETURN) {
                    connection->state = 2;
                    continue;
                }
                return ssl_result(connection, ret);
            }
            connection->headers[connection->header_size++] = byte;
            if (connection->header_size >= 4 &&
                memcmp(connection->headers + connection->header_size - 4, "\r\n\r\n", 4) == 0) {
                if (!valid_headers(connection->headers, connection->header_size)) { return ENGINE_HTTP; }
                OPENSSL_cleanse(connection->headers, sizeof(connection->headers));
                connection->state = 1;
            } else if (connection->header_size == sizeof(connection->headers)) { return ENGINE_HTTP; }
        } else if (connection->state == 1) {
            ret = SSL_write(connection->ssl, response + connection->response_offset,
                            (int)(sizeof(response) - 1 - connection->response_offset));
            if (ret <= 0) { return ssl_result(connection, ret); }
            connection->response_offset += (size_t)ret;
            if (connection->response_offset == sizeof(response) - 1) { connection->state = 2; }
        } else if (connection->state == 2) {
            ret = SSL_shutdown(connection->ssl);
            /* One-way close: do not wait for the peer's close_notify. */
            if (ret < 0) { return ssl_result(connection, ret); }
            connection->state = 3;
            return 0;
        } else { return 0; }
    }
}

int tls_connection_process(tls_connection *connection,
                           const unsigned char *input, size_t input_size,
                           unsigned char *output, size_t capacity,
                           size_t *written, unsigned int *flags)
{
    if (written == NULL || flags == NULL) { return ENGINE_INVALID; }
    *written = 0;
    *flags = 0;
    if (connection == NULL || (input == NULL && input_size != 0) ||
        (output == NULL && capacity != 0)) { return ENGINE_INVALID; }
    if (input_size > BIO_ctrl_get_write_guarantee(connection->network)) { return ENGINE_BOUNDS; }
    if (connection->state == 3 && input_size != 0) { return ENGINE_INVALID; }
    /* Copy all input before writing output, including when buffers overlap. */
    if (input_size != 0 && BIO_write(connection->network, input, (int)input_size) != (int)input_size) {
        return ENGINE_TLS;
    }
    if (connection->state != 3) {
        connection->write_pending = 0;
        connection->error = advance(connection);
        if (connection->error != 0) {
            connection->state = 3;
            OPENSSL_cleanse(connection->headers, sizeof(connection->headers));
        }
    }
    size_t count = BIO_ctrl_pending(connection->network);
    if (count > capacity) { count = capacity; }
    if (count != 0) {
        int read = BIO_read(connection->network, output, (int)count);
        if (read > 0) { *written = (size_t)read; }
    }
    if (connection->handshake) { *flags |= TLS_FLAG_HANDSHAKE; }
    if (BIO_ctrl_pending(connection->network) != 0 ||
        (connection->state != 3 && connection->write_pending)) {
        *flags |= TLS_FLAG_MORE_OUTPUT;
    }
    if (connection->state == 3) { *flags |= TLS_FLAG_CLOSED; }
    return connection->error;
}
