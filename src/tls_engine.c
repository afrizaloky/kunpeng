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

#ifdef KUNPENG_ITRUSTEE
#include <tee_log.h>

/* Only public stages and packed error codes: never error data or source metadata. */
static void tls_engine_log_error(const char *stage)
{
    unsigned long error = ERR_get_error();
    tloge("tls-engine failure stage=%s openssl=0x%lx\n", stage, error);
    while ((error = ERR_get_error()) != 0) {
        tloge("tls-engine failure stage=%s openssl=0x%lx\n", stage, error);
    }
}
#define TLS_ENGINE_LOG_ERROR(stage) tls_engine_log_error(stage)
#else
#define TLS_ENGINE_LOG_ERROR(stage) ((void)(stage))
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
    uint32_t next_request_id;
    host_call_budget host_budget;
};

struct tls_connection {
    SSL *ssl;
    BIO *network;
    tls_identity *identity;
    tls_host_data_request pending;
    host_call host_object;
    unsigned char host_response[160];
    size_t host_response_size;
    size_t body_offset;
    int host_body;
    unsigned char headers[4096];
    size_t header_size;
    size_t response_offset;
    int handshake;
    int write_pending;
    int close_after_response;
    int state; /* 0: handshake/headers, 1: response, 2: close, 3: closed */
    int error;
};

static const unsigned char persistent_response[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n"
    "\r\nHello from the TEE!\n";

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
    const char *stage = "identity-allocation";
    if (out == NULL) { return ENGINE_INVALID; }
    *out = NULL;
    if (random == NULL) { return ENGINE_INVALID; }
    identity = calloc(1, sizeof(*identity));
    if (identity == NULL) { TLS_ENGINE_LOG_ERROR(stage); return ENGINE_TLS; }
    identity->random = random;
    identity->random_context = context;
#ifdef KUNPENG_ITRUSTEE
    tlogi("tls-engine startup openssl=%s\n", OpenSSL_version(OPENSSL_VERSION));
#endif
    stage = "library-context";
    identity->library = OSSL_LIB_CTX_new();
    if (identity->library == NULL) { goto done; }
    stage = "random-provider-register";
    if (!OSSL_PROVIDER_add_builtin(identity->library, "trusted-random", random_provider_init)) { goto done; }
    stage = "random-provider-load";
    identity->provider = OSSL_PROVIDER_load(identity->library, "trusted-random");
    if (identity->provider == NULL) { goto done; }
    *(tls_identity **)OSSL_PROVIDER_get0_provider_ctx(identity->provider) = identity;
    stage = "random-provider-select";
    if (!RAND_set1_random_provider(identity->library, identity->provider)) { goto done; }
    stage = "default-provider-load";
    identity->defaults = OSSL_PROVIDER_load(identity->library, "default");
    if (identity->defaults == NULL) { goto done; }
    stage = "keygen";
    key = EVP_PKEY_Q_keygen(identity->library, NULL, "EC", "prime256v1");
    certificate = X509_new_ex(identity->library, NULL);
    signer = EVP_MD_CTX_new();
    pem = BIO_new(BIO_s_mem());
    if (key == NULL) { goto done; }
    stage = "certificate-allocation";
    if (certificate == NULL) { goto done; }
    stage = "signer-allocation";
    if (signer == NULL) { goto done; }
    stage = "pem-allocation";
    if (pem == NULL) { goto done; }
    stage = "serial-random";
    if (!RAND_bytes_ex(identity->library, serial, sizeof(serial), 128)) { goto done; }
    serial[0] = (unsigned char)((serial[0] & 0x7fu) | 1u);
    stage = "certificate-fields";
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
    stage = "certificate-extensions";
    for (size_t i = 0; i < 3; ++i) {
        X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, NULL, extensions[i], values[i]);
        if (extension == NULL) { goto done; }
        int added = X509_add_ext(certificate, extension, -1);
        X509_EXTENSION_free(extension);
        if (!added) { goto done; }
    }
    stage = "certificate-sign-pem";
    if (!EVP_DigestSignInit_ex(signer, NULL, "SHA256", identity->library, NULL, key, NULL) ||
        !X509_sign_ctx(certificate, signer) || !PEM_write_bio_X509(pem, certificate)) { goto done; }
    stage = "certificate-export";
    size_t length = BIO_ctrl_pending(pem);
    if (length >= sizeof(identity->pem) ||
        BIO_read(pem, identity->pem, (int)length) != (int)length) { goto done; }
    identity->pem_size = length + 1;
    stage = "ssl-context";
    identity->config = SSL_CTX_new_ex(identity->library, NULL, TLS_server_method());
    if (identity->config == NULL) { goto done; }
    stage = "tls-min-version";
    if (!SSL_CTX_set_min_proto_version(identity->config, TLS1_2_VERSION)) { goto done; }
    stage = "tls-max-version";
    if (!SSL_CTX_set_max_proto_version(identity->config, TLS1_3_VERSION)) { goto done; }
#ifdef KUNPENG_ITRUSTEE
    STACK_OF(OPENSSL_CSTRING) *groups = sk_OPENSSL_CSTRING_new_null();
    if (groups == NULL) {
        TLS_ENGINE_LOG_ERROR("implemented-groups-allocation");
    } else {
        if (!SSL_CTX_get0_implemented_groups(identity->config, 0, groups)) {
            TLS_ENGINE_LOG_ERROR("implemented-groups-enumeration");
        } else {
            const int count = sk_OPENSSL_CSTRING_num(groups);
            tlogi("tls-engine implemented-groups count=%d\n", count);
            for (int i = 0; i < count; ++i) {
                tlogi("tls-engine implemented-group name=%s\n",
                      sk_OPENSSL_CSTRING_value(groups, i));
            }
        }
        sk_OPENSSL_CSTRING_free(groups);
    }
#endif
    stage = "tls12-ciphers";
    if (!SSL_CTX_set_cipher_list(identity->config, "ECDHE-ECDSA-AES128-GCM-SHA256")) { goto done; }
    stage = "tls13-ciphers";
    if (!SSL_CTX_set_ciphersuites(identity->config,
            "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")) { goto done; }
    const char *AVAILABLE_GROUPS =
            "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024/"
            "X25519:X448:P-256:P-384:P-521:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192";
    stage = "tls-groups";
    if (!SSL_CTX_set1_groups_list(identity->config, AVAILABLE_GROUPS)) { goto done; }
    stage = "certificate-install";
    if (!SSL_CTX_use_certificate(identity->config, certificate)) { goto done; }
    stage = "key-install";
    if (!SSL_CTX_use_PrivateKey(identity->config, key)) { goto done; }
    SSL_CTX_set_options(identity->config,
        SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    stage = "ticket-count";
    if (!SSL_CTX_set_num_tickets(identity->config, 0)) { goto done; }
    SSL_CTX_set_session_cache_mode(identity->config, SSL_SESS_CACHE_OFF);
    ok = 1;
done:
    if (!ok) { TLS_ENGINE_LOG_ERROR(stage); }
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
    host_call_release(&connection->host_object);
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
    if (connection == NULL) {
        TLS_ENGINE_LOG_ERROR("connection-allocation");
        return ENGINE_TLS;
    }
    connection->identity = identity;
    connection->ssl = SSL_new(identity->config);
    if (connection->ssl == NULL) {
        TLS_ENGINE_LOG_ERROR("connection-ssl");
        tls_connection_destroy(connection);
        return ENGINE_TLS;
    }
    if (!BIO_new_bio_pair(&transport, TLS_ENGINE_TEST_BIO_CAPACITY,
                          &connection->network, TLS_IO_CAPACITY)) {
        TLS_ENGINE_LOG_ERROR("connection-bio-pair");
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

static int equal_header(const unsigned char *data, size_t size, const char *name)
{
    if (size != strlen(name)) { return 0; }
    for (size_t i = 0; i < size; ++i) {
        unsigned char c = data[i];
        if (c >= 'A' && c <= 'Z') { c += 'a' - 'A'; }
        if (c != (unsigned char)name[i]) { return 0; }
    }
    return 1;
}

static int valid_headers(tls_connection *connection)
{
    const unsigned char *data = connection->headers;
    size_t size = connection->header_size;
    size_t i = 0;
    size_t start;
    int content_length = 0;
    int post = size >= 7 && memcmp(data, "POST / ", 7) == 0;
    if (!post && (size < 4 || memcmp(data, "GET ", 4) != 0)) { return 0; }
    while (i < size && token(data[i])) { ++i; }
    if (i == 0 || i >= size || data[i++] != ' ') { return 0; }
    start = i;
    while (i < size && data[i] > 0x20 && data[i] < 0x7f) { ++i; }
    if (i == start || i >= size || data[i++] != ' ') { return 0; }
    if (size - i < 10 || memcmp(data + i, "HTTP/1.", 7) != 0 ||
        (data[i + 7] != '0' && data[i + 7] != '1') ||
        data[i + 8] != '\r' || data[i + 9] != '\n') { return 0; }
    connection->close_after_response = data[i + 7] == '0';
    i += 10;
    while (size - i > 2) {
        start = i;
        while (i < size && token(data[i])) { ++i; }
        if (i == start || i >= size || data[i++] != ':') { return 0; }
        size_t name_size = i - start - 1;
        size_t value = i;
        while (i < size && data[i] != '\r') {
            if ((data[i] < 0x20 && data[i] != '\t') || data[i] == 0x7f) { return 0; }
            ++i;
        }
        if (size - i < 2 || data[i + 1] != '\n') { return 0; }
        size_t end = i;
        while (value < end && (data[value] == ' ' || data[value] == '\t')) { ++value; }
        while (end > value && (data[end - 1] == ' ' || data[end - 1] == '\t')) { --end; }
        if (equal_header(data + start, name_size, "transfer-encoding")) { return 0; }
        if (equal_header(data + start, name_size, "content-length")) {
            if (content_length++ || value == end) { return 0; }
            /* Only decimal zero is bodyless; no integer conversion can overflow. */
            for (size_t j = value; j < end; ++j) {
                if (data[j] != '0') { return 0; }
            }
        }
        if (equal_header(data + start, name_size, "connection")) {
            while (value < end) {
                size_t part = value;
                while (value < end && data[value] != ',') { ++value; }
                size_t part_end = value;
                while (part < part_end && (data[part] == ' ' || data[part] == '\t')) { ++part; }
                while (part_end > part && (data[part_end - 1] == ' ' || data[part_end - 1] == '\t')) { --part_end; }
                if (equal_header(data + part, part_end - part, "close")) {
                    connection->close_after_response = 1;
                }
                if (value < end) { ++value; }
            }
        }
        i += 2;
    }
    if (size - i != 2 || data[i] != '\r' || data[i + 1] != '\n' ||
        (post && content_length != 1)) { return 0; }
    return post ? 2 : 1;
}

int tls_connection_host_request(const tls_connection *connection, tls_host_data_request *request)
{
    if (connection == NULL || request == NULL) { return ENGINE_INVALID; }
    *request = connection->pending;
    return 0;
}

int tls_connection_supply_host_chunk(tls_connection *connection,
    const unsigned char *wire, size_t size)
{
    if (connection == NULL) return ENGINE_INVALID;
    if (connection->state != 4 ||
        host_call_receive(&connection->host_object, wire, size) != 0) {
        host_call_release(&connection->host_object);
        connection->pending = (tls_host_data_request){0, 0};
        connection->state = 3;
        connection->error = ENGINE_INVALID;
        return ENGINE_INVALID;
    }
    if (connection->host_object.state != HOST_CALL_COMPLETE) return 0;
    /* Operation-specific decoder: DEMO_DATA permits every binary string,
     * including empty; it has no authentication or authorization meaning. */
    static const char prefix[] = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ";
    unsigned char *out = connection->host_response;
    size_t used = sizeof(prefix) - 1;
    memcpy(out, prefix, used);
    size_t length = connection->host_object.size;
    size_t divisor = 1;
    while (length / divisor >= 10) divisor *= 10;
    do {
        out[used++] = (unsigned char)('0' + length / divisor);
        length %= divisor;
        divisor /= 10;
    } while (divisor);
    const char *ending = connection->close_after_response ? "\r\nConnection: close\r\n\r\n" : "\r\n\r\n";
    size_t ending_size = strlen(ending);
    memcpy(out + used, ending, ending_size);
    connection->host_response_size = used + ending_size;
    connection->host_body = 1;
    connection->pending = (tls_host_data_request){0, 0};
    connection->state = 1;
    return 0;
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
                int kind = valid_headers(connection);
                if (kind == 0) { return ENGINE_HTTP; }
                OPENSSL_cleanse(connection->headers, sizeof(connection->headers));
                if (kind == 2) {
                    if (connection->identity->next_request_id == UINT32_MAX) { return ENGINE_HTTP; }
                    connection->pending.operation = TLS_HOST_OP_DEMO_DATA;
                    connection->pending.id = ++connection->identity->next_request_id;
                    if (host_call_begin(&connection->host_object, &connection->identity->host_budget,
                        connection->pending.operation, connection->pending.id) != 0) return ENGINE_HTTP;
                    connection->state = 4;
                    return 0;
                }
                connection->state = 1;
            } else if (connection->header_size == sizeof(connection->headers)) { return ENGINE_HTTP; }
        } else if (connection->state == 1) {
            const unsigned char *bytes = connection->close_after_response ? response : persistent_response;
            size_t size = connection->close_after_response ? sizeof(response) - 1 : sizeof(persistent_response) - 1;
            if (connection->host_response_size != 0) {
                bytes = connection->host_response;
                size = connection->host_response_size;
            }
            if (connection->response_offset < size) {
                ret = SSL_write(connection->ssl, bytes + connection->response_offset,
                                 (int)(size - connection->response_offset));
                if (ret <= 0) { return ssl_result(connection, ret); }
                connection->response_offset += (size_t)ret;
            }
            if (connection->host_body && connection->response_offset == size &&
                connection->body_offset < connection->host_object.size) {
                size_t available;
                bytes = host_call_slice(&connection->host_object, connection->body_offset, &available);
                ret = SSL_write(connection->ssl, bytes, (int)available);
                if (ret <= 0) { return ssl_result(connection, ret); }
                connection->body_offset += (size_t)ret;
                continue;
            }
            if (connection->response_offset == size) {
                connection->state = connection->close_after_response ? 2 : 0;
                connection->header_size = 0;
                connection->response_offset = 0;
                connection->host_response_size = 0;
                connection->body_offset = 0;
                connection->host_body = 0;
                host_call_release(&connection->host_object);
                OPENSSL_cleanse(connection->host_response, sizeof(connection->host_response));
                connection->close_after_response = 0;
            }
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
    if (connection->state == 4 && input_size != 0) { return ENGINE_INVALID; }
    if (input_size > BIO_ctrl_get_write_guarantee(connection->network)) { return ENGINE_BOUNDS; }
    if (connection->state == 3 && input_size != 0) { return ENGINE_INVALID; }
    /* Copy all input before writing output, including when buffers overlap. */
    if (input_size != 0 && BIO_write(connection->network, input, (int)input_size) != (int)input_size) {
        return ENGINE_TLS;
    }
    if (connection->state != 3 && connection->state != 4) {
        connection->write_pending = 0;
        connection->error = advance(connection);
        if (connection->error != 0) {
            connection->state = 3;
            connection->pending = (tls_host_data_request){0, 0};
            host_call_release(&connection->host_object);
            OPENSSL_cleanse(connection->headers, sizeof(connection->headers));
        }
    }
    size_t count = BIO_ctrl_pending(connection->network);
    if (count > capacity) { count = capacity; }
    if (count != 0) {
        int read = BIO_read(connection->network, output, (int)count);
        if (read > 0) { *written = (size_t)read; }
    }
    if (connection->state == 4) { *flags |= TLS_FLAG_HOST_REQUEST; }
    if (connection->handshake) { *flags |= TLS_FLAG_HANDSHAKE; }
    if (BIO_ctrl_pending(connection->network) != 0 ||
        (connection->state != 3 && connection->write_pending)) {
        *flags |= TLS_FLAG_MORE_OUTPUT;
    }
    if (connection->state == 3) { *flags |= TLS_FLAG_CLOSED; }
    return connection->error;
}
