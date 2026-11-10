#include "tls_engine.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/ecp.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#define ENGINE_INVALID (-1)
#define ENGINE_BOUNDS (-2)
#define ENGINE_HTTP (-3)

struct tls_identity {
    mbedtls_pk_context key;
    mbedtls_x509_crt certificate;
    mbedtls_ssl_config config;
    tls_random_fn random;
    void *random_context;
    unsigned char pem[2048];
    size_t pem_size;
};

struct tls_connection {
    mbedtls_ssl_context ssl;
    unsigned char input[TLS_IO_CAPACITY];
    size_t input_size;
    unsigned char output[TLS_IO_CAPACITY];
    size_t output_size;
    unsigned char headers[4096];
    size_t header_size;
    size_t response_offset;
    int handshake;
    int state; /* 0: handshake/headers, 1: response, 2: close, 3: closed */
    int error;
};

static const unsigned char response[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n"
    "Connection: close\r\n\r\nHello from the TEE!\n";

static int identity_random(void *context, unsigned char *out, size_t size)
{
    tls_identity *identity = context;
    int ret = identity->random(identity->random_context, out, size);
    return ret == 0 ? 0 : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

void tls_identity_destroy(tls_identity *identity)
{
    if (identity == NULL) {
        return;
    }
    mbedtls_ssl_config_free(&identity->config);
    mbedtls_x509_crt_free(&identity->certificate);
    mbedtls_pk_free(&identity->key);
    mbedtls_platform_zeroize(identity, sizeof(*identity));
    free(identity);
}

int tls_identity_create(tls_identity **out, tls_random_fn random, void *context)
{
    tls_identity *identity;
    mbedtls_x509write_cert writer;
    unsigned char serial[16] = { 0 };
    /* DER GeneralNames containing a single dNSName localhost. */
    static const unsigned char san[] = {
        0x30, 0x0b, 0x82, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'
    };
    int ret;
    if (out == NULL) {
        return ENGINE_INVALID;
    }
    *out = NULL;
    if (random == NULL) {
        return ENGINE_INVALID;
    }
    identity = calloc(1, sizeof(*identity));
    if (identity == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    identity->random = random;
    identity->random_context = context;
    mbedtls_pk_init(&identity->key);
    mbedtls_x509_crt_init(&identity->certificate);
    mbedtls_ssl_config_init(&identity->config);
    mbedtls_x509write_crt_init(&writer);
    ret = mbedtls_pk_setup(&identity->key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret == 0) {
        ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                  mbedtls_pk_ec(identity->key), identity_random, identity);
    }
    if (ret == 0) {
        ret = identity_random(identity, serial, sizeof(serial));
    }
    serial[0] = (unsigned char) ((serial[0] & 0x7fu) | 1u);
    mbedtls_x509write_crt_set_version(&writer, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&writer, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&writer, &identity->key);
    mbedtls_x509write_crt_set_issuer_key(&writer, &identity->key);
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_serial_raw(&writer, serial, sizeof(serial));
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_subject_name(&writer, "CN=localhost");
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_issuer_name(&writer, "CN=localhost");
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_validity(&writer, "20240101000000", "20491231235959");
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_basic_constraints(&writer, 0, -1);
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_key_usage(&writer, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_extension(&writer, MBEDTLS_OID_SUBJECT_ALT_NAME,
                MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME), 0, san, sizeof(san));
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_pem(&writer, identity->pem, sizeof(identity->pem),
                                       identity_random, identity);
    }
    if (ret == 0) {
        identity->pem_size = strlen((const char *) identity->pem) + 1;
        ret = mbedtls_x509_crt_parse(&identity->certificate, identity->pem, identity->pem_size);
    }
    if (ret == 0) {
        ret = mbedtls_ssl_config_defaults(&identity->config, MBEDTLS_SSL_IS_SERVER,
                                          MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    }
    if (ret == 0) {
        mbedtls_ssl_conf_rng(&identity->config, identity_random, identity);
        mbedtls_ssl_conf_authmode(&identity->config, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_min_tls_version(&identity->config, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&identity->config, MBEDTLS_SSL_VERSION_TLS1_2);
        ret = mbedtls_ssl_conf_own_cert(&identity->config, &identity->certificate, &identity->key);
    }
    mbedtls_x509write_crt_free(&writer);
    mbedtls_platform_zeroize(serial, sizeof(serial));
    if (ret != 0) {
        tls_identity_destroy(identity);
        return ret;
    }
    *out = identity;
    return 0;
}

int tls_identity_certificate(tls_identity *identity, unsigned char *out,
                             size_t capacity, size_t *written)
{
    if (written == NULL) {
        return ENGINE_INVALID;
    }
    *written = 0;
    if (identity == NULL || (out == NULL && capacity != 0)) {
        return ENGINE_INVALID;
    }
    *written = identity->pem_size;
    if (capacity < identity->pem_size) {
        return ENGINE_BOUNDS;
    }
    if (out == NULL) {
        return ENGINE_INVALID;
    }
    memcpy(out, identity->pem, identity->pem_size);
    return 0;
}

static int send_ciphertext(void *context, const unsigned char *data, size_t size)
{
    tls_connection *connection = context;
    size_t available = TLS_IO_CAPACITY - connection->output_size;
    if (available == 0) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    if (size > available) {
        size = available;
    }
    memcpy(connection->output + connection->output_size, data, size);
    connection->output_size += size;
    return (int) size;
}

static int receive_ciphertext(void *context, unsigned char *data, size_t size)
{
    tls_connection *connection = context;
    if (connection->input_size == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    if (size > connection->input_size) {
        size = connection->input_size;
    }
    memcpy(data, connection->input, size);
    connection->input_size -= size;
    memmove(connection->input, connection->input + size, connection->input_size);
    return (int) size;
}

void tls_connection_destroy(tls_connection *connection)
{
    if (connection != NULL) {
        mbedtls_ssl_free(&connection->ssl);
        mbedtls_platform_zeroize(connection, sizeof(*connection));
        free(connection);
    }
}

int tls_connection_create(tls_connection **out, tls_identity *identity)
{
    tls_connection *connection;
    int ret;
    if (out == NULL) {
        return ENGINE_INVALID;
    }
    *out = NULL;
    if (identity == NULL) {
        return ENGINE_INVALID;
    }
    connection = calloc(1, sizeof(*connection));
    if (connection == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    mbedtls_ssl_init(&connection->ssl);
    ret = mbedtls_ssl_setup(&connection->ssl, &identity->config);
    if (ret != 0) {
        tls_connection_destroy(connection);
        return ret;
    }
    mbedtls_ssl_set_bio(&connection->ssl, connection, send_ciphertext, receive_ciphertext, NULL);
    *out = connection;
    return 0;
}

/* A deliberately small HTTP header grammar: token method/field names,
 * nonempty visible request target, HTTP/1.0 or 1.1, CRLF lines, no obs-fold. */
static int token(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           (c != 0 && strchr("!#$%&'*+-.^_`|~", (int) c) != NULL);
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

static int advance(tls_connection *connection)
{
    int ret;
    for (;;) {
        if (!connection->handshake) {
            ret = mbedtls_ssl_handshake(&connection->ssl);
            if (ret != 0) { return ret; }
            connection->handshake = 1;
        }
        if (connection->state == 0) {
            unsigned char byte;
            ret = mbedtls_ssl_read(&connection->ssl, &byte, 1);
            if (ret <= 0) {
                if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                    connection->state = 2;
                    continue;
                }
                return ret;
            }
            connection->headers[connection->header_size++] = byte;
            if (connection->header_size >= 4 &&
                memcmp(connection->headers + connection->header_size - 4, "\r\n\r\n", 4) == 0) {
                if (!valid_headers(connection->headers, connection->header_size)) {
                    return ENGINE_HTTP;
                }
                mbedtls_platform_zeroize(connection->headers, sizeof(connection->headers));
                connection->state = 1;
            } else if (connection->header_size == sizeof(connection->headers)) {
                return ENGINE_HTTP;
            }
        } else if (connection->state == 1) {
            /* Offset changes only after success: identical retry arguments. */
            ret = mbedtls_ssl_write(&connection->ssl, response + connection->response_offset,
                                    sizeof(response) - 1 - connection->response_offset);
            if (ret <= 0) { return ret == 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : ret; }
            connection->response_offset += (size_t) ret;
            if (connection->response_offset == sizeof(response) - 1) {
                connection->state = 2;
            }
        } else if (connection->state == 2) {
            ret = mbedtls_ssl_close_notify(&connection->ssl);
            if (ret != 0) { return ret; }
            connection->state = 3;
            return 0;
        } else {
            return 0;
        }
    }
}

int tls_connection_process(tls_connection *connection,
                           const unsigned char *input, size_t input_size,
                           unsigned char *output, size_t capacity,
                           size_t *written, unsigned int *flags)
{
    int ret;
    size_t count;
    if (written == NULL || flags == NULL) { return ENGINE_INVALID; }
    *written = 0;
    *flags = 0;
    if (connection == NULL || (input == NULL && input_size != 0) ||
        (output == NULL && capacity != 0)) { return ENGINE_INVALID; }
    if (input_size > TLS_IO_CAPACITY - connection->input_size) { return ENGINE_BOUNDS; }
    if (connection->state == 3 && input_size != 0) { return ENGINE_INVALID; }
    if (input_size != 0) {
        memcpy(connection->input + connection->input_size, input, input_size);
        connection->input_size += input_size;
    }
    if (connection->state != 3) {
        ret = advance(connection);
        if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            connection->error = ret;
            connection->state = 3;
            mbedtls_platform_zeroize(connection->headers, sizeof(connection->headers));
        }
    }
    count = connection->output_size < capacity ? connection->output_size : capacity;
    if (count != 0) {
        memcpy(output, connection->output, count);
        connection->output_size -= count;
        memmove(connection->output, connection->output + count, connection->output_size);
    }
    *written = count;
    if (connection->handshake) { *flags |= TLS_FLAG_HANDSHAKE; }
    if (connection->output_size != 0) { *flags |= TLS_FLAG_MORE_OUTPUT; }
    if (connection->state == 3) { *flags |= TLS_FLAG_CLOSED; }
    return connection->error;
}
