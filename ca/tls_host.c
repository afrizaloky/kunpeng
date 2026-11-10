#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "tee_client_api.h"
#include "tls_protocol.h"

static const TEEC_UUID uuid = TLS_TA_UUID;

static void tee_error(const char *action, TEEC_Result result, uint32_t origin)
{
    fprintf(stderr, "%s: TEEC result=0x%08x origin=0x%08x\n",
        action, (unsigned int)result, origin);
}

static int open_session(TEEC_Context *context, TEEC_Session *session)
{
    TEEC_Operation operation = {0};
    uint32_t origin = 0;
    TEEC_Result result;
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    result = TEEC_OpenSession(context, session, &uuid, TEEC_LOGIN_IDENTIFY,
        NULL, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        tee_error("open session", result, origin);
        return -1;
    }
    return 0;
}

static int export_certificate(TEEC_Context *context, const char *path)
{
    TEEC_Session session = {0};
    TEEC_Operation operation = {0};
    unsigned char certificate[TLS_PROTOCOL_CAPACITY];
    uint32_t origin = 0;
    TEEC_Result result;
    FILE *file;
    size_t length;
    int status = -1;
    if (open_session(context, &session) != 0)
        return -1;
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = certificate;
    operation.params[0].tmpref.size = sizeof(certificate);
    result = TEEC_InvokeCommand(&session, TLS_CMD_CERTIFICATE, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        tee_error("export certificate", result, origin);
        goto done;
    }
    length = operation.params[0].tmpref.size;
    if (length < 2 || length > sizeof(certificate) || certificate[length - 1] != '\0') {
        fprintf(stderr, "invalid public certificate response\n");
        goto done;
    }
    file = fopen(path, "wb");
    if (file == NULL) {
        perror("open certificate file");
        goto done;
    }
    status = 0;
    if (fwrite(certificate, 1, length - 1, file) != length - 1) {
        perror("write certificate file");
        status = -1;
    }
    if (fclose(file) != 0) {
        perror("close certificate file");
        status = -1;
    }
done:
    TEEC_CloseSession(&session);
    return status;
}

static int send_all(int socket_fd, const unsigned char *data, size_t length)
{
    while (length != 0) {
        ssize_t sent = send(socket_fd, data, length, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0) {
            if (sent < 0)
                perror("send ciphertext");
            else
                fprintf(stderr, "send ciphertext: no progress\n");
            return -1;
        }
        data += (size_t)sent;
        length -= (size_t)sent;
    }
    return 0;
}

static void relay(int socket_fd, TEEC_Session *session)
{
    unsigned char input[TLS_PROTOCOL_CAPACITY];
    unsigned char output[TLS_PROTOCOL_CAPACITY];
    unsigned int flags = 0;
    int fatal = 0;
    /* Start with empty input, then always drain before receiving again. */
    size_t length = 0;
    for (;;) {
        TEEC_Operation operation = {0};
        uint32_t origin = 0;
        TEEC_Result result;
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_OUTPUT, TEEC_NONE);
        operation.params[0].tmpref.buffer = input;
        operation.params[0].tmpref.size = (uint32_t)length;
        operation.params[1].tmpref.buffer = output;
        operation.params[1].tmpref.size = sizeof(output);
        result = TEEC_InvokeCommand(session, TLS_CMD_PROCESS, &operation, &origin);
        if (result != TEEC_SUCCESS) {
            tee_error("process ciphertext", result, origin);
            return;
        }
        flags = operation.params[2].value.a;
        length = operation.params[1].tmpref.size;
        if (length > sizeof(output) || operation.params[2].value.b != 0 ||
            (flags & ~(TLS_PROTOCOL_FLAG_HANDSHAKE | TLS_PROTOCOL_FLAG_MORE_OUTPUT |
                TLS_PROTOCOL_FLAG_CLOSED | TLS_PROTOCOL_FLAG_FATAL)) != 0) {
            fprintf(stderr, "invalid process response\n");
            return;
        }
        if (send_all(socket_fd, output, length) != 0)
            return;
        fatal |= (flags & TLS_PROTOCOL_FLAG_FATAL) != 0;
        length = 0;
        if (flags & TLS_PROTOCOL_FLAG_MORE_OUTPUT)
            continue;
        if (fatal || (flags & TLS_PROTOCOL_FLAG_CLOSED))
            return;
        for (;;) {
            ssize_t received = recv(socket_fd, input, sizeof(input), 0);
            if (received < 0 && errno == EINTR)
                continue;
            if (received <= 0) {
                if (received < 0)
                    perror("receive ciphertext");
                return;
            }
            length = (size_t)received;
            break;
        }
    }
}

static void usage(const char *program)
{
    printf("Usage: %s --certificate-out FILE [--port PORT] [--bind IPv4] [--ta PATH]\n"
        "Defaults: --port 8443 --bind 127.0.0.1\n", program);
}

int main(int argc, char **argv)
{
    static const struct option options[] = {
        {"port", required_argument, NULL, 'p'},
        {"certificate-out", required_argument, NULL, 'c'},
        {"bind", required_argument, NULL, 'b'},
        {"ta", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    const char *certificate_path = NULL;
    const char *ta_path = NULL;
    struct sockaddr_in address = {0};
    TEEC_Context context = {0};
    TEEC_Result result;
    int listener = -1;
    int status = EXIT_FAILURE;
    int option;
    address.sin_family = AF_INET;
    address.sin_port = htons(8443);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'h': usage(argv[0]); return EXIT_SUCCESS;
        case 'c': certificate_path = optarg; break;
        case 't': ta_path = optarg; break;
        case 'b':
            if (inet_pton(AF_INET, optarg, &address.sin_addr) != 1) {
                fprintf(stderr, "--bind requires an IPv4 address\n");
                return EXIT_FAILURE;
            }
            break;
        case 'p': {
            char *end;
            unsigned long port;
            errno = 0;
            port = strtoul(optarg, &end, 10);
            if (errno != 0 || end == optarg || *end != '\0' ||
                optarg[0] < '0' || optarg[0] > '9' || port == 0 || port > 65535) {
                fprintf(stderr, "--port requires a number from 1 to 65535\n");
                return EXIT_FAILURE;
            }
            address.sin_port = htons((uint16_t)port);
            break;
        }
        default: usage(argv[0]); return EXIT_FAILURE;
        }
    }
    if (certificate_path == NULL || *certificate_path == '\0' || optind != argc ||
        (ta_path != NULL && *ta_path == '\0')) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS) {
        tee_error("initialize context", result, 0);
        return EXIT_FAILURE;
    }
    context.ta_path = (uint8_t *)ta_path;
    if (export_certificate(&context, certificate_path) != 0)
        goto done;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        goto done;
    }
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0) {
        perror("bind/listen");
        goto done;
    }
    for (;;) {
        TEEC_Session session = {0};
        struct timeval timeout = {.tv_sec = 15, .tv_usec = 0};
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            goto done;
        }
        if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
            perror("set socket timeout");
            close(client);
            continue;
        }
        if (open_session(&context, &session) != 0) {
            close(client);
            goto done;
        }
        relay(client, &session);
        TEEC_CloseSession(&session);
        if (close(client) != 0)
            perror("close client");
    }
done:
    if (listener >= 0 && close(listener) != 0)
        perror("close listener");
    TEEC_FinalizeContext(&context);
    return status;
}
