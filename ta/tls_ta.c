#include <tee_ext_api.h>
#include <tee_crypto_api.h>
#include "tls_engine.h"
#include "tls_protocol.h"

_Static_assert(TLS_IO_CAPACITY == TLS_PROTOCOL_CAPACITY, "capacity contract");
_Static_assert(TLS_FLAG_HANDSHAKE == TLS_PROTOCOL_FLAG_HANDSHAKE &&
    TLS_FLAG_MORE_OUTPUT == TLS_PROTOCOL_FLAG_MORE_OUTPUT &&
    TLS_FLAG_CLOSED == TLS_PROTOCOL_FLAG_CLOSED, "flag contract");

static tls_identity *identity;
static int session_active;

static int random_bytes(void *context, unsigned char *output, size_t length)
{
    (void)context;
    TEE_GenerateRandom(output, length);
    return 0;
}

TEE_Result TA_CreateEntryPoint(void)
{
    if (addcaller_ca_exec("/vendor/bin/kunpeng-tls-host", "root") != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;
    if (tls_identity_create(&identity, random_bytes, NULL) != 0)
        return TEE_ERROR_GENERIC;
    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t types, TEE_Param params[4], void **context)
{
    tls_connection *connection = NULL;
    (void)params;
    if (context == NULL || types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    *context = NULL;
    /* Defense against overlapping sessions; not a synchronization primitive.
     * The TA manifest must enforce single-session execution. */
    if (session_active)
        return TEE_ERROR_BUSY;
    if (tls_connection_create(&connection, identity) != 0)
        return TEE_ERROR_GENERIC;
    session_active = 1;
    *context = connection;
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *context, uint32_t command,
    uint32_t types, TEE_Param params[4])
{
    size_t written = 0;
    unsigned int flags = 0;
    int result;
    if (context == NULL || params == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    switch (command) {
    case TLS_CMD_PROCESS:
        if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
            TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT,
            TEE_PARAM_TYPE_NONE))
            return TEE_ERROR_BAD_PARAMETERS;
        if (params[0].memref.size > TLS_PROTOCOL_CAPACITY ||
            (params[0].memref.size != 0 && params[0].memref.buffer == NULL) ||
            params[1].memref.size == 0 ||
            params[1].memref.size > TLS_PROTOCOL_CAPACITY ||
            params[1].memref.buffer == NULL)
            return TEE_ERROR_BAD_PARAMETERS;
        result = tls_connection_process(context, params[0].memref.buffer,
            params[0].memref.size, params[1].memref.buffer,
            params[1].memref.size, &written, &flags);
        params[1].memref.size = written;
        params[2].value.a = flags | (result != 0 ?
            TLS_PROTOCOL_FLAG_FATAL | TLS_PROTOCOL_FLAG_CLOSED : 0u);
        params[2].value.b = 0;
        return TEE_SUCCESS;
    case TLS_CMD_CERTIFICATE:
        if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE) ||
            params[0].memref.buffer == NULL || params[0].memref.size == 0 ||
            params[0].memref.size > TLS_PROTOCOL_CAPACITY)
            return TEE_ERROR_BAD_PARAMETERS;
        result = tls_identity_certificate(identity, params[0].memref.buffer,
            params[0].memref.size, &written);
        params[0].memref.size = written;
        return result == 0 ? TEE_SUCCESS : TEE_ERROR_GENERIC;
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

void TA_CloseSessionEntryPoint(void *context)
{
    if (context != NULL) {
        tls_connection_destroy(context);
        session_active = 0;
    }
}

void TA_DestroyEntryPoint(void)
{
    tls_identity_destroy(identity);
    identity = NULL;
}
