#include <tee_ext_api.h>
#include <tee_crypto_api.h>
#include <tee_core_api.h>
#include <pthread.h>

#include "tls_engine.h"
#include "tls_protocol.h"

#ifdef KUNPENG_ITRUSTEE
#include <tee_log.h>
#define TA_STARTUP_ERROR(stage, code) \
    tloge("tls-ta failure stage=%s code=0x%x\n", stage, (unsigned int)(code))
#else
#define TA_STARTUP_ERROR(stage, code) ((void)(stage), (void)(code))
#endif

_Static_assert(TLS_IO_CAPACITY == TLS_PROTOCOL_CAPACITY, "capacity contract");
_Static_assert(TLS_FLAG_HANDSHAKE == TLS_PROTOCOL_FLAG_HANDSHAKE &&
    TLS_FLAG_MORE_OUTPUT == TLS_PROTOCOL_FLAG_MORE_OUTPUT &&
    TLS_FLAG_CLOSED == TLS_PROTOCOL_FLAG_CLOSED, "flag contract");

static tls_identity *identity;
static unsigned int session_count;
static pthread_mutex_t engine_mutex = PTHREAD_MUTEX_INITIALIZER;

static void unlock_engine(void)
{
    if (pthread_mutex_unlock(&engine_mutex) != 0)
        TEE_Panic(TEE_ERROR_GENERIC);
}

static int random_bytes(void *context, unsigned char *output, size_t length)
{
    (void)context;
    TEE_GenerateRandom(output, length);
    return 0;
}

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result caller_result = addcaller_ca_exec("/vendor/bin/kunpeng-tls-host", "root");
    if (caller_result != TEE_SUCCESS) {
        TA_STARTUP_ERROR("caller-registration", caller_result);
        return TEE_ERROR_GENERIC;
    }
    int lock_result = pthread_mutex_lock(&engine_mutex);
    if (lock_result != 0) {
        TA_STARTUP_ERROR("create-mutex", lock_result);
        return TEE_ERROR_GENERIC;
    }
    TEE_Result result = TEE_ERROR_BAD_STATE;
    if (identity == NULL && session_count == 0)
        result = tls_identity_create(&identity, random_bytes, NULL) == 0 ?
            TEE_SUCCESS : TEE_ERROR_GENERIC;
    if (result != TEE_SUCCESS)
        TA_STARTUP_ERROR("identity-create", result);
    unlock_engine();
    return result;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t types, TEE_Param params[4], void **context)
{
    tls_connection *connection = NULL;
    (void)params;
    if (context == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    *context = NULL;
    /* TEEC_LOGIN_IDENTIFY reserves slots 2/3 for driver-injected identity inputs.
     * Caller authorization remains the addcaller_ca_exec allowlist, not these bytes. */
    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT))
        return TEE_ERROR_BAD_PARAMETERS;
    int lock_result = pthread_mutex_lock(&engine_mutex);
    if (lock_result != 0) {
        TA_STARTUP_ERROR("open-mutex", lock_result);
        return TEE_ERROR_GENERIC;
    }
    TEE_Result result;
    if (identity == NULL)
        result = TEE_ERROR_BAD_STATE;
    else if (session_count >= TLS_MAX_SESSIONS)
        result = TEE_ERROR_BUSY;
    else {
        int connection_result = tls_connection_create(&connection, identity);
        if (connection_result != 0) {
            TA_STARTUP_ERROR("connection-create", connection_result);
            result = TEE_ERROR_GENERIC;
        } else {
            ++session_count;
            *context = connection;
            result = TEE_SUCCESS;
        }
    }
    unlock_engine();
    return result;
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
        if (pthread_mutex_lock(&engine_mutex) != 0)
            return TEE_ERROR_GENERIC;
        result = tls_connection_process(context, params[0].memref.buffer,
            params[0].memref.size, params[1].memref.buffer,
            params[1].memref.size, &written, &flags);
        unlock_engine();
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
        if (pthread_mutex_lock(&engine_mutex) != 0)
            return TEE_ERROR_GENERIC;
        result = tls_identity_certificate(identity, params[0].memref.buffer,
            params[0].memref.size, &written);
        unlock_engine();
        params[0].memref.size = written;
        return result == 0 ? TEE_SUCCESS : TEE_ERROR_GENERIC;
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

void TA_CloseSessionEntryPoint(void *context)
{
    if (context != NULL) {
        if (pthread_mutex_lock(&engine_mutex) != 0) {
            TEE_Panic(TEE_ERROR_GENERIC);
            return;
        }
        if (session_count == 0) {
            TEE_Panic(TEE_ERROR_BAD_STATE);
            return;
        }
        tls_connection_destroy(context);
        --session_count;
        unlock_engine();
    }
}

void TA_DestroyEntryPoint(void)
{
    if (pthread_mutex_lock(&engine_mutex) != 0) {
        TEE_Panic(TEE_ERROR_GENERIC);
        return;
    }
    if (session_count != 0) {
        TEE_Panic(TEE_ERROR_BAD_STATE);
        return;
    }
    tls_identity_destroy(identity);
    identity = NULL;
    unlock_engine();
}
