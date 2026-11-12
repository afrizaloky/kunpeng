#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "tee_ext_api.h"
#include "tls_engine.h"
#include "tls_protocol.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
static pthread_mutex_t monitor = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned attempts, entered, active, maximum, live, identities;
static int gate, release_gate, fail_create;
static void wait_until(unsigned *value, unsigned target)
{
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 10;
    while (*value < target)
        CHECK(pthread_cond_timedwait(&changed, &monitor, &deadline) == 0);
}
/* Observe attempts before the real TA lock, not timing or thread scheduling. */
static int ta_lock(pthread_mutex_t *mutex)
{
    CHECK(pthread_mutex_lock(&monitor) == 0);
    ++attempts;
    CHECK(pthread_cond_broadcast(&changed) == 0);
    CHECK(pthread_mutex_unlock(&monitor) == 0);
    return pthread_mutex_lock(mutex);
}
#define pthread_mutex_lock ta_lock
#include "../ta/tls_ta.c"
#undef pthread_mutex_lock

struct tls_identity { int marker; };
struct tls_connection { tls_identity *owner; };
static void engine_enter(void)
{
    CHECK(pthread_mutex_lock(&monitor) == 0);
    ++active;
    if (active > maximum) maximum = active;
    ++entered;
    CHECK(pthread_cond_broadcast(&changed) == 0);
    while (gate && !release_gate) {
        struct timespec deadline;
        CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
        deadline.tv_sec += 10;
        CHECK(pthread_cond_timedwait(&changed, &monitor, &deadline) == 0);
    }
    CHECK(pthread_mutex_unlock(&monitor) == 0);
}
static void engine_leave(void)
{
    CHECK(pthread_mutex_lock(&monitor) == 0);
    CHECK(active != 0);
    --active;
    CHECK(pthread_mutex_unlock(&monitor) == 0);
}
TEE_Result addcaller_ca_exec(const char *path, const char *user)
{
    CHECK(strcmp(path, "/vendor/bin/kunpeng-tls-host") == 0);
    CHECK(strcmp(user, "root") == 0);
    return TEE_SUCCESS;
}
void TEE_GenerateRandom(void *out, size_t size) { memset(out, 1, size); }
_Noreturn void TEE_Panic(TEE_Result result) { (void)result; abort(); }
int tls_identity_create(tls_identity **out, tls_random_fn random, void *context)
{
    unsigned char byte;
    engine_enter();
    CHECK(random(context, &byte, 1) == 0);
    *out = calloc(1, sizeof(**out));
    CHECK(*out != NULL);
    ++identities;
    engine_leave();
    return 0;
}
void tls_identity_destroy(tls_identity *id)
{
    engine_enter(); CHECK(live == 0); free(id); --identities; engine_leave();
}
int tls_connection_create(tls_connection **out, tls_identity *id)
{
    engine_enter(); CHECK(id != NULL && identities == 1);
    if (fail_create) { fail_create = 0; *out = NULL; engine_leave(); return -1; }
    *out = malloc(sizeof(**out)); CHECK(*out != NULL);
    (*out)->owner = id; ++live; engine_leave(); return 0;
}
void tls_connection_destroy(tls_connection *connection)
{
    engine_enter(); CHECK(connection->owner != NULL && live != 0);
    free(connection); --live; engine_leave();
}
int tls_identity_certificate(tls_identity *id, unsigned char *out, size_t capacity, size_t *written)
{
    engine_enter(); CHECK(id != NULL && capacity >= 1);
    out[0] = 42; *written = 1; engine_leave(); return 0;
}
int tls_connection_process(tls_connection *connection, const unsigned char *input,
    size_t size, unsigned char *out, size_t capacity, size_t *written, unsigned *flags)
{
    (void)input; (void)size;
    engine_enter(); CHECK(connection->owner != NULL && capacity >= 1);
    out[0] = 17; *written = 1; *flags = TLS_FLAG_HANDSHAKE; engine_leave(); return 0;
}
struct job { unsigned operation; void *context; };
static void *run_job(void *argument)
{
    struct job *job = argument;
    unsigned char output[16];
    TEE_Param params[4] = {0};
    if (job->operation == 0) {
        params[1].memref.buffer = output; params[1].memref.size = sizeof(output);
        CHECK(TA_InvokeCommandEntryPoint(job->context, TLS_CMD_PROCESS,
            TEE_PARAM_TYPES(5, 6, 2, 0), params) == TEE_SUCCESS);
        CHECK(output[0] == 17 && params[1].memref.size == 1);
        CHECK(params[2].value.a == TLS_FLAG_HANDSHAKE);
    } else if (job->operation == 1) {
        params[0].memref.buffer = output; params[0].memref.size = sizeof(output);
        CHECK(TA_InvokeCommandEntryPoint(job->context, TLS_CMD_CERTIFICATE,
            TEE_PARAM_TYPES(6, 0, 0, 0), params) == TEE_SUCCESS);
        CHECK(output[0] == 42 && params[0].memref.size == 1);
    } else if (job->operation == 2) {
        CHECK(TA_OpenSessionEntryPoint(TEE_PARAM_TYPES(0, 0, 5, 5), NULL, &job->context) == TEE_SUCCESS);
    } else {
        TA_CloseSessionEntryPoint(job->context); job->context = NULL;
    }
    return NULL;
}
int main(void)
{
    void *contexts[TLS_MAX_SESSIONS] = {0}, *extra = NULL;
    CHECK(TA_OpenSessionEntryPoint(TEE_PARAM_TYPES(0, 0, 5, 5), NULL, &extra) == TEE_ERROR_BAD_STATE);
    CHECK(TA_CreateEntryPoint() == TEE_SUCCESS);
    /* Only the driver-injected INPUT identity slots are accepted. */
    unsigned before_reject = entered;
    CHECK(TA_OpenSessionEntryPoint(TEE_PARAM_TYPES(0, 0, 5, 5), NULL, NULL) ==
        TEE_ERROR_BAD_PARAMETERS);
    for (unsigned slot = 0; slot < 4; ++slot) {
        for (unsigned type = 0; type < 16; ++type) {
            unsigned expected = slot < 2 ? TEE_PARAM_TYPE_NONE : TEE_PARAM_TYPE_MEMREF_INPUT;
            if (type == expected) continue;
            uint32_t types = (0x5500u & ~(0xfu << (slot * 4))) | (type << (slot * 4));
            extra = &before_reject;
            CHECK(TA_OpenSessionEntryPoint(types, NULL, &extra) == TEE_ERROR_BAD_PARAMETERS);
            CHECK(extra == NULL && entered == before_reject && live == 0);
        }
    }
    extra = &before_reject;
    CHECK(TA_OpenSessionEntryPoint(0, NULL, &extra) == TEE_ERROR_BAD_PARAMETERS);
    CHECK(extra == NULL && entered == before_reject && live == 0);
    fail_create = 1;
    CHECK(TA_OpenSessionEntryPoint(TEE_PARAM_TYPES(0, 0, 5, 5), NULL, &extra) == TEE_ERROR_GENERIC && extra == NULL);
    for (unsigned i = 0; i < TLS_MAX_SESSIONS; ++i) {
        CHECK(TA_OpenSessionEntryPoint(TEE_PARAM_TYPES(0, 0, 5, 5), NULL, &contexts[i]) == TEE_SUCCESS);
        for (unsigned j = 0; j < i; ++j) CHECK(contexts[i] != contexts[j]);
    }
    CHECK(live == TLS_MAX_SESSIONS);
    CHECK(TA_OpenSessionEntryPoint(TEE_PARAM_TYPES(0, 0, 5, 5), NULL, &extra) == TEE_ERROR_BUSY && extra == NULL);
    TA_CloseSessionEntryPoint(contexts[7]);
    CHECK(TA_OpenSessionEntryPoint(TEE_PARAM_TYPES(0, 0, 5, 5), NULL, &contexts[7]) == TEE_SUCCESS);
    for (unsigned i = 3; i < TLS_MAX_SESSIONS; ++i) TA_CloseSessionEntryPoint(contexts[i]);

    pthread_t threads[4];
    struct job jobs[4] = {{0, contexts[0]}, {1, contexts[1]}, {2, NULL}, {3, contexts[2]}};
    CHECK(pthread_mutex_lock(&monitor) == 0);
    gate = 1; release_gate = 0;
    unsigned start_attempts = attempts, start_entered = entered;
    CHECK(pthread_mutex_unlock(&monitor) == 0);
    CHECK(pthread_create(&threads[0], NULL, run_job, &jobs[0]) == 0);
    CHECK(pthread_mutex_lock(&monitor) == 0);
    wait_until(&entered, start_entered + 1);
    CHECK(pthread_mutex_unlock(&monitor) == 0);
    for (unsigned i = 1; i < 4; ++i) CHECK(pthread_create(&threads[i], NULL, run_job, &jobs[i]) == 0);
    CHECK(pthread_mutex_lock(&monitor) == 0);
    wait_until(&attempts, start_attempts + 4);
    CHECK(entered == start_entered + 1 && active == 1);
    release_gate = 1;
    CHECK(pthread_cond_broadcast(&changed) == 0);
    CHECK(pthread_mutex_unlock(&monitor) == 0);
    for (unsigned i = 0; i < 4; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(maximum == 1 && live == 3);
    TA_CloseSessionEntryPoint(contexts[0]); TA_CloseSessionEntryPoint(contexts[1]);
    TA_CloseSessionEntryPoint(jobs[2].context);
    CHECK(live == 0 && identities == 1);
    CHECK(TA_OpenSessionEntryPoint(TEE_PARAM_TYPES(0, 0, 5, 5), NULL, &extra) == TEE_SUCCESS);
    TA_CloseSessionEntryPoint(extra);
    TA_DestroyEntryPoint(); CHECK(identities == 0);
    puts("TA sessions: cap, allocation rollback, slot reuse, identity lifetime and serialization passed");
    return 0;
}
