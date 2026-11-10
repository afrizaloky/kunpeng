#ifndef TEST_TEE_EXT_API_H
#define TEST_TEE_EXT_API_H
#include <stddef.h>
#include <stdint.h>
typedef uint32_t TEE_Result;
typedef union {
    struct { void *buffer; size_t size; } memref;
    struct { uint32_t a, b; } value;
} TEE_Param;
#define TEE_SUCCESS 0u
#define TEE_ERROR_GENERIC 0xffff0000u
#define TEE_ERROR_BAD_PARAMETERS 0xffff0006u
#define TEE_ERROR_BAD_STATE 0xffff0007u
#define TEE_ERROR_BUSY 0xffff000du
#define TEE_PARAM_TYPE_NONE 0u
#define TEE_PARAM_TYPE_VALUE_OUTPUT 2u
#define TEE_PARAM_TYPE_MEMREF_INPUT 5u
#define TEE_PARAM_TYPE_MEMREF_OUTPUT 6u
#define TEE_PARAM_TYPES(a,b,c,d) ((a) | ((b)<<4) | ((c)<<8) | ((d)<<12))
TEE_Result addcaller_ca_exec(const char *, const char *);
void TEE_GenerateRandom(void *, size_t);
_Noreturn void TEE_Panic(TEE_Result);
#endif
