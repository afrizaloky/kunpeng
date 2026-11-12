/* Rename only direct engine allocations, never shared libcrypto references. */
#include <stdlib.h>
#include "heap_tracker.h"
#define calloc heap_engine_calloc
#define free heap_free
#include "../src/tls_engine.c"
