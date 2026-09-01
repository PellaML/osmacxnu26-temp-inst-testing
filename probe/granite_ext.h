/*
 * granite_ext.h — stable native extension bootstrap ABI, version 1.0.
 *
 * Rich requests and manifests are pointer-free little-endian byte messages. This
 * header contains only the two-function bootstrap. A module exports exactly:
 *
 *   granite_native_status granite_extension_query_v1(
 *       const granite_host_api_v1 *, granite_module_api_v1 *);
 *
 * This is Apache-2.0 and may be copied into proprietary modules. No private key or
 * DRM implementation belongs in the kernel tree; a licensed provider attaches here.
 *
 * Native code is a hostile boundary, not a memory-safety promise. The host validates
 * and copies every span before use; a nonzero length requires a non-null pointer, and
 * addresses still require platform-specific validation in the loader capsule. Neither
 * a Rust panic nor a C++ exception may unwind through any function in this header.
 */
#ifndef GRANITE_EXT_H
#define GRANITE_EXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(UINTPTR_MAX) || UINTPTR_MAX != UINT64_MAX
# error "granite native extensions require a 64-bit host ABI"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define GRANITE_EXT_NATIVE_ABI_MAJOR 1u
#define GRANITE_EXT_NATIVE_ABI_MINOR 0u
#define GRANITE_EXT_QUERY_SYMBOL "granite_extension_query_v1"

typedef int32_t granite_native_status;
enum {
    GRANITE_EXT_OK               = 0,
    GRANITE_EXT_BUFFER_TOO_SMALL = 1,
    GRANITE_EXT_UNSUPPORTED      = 2,
    GRANITE_EXT_MALFORMED        = 3,
    GRANITE_EXT_ABI_MISMATCH     = 4,
    GRANITE_EXT_PROVIDER_ERROR   = 5,
    GRANITE_EXT_WOULD_BLOCK      = 6,
};

typedef struct granite_bytes {
    const uint8_t *ptr;
    uint32_t len;
    uint32_t reserved;
} granite_bytes;

typedef struct granite_bytes_mut {
    uint8_t *ptr;
    uint32_t capacity;
    uint32_t written;
} granite_bytes_mut;

/* Structural checks only; they cannot prove that a foreign address is mapped. */
static inline bool granite_bytes_valid(granite_bytes bytes) {
    return bytes.reserved == 0 && (bytes.len == 0 || bytes.ptr != NULL);
}

static inline bool granite_bytes_mut_valid(const granite_bytes_mut *bytes) {
    return bytes != NULL && bytes->written <= bytes->capacity &&
        (bytes->capacity == 0 || bytes->ptr != NULL);
}

typedef granite_native_status (*granite_invoke_fn)(
    void *module_context,
    granite_bytes request,
    granite_bytes_mut *response);

typedef void (*granite_stop_fn)(void *module_context);

typedef granite_native_status (*granite_host_call_fn)(
    void *host_context,
    uint32_t opcode,
    granite_bytes request,
    granite_bytes_mut *response);

typedef struct granite_host_api_v1 {
    uint32_t size;
    uint32_t reserved;
    void *context;
    granite_host_call_fn call;
    uint64_t capabilities;
} granite_host_api_v1;

typedef struct granite_module_api_v1 {
    uint32_t size;
    uint16_t abi_major;
    uint16_t abi_minor;
    void *context;
    granite_bytes manifest;
    granite_invoke_fn invoke;
    granite_stop_fn stop;
    uint64_t flags;
} granite_module_api_v1;

typedef granite_native_status (*granite_extension_query_fn_v1)(
    const granite_host_api_v1 *host,
    granite_module_api_v1 *module);

/* The one symbol a native module exports. */
granite_native_status granite_extension_query_v1(
    const granite_host_api_v1 *host,
    granite_module_api_v1 *module);

/* Module flags. */
#define GRANITE_EXT_MODULE_USERSPACE_SAFE UINT64_C(0x0001)
#define GRANITE_EXT_MODULE_DETERMINISTIC   UINT64_C(0x0002)
#define GRANITE_EXT_MODULE_SNAPSHOT        UINT64_C(0x0004)
#define GRANITE_EXT_MODULE_REALTIME        UINT64_C(0x0008)
#define GRANITE_EXT_MODULE_KNOWN_FLAGS     UINT64_C(0x000f)

/* Generic host-call opcodes. */
#define GRANITE_EXT_HOST_BUFFER_READ       1u
#define GRANITE_EXT_HOST_BUFFER_WRITE      2u
#define GRANITE_EXT_HOST_BUFFER_ALLOC      3u
#define GRANITE_EXT_HOST_BUFFER_RELEASE    4u
#define GRANITE_EXT_HOST_LOG               5u
#define GRANITE_EXT_HOST_MONOTONIC_TIME    6u
#define GRANITE_EXT_HOST_TASK_INFO         7u
#define GRANITE_EXT_HOST_RESUME            8u
#define GRANITE_EXT_HOST_CALL_NEXT         9u
#define GRANITE_EXT_HOST_CALL_ORIGINAL    10u
#define GRANITE_EXT_HOST_CALL_TAG         11u
#define GRANITE_EXT_HOST_PROTECTED_SURFACE 12u

/* Compile in every module. If one fails, compiler/packing flags changed the ABI. */
#if defined(__cplusplus)
static_assert(sizeof(granite_bytes) == 16, "granite_bytes ABI");
static_assert(offsetof(granite_bytes, len) == 8, "granite_bytes.len ABI");
static_assert(sizeof(granite_bytes_mut) == 16, "granite_bytes_mut ABI");
static_assert(sizeof(granite_host_api_v1) == 32, "granite_host_api_v1 ABI");
static_assert(offsetof(granite_host_api_v1, call) == 16, "host.call ABI");
static_assert(sizeof(granite_module_api_v1) == 56, "granite_module_api_v1 ABI");
static_assert(offsetof(granite_module_api_v1, manifest) == 16, "module.manifest ABI");
static_assert(offsetof(granite_module_api_v1, invoke) == 32, "module.invoke ABI");
#else
_Static_assert(sizeof(granite_bytes) == 16, "granite_bytes ABI");
_Static_assert(offsetof(granite_bytes, len) == 8, "granite_bytes.len ABI");
_Static_assert(sizeof(granite_bytes_mut) == 16, "granite_bytes_mut ABI");
_Static_assert(sizeof(granite_host_api_v1) == 32, "granite_host_api_v1 ABI");
_Static_assert(offsetof(granite_host_api_v1, call) == 16, "host.call ABI");
_Static_assert(sizeof(granite_module_api_v1) == 56, "granite_module_api_v1 ABI");
_Static_assert(offsetof(granite_module_api_v1, manifest) == 16, "module.manifest ABI");
_Static_assert(offsetof(granite_module_api_v1, invoke) == 32, "module.invoke ABI");
#endif

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* GRANITE_EXT_H */
