// abi_provider.c — tiny third-party-style provider for the native bootstrap test.
#include "granite_ext.h"
#include <string.h>

static granite_native_status invoke(void *context, granite_bytes request,
    granite_bytes_mut *response) {
    static const uint8_t prefix[] = {'o', 'k', ':'};
    (void)context;
    if (!granite_bytes_valid(request) || !granite_bytes_mut_valid(response) ||
        response->written != 0)
        return GRANITE_EXT_MALFORMED;
    uint32_t needed = (uint32_t)sizeof(prefix) + request.len;
    if (response->capacity < needed || response->ptr == NULL)
        return GRANITE_EXT_BUFFER_TOO_SMALL;
    memcpy(response->ptr, prefix, sizeof(prefix));
    if (request.len != 0 && request.ptr != NULL)
        memcpy(response->ptr + sizeof(prefix), request.ptr, request.len);
    response->written = needed;
    return GRANITE_EXT_OK;
}

static void stop(void *context) { (void)context; }

__attribute__((visibility("default")))
granite_native_status granite_extension_query_v1(
    const granite_host_api_v1 *host, granite_module_api_v1 *module) {
    static const uint8_t manifest[] = {'A','B','I','-','P','R','O','B','E'};
    if (host == NULL || module == NULL || host->size < sizeof(*host) ||
        module->size < sizeof(*module) || host->reserved != 0 || host->call == NULL)
        return GRANITE_EXT_ABI_MISMATCH;
    module->size = sizeof(*module);
    module->abi_major = GRANITE_EXT_NATIVE_ABI_MAJOR;
    module->abi_minor = GRANITE_EXT_NATIVE_ABI_MINOR;
    module->context = NULL;
    module->manifest = (granite_bytes){manifest, (uint32_t)sizeof(manifest), 0};
    module->invoke = invoke;
    module->stop = stop;
    module->flags = GRANITE_EXT_MODULE_USERSPACE_SAFE |
        GRANITE_EXT_MODULE_DETERMINISTIC;
    return GRANITE_EXT_OK;
}
