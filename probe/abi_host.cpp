// abi_host.cpp — loads a C provider and exercises the bootstrap from C++.
#include "granite_ext.h"
#include <dlfcn.h>
#include <cstdio>
#include <cstring>

static granite_native_status host_call(void *context, uint32_t opcode,
    granite_bytes request, granite_bytes_mut *response) {
    (void)context;
    (void)request;
    (void)response;
    return opcode <= GRANITE_EXT_HOST_PROTECTED_SURFACE
        ? GRANITE_EXT_OK : GRANITE_EXT_UNSUPPORTED;
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    void *image = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (image == nullptr) {
        std::fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }
    void *symbol = dlsym(image, GRANITE_EXT_QUERY_SYMBOL);
    granite_extension_query_fn_v1 query = nullptr;
    static_assert(sizeof(query) == sizeof(symbol));
    std::memcpy(&query, &symbol, sizeof(query));
    if (query == nullptr) return 2;

    granite_host_api_v1 host{};
    host.size = sizeof(host);
    host.call = host_call;
    host.capabilities = UINT64_C(0x0102030405060708);
    granite_module_api_v1 module{};
    module.size = sizeof(module);
    granite_native_status status = query(&host, &module);
    if (status != GRANITE_EXT_OK || module.size != sizeof(module) ||
        module.abi_major != GRANITE_EXT_NATIVE_ABI_MAJOR ||
        module.abi_minor != GRANITE_EXT_NATIVE_ABI_MINOR ||
        module.invoke == nullptr || module.stop == nullptr ||
        module.manifest.len != 9 || module.manifest.ptr == nullptr)
        return 3;

    const uint8_t request_data[] = {'p','i','n','g'};
    uint8_t output[32]{};
    granite_bytes request{request_data, static_cast<uint32_t>(sizeof(request_data)), 0};
    granite_bytes_mut response{output, static_cast<uint32_t>(sizeof(output)), 0};
    status = module.invoke(module.context, request, &response);
    static const uint8_t expected[] = {'o','k',':','p','i','n','g'};
    if (status != GRANITE_EXT_OK || response.written != sizeof(expected) ||
        std::memcmp(output, expected, sizeof(expected)) != 0)
        return 4;
    module.stop(module.context);

    std::printf("native-abi-ok pointer=%zu bytes=%zu host=%zu module=%zu "
        "manifest=%.*s response=%.*s\n", sizeof(void *), sizeof(granite_bytes),
        sizeof(granite_host_api_v1), sizeof(granite_module_api_v1),
        static_cast<int>(module.manifest.len),
        reinterpret_cast<const char *>(module.manifest.ptr),
        static_cast<int>(response.written), reinterpret_cast<const char *>(output));
    dlclose(image);
    return 0;
}
