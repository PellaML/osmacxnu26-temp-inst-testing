// wire_builder.c — compile/run test for the public pointer-free C builder.
#include "granite_ext_wire.h"
#include <stdio.h>
#include <stdlib.h>

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(void) {
    static const uint8_t provider_id[] = "com.example.actions-probe";
    static const uint8_t provider_name[] = "Actions ABI Probe";
    enum { provider_offset = GRANITE_WIRE_HEADER_SIZE };
    enum { data_offset = provider_offset + GRANITE_WIRE_PROVIDER_SIZE };
    enum { id_length = sizeof(provider_id) - 1 };
    enum { name_length = sizeof(provider_name) - 1 };
    enum { total_size = data_offset + id_length + name_length };
    uint8_t module[total_size];
    memset(module, 0, sizeof(module));

    granite_wire_init_header(module);
    module[GRANITE_WIRE_H_FLAGS] = GRANITE_WIRE_FLAG_USERSPACE_ONLY;
    granite_wire_put_u32(module + GRANITE_WIRE_H_TOTAL_SIZE, sizeof(module));
    granite_wire_put_u32(module + GRANITE_WIRE_H_PROVIDERS_OFFSET, provider_offset);
    granite_wire_put_u32(module + GRANITE_WIRE_H_PROVIDERS_COUNT, 1);
    granite_wire_put_u32(module + GRANITE_WIRE_H_REGISTRATIONS_OFFSET, data_offset);
    granite_wire_put_u32(module + GRANITE_WIRE_H_REGISTRATIONS_COUNT, 0);
    granite_wire_put_ref(module + GRANITE_WIRE_H_DATA_OFFSET, data_offset,
        id_length + name_length);

    uint8_t *provider = module + provider_offset;
    granite_wire_init_provider(provider);
    granite_wire_put_u16(provider + GRANITE_WIRE_P_KIND, 13); /* interceptor */
    granite_wire_put_ref(provider + GRANITE_WIRE_P_ID, data_offset, id_length);
    granite_wire_put_ref(provider + GRANITE_WIRE_P_NAME, data_offset + id_length,
        name_length);
    memcpy(module + data_offset, provider_id, id_length);
    memcpy(module + data_offset + id_length, provider_name, name_length);

    if (memcmp(module, "GRANEXT\0", 8) != 0 ||
        get_u16(module + GRANITE_WIRE_H_HEADER_SIZE) != GRANITE_WIRE_HEADER_SIZE ||
        get_u16(module + GRANITE_WIRE_H_PROVIDER_STRIDE) != GRANITE_WIRE_PROVIDER_SIZE ||
        get_u16(module + GRANITE_WIRE_H_REGISTRATION_STRIDE) != GRANITE_WIRE_REGISTRATION_SIZE ||
        get_u32(module + GRANITE_WIRE_H_TOTAL_SIZE) != sizeof(module) ||
        get_u32(provider + GRANITE_WIRE_P_ID) != data_offset)
        return 1;

    FILE *file = fopen("wire-module.bin", "wb");
    if (file == NULL) return 2;
    if (fwrite(module, 1, sizeof(module), file) != sizeof(module)) return 3;
    if (fclose(file) != 0) return 4;
    printf("wire-builder-ok size=%zu provider=%u registration=%u id=%s name=%s\n",
        sizeof(module), GRANITE_WIRE_PROVIDER_SIZE, GRANITE_WIRE_REGISTRATION_SIZE,
        (const char *)provider_id, (const char *)provider_name);
    return 0;
}
