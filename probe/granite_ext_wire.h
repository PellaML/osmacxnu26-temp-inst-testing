/*
 * granite_ext_wire.h — pointer-free little-endian module format, ABI 0.1.
 *
 * This format is deliberately not a packed C struct. Records may start at any byte
 * alignment and every multibyte value is little-endian. Use these byte offsets and
 * stores; never cast descriptor bytes to a native struct pointer.
 *
 * ABI 0.x is not frozen: third-party modules must be rebuilt for each ABI minor until
 * GRANITE_WIRE_ABI_MAJOR becomes 1. This header is Apache-2.0.
 */
#ifndef GRANITE_EXT_WIRE_H
#define GRANITE_EXT_WIRE_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if CHAR_BIT != 8 || UINT16_MAX != 0xffffu || UINT32_MAX != 0xffffffffu || \
    UINT64_MAX != UINT64_C(0xffffffffffffffff)
# error "granite wire ABI requires 8-bit bytes and exact-width integers"
#endif

#define GRANITE_WIRE_ABI_MAJOR 0u
#define GRANITE_WIRE_ABI_MINOR 1u
#define GRANITE_WIRE_ENDIAN_LITTLE 1u
#define GRANITE_WIRE_HEADER_SIZE 64u
#define GRANITE_WIRE_PROVIDER_SIZE 64u
#define GRANITE_WIRE_REGISTRATION_SIZE 80u
#define GRANITE_WIRE_MAX_MODULE_BYTES 16777216u
#define GRANITE_WIRE_MAX_RECORDS 65536u

#define GRANITE_WIRE_FLAG_SIGNED 0x01u
#define GRANITE_WIRE_FLAG_USERSPACE_ONLY 0x02u
#define GRANITE_WIRE_FLAG_KNOWN 0x03u
#define GRANITE_WIRE_FLAG_REQUIRED_MASK 0xf0u

#define GRANITE_WIRE_H_MAGIC 0u
#define GRANITE_WIRE_H_HEADER_SIZE 8u
#define GRANITE_WIRE_H_ABI_MAJOR 10u
#define GRANITE_WIRE_H_ABI_MINOR 12u
#define GRANITE_WIRE_H_ENDIAN 14u
#define GRANITE_WIRE_H_FLAGS 15u
#define GRANITE_WIRE_H_TOTAL_SIZE 16u
#define GRANITE_WIRE_H_PROVIDERS_OFFSET 20u
#define GRANITE_WIRE_H_PROVIDERS_COUNT 24u
#define GRANITE_WIRE_H_REGISTRATIONS_OFFSET 28u
#define GRANITE_WIRE_H_REGISTRATIONS_COUNT 32u
#define GRANITE_WIRE_H_DATA_OFFSET 36u
#define GRANITE_WIRE_H_DATA_LENGTH 40u
#define GRANITE_WIRE_H_SIGNATURE_OFFSET 44u
#define GRANITE_WIRE_H_SIGNATURE_LENGTH 48u
#define GRANITE_WIRE_H_PROVIDER_STRIDE 52u
#define GRANITE_WIRE_H_REGISTRATION_STRIDE 54u
#define GRANITE_WIRE_H_RESERVED 56u

#define GRANITE_WIRE_P_RECORD_SIZE 0u
#define GRANITE_WIRE_P_KIND 2u
#define GRANITE_WIRE_P_FLAGS 4u
#define GRANITE_WIRE_P_ID 8u
#define GRANITE_WIRE_P_NAME 16u
#define GRANITE_WIRE_P_IOKIT_CLASS 24u
#define GRANITE_WIRE_P_CAPABILITIES 32u
#define GRANITE_WIRE_P_FIRST_REGISTRATION 40u
#define GRANITE_WIRE_P_REGISTRATION_COUNT 44u
#define GRANITE_WIRE_P_MIN_OS_MAJOR 48u
#define GRANITE_WIRE_P_MAX_OS_MAJOR 50u
#define GRANITE_WIRE_P_RESERVED 52u

#define GRANITE_WIRE_R_RECORD_SIZE 0u
#define GRANITE_WIRE_R_PATCH_KIND 2u
#define GRANITE_WIRE_R_STAGE 4u
#define GRANITE_WIRE_R_CONFLICT 5u
#define GRANITE_WIRE_R_RESERVED_A 6u
#define GRANITE_WIRE_R_MODE 8u
#define GRANITE_WIRE_R_PRIORITY 12u
#define GRANITE_WIRE_R_REGISTRATION_INDEX 16u
#define GRANITE_WIRE_R_DOMAIN 20u
#define GRANITE_WIRE_R_PERSONALITY 22u
#define GRANITE_WIRE_R_OPERATION 24u
#define GRANITE_WIRE_R_VARIANT 28u
#define GRANITE_WIRE_R_CATALOG 32u
#define GRANITE_WIRE_R_SCOPE 36u
#define GRANITE_WIRE_R_SELECTOR 44u
#define GRANITE_WIRE_R_REPLACEMENT_ID 52u
#define GRANITE_WIRE_R_FLAGS 60u
#define GRANITE_WIRE_R_RESERVED_TAIL 68u

/* A caller-owned output buffer. `data` must designate `capacity` writable bytes. */
typedef struct granite_wire_mut {
    uint8_t *data;
    size_t capacity;
} granite_wire_mut;

static inline granite_wire_mut granite_wire_buffer(void *data, size_t capacity) {
    granite_wire_mut out = {(uint8_t *)data, capacity};
    return out;
}

static inline bool granite_wire_span(granite_wire_mut out, uint32_t offset,
    size_t width, uint8_t **span) {
    size_t start = (size_t)offset;
    if (span == NULL) return false;
    *span = NULL;
    if (out.data == NULL || start > out.capacity || width > out.capacity - start)
        return false;
    *span = out.data + start;
    return true;
}

static inline bool granite_wire_put_u16(granite_wire_mut out, uint32_t offset,
    uint16_t value) {
    uint8_t *at;
    if (!granite_wire_span(out, offset, 2, &at)) return false;
    at[0] = (uint8_t)value;
    at[1] = (uint8_t)(value >> 8);
    return true;
}
static inline bool granite_wire_put_u32(granite_wire_mut out, uint32_t offset,
    uint32_t value) {
    uint8_t *at;
    if (!granite_wire_span(out, offset, 4, &at)) return false;
    at[0] = (uint8_t)value;
    at[1] = (uint8_t)(value >> 8);
    at[2] = (uint8_t)(value >> 16);
    at[3] = (uint8_t)(value >> 24);
    return true;
}
static inline bool granite_wire_put_i32(granite_wire_mut out, uint32_t offset,
    int32_t value) {
    return granite_wire_put_u32(out, offset, (uint32_t)value);
}
static inline bool granite_wire_put_u64(granite_wire_mut out, uint32_t offset,
    uint64_t value) {
    uint8_t *at;
    if (!granite_wire_span(out, offset, 8, &at)) return false;
    at[0] = (uint8_t)value;
    at[1] = (uint8_t)(value >> 8);
    at[2] = (uint8_t)(value >> 16);
    at[3] = (uint8_t)(value >> 24);
    at[4] = (uint8_t)(value >> 32);
    at[5] = (uint8_t)(value >> 40);
    at[6] = (uint8_t)(value >> 48);
    at[7] = (uint8_t)(value >> 56);
    return true;
}
static inline bool granite_wire_put_ref(granite_wire_mut out, uint32_t offset,
    uint32_t target, uint32_t length) {
    uint8_t *at;
    if (!granite_wire_span(out, offset, 8, &at)) return false;
    at[0] = (uint8_t)target;
    at[1] = (uint8_t)(target >> 8);
    at[2] = (uint8_t)(target >> 16);
    at[3] = (uint8_t)(target >> 24);
    at[4] = (uint8_t)length;
    at[5] = (uint8_t)(length >> 8);
    at[6] = (uint8_t)(length >> 16);
    at[7] = (uint8_t)(length >> 24);
    return true;
}

static inline bool granite_wire_init_header(granite_wire_mut out) {
    static const uint8_t magic[8] = {'G','R','A','N','E','X','T',0};
    uint8_t *header;
    if (!granite_wire_span(out, 0, GRANITE_WIRE_HEADER_SIZE, &header)) return false;
    memset(header, 0, GRANITE_WIRE_HEADER_SIZE);
    memcpy(header + GRANITE_WIRE_H_MAGIC, magic, sizeof(magic));
    header[GRANITE_WIRE_H_ENDIAN] = GRANITE_WIRE_ENDIAN_LITTLE;
    return granite_wire_put_u16(out, GRANITE_WIRE_H_HEADER_SIZE,
               GRANITE_WIRE_HEADER_SIZE) &&
        granite_wire_put_u16(out, GRANITE_WIRE_H_ABI_MAJOR,
               GRANITE_WIRE_ABI_MAJOR) &&
        granite_wire_put_u16(out, GRANITE_WIRE_H_ABI_MINOR,
               GRANITE_WIRE_ABI_MINOR) &&
        granite_wire_put_u16(out, GRANITE_WIRE_H_PROVIDER_STRIDE,
               GRANITE_WIRE_PROVIDER_SIZE) &&
        granite_wire_put_u16(out, GRANITE_WIRE_H_REGISTRATION_STRIDE,
               GRANITE_WIRE_REGISTRATION_SIZE);
}
static inline bool granite_wire_init_provider(granite_wire_mut out,
    uint32_t offset) {
    uint8_t *record;
    if (!granite_wire_span(out, offset, GRANITE_WIRE_PROVIDER_SIZE, &record))
        return false;
    memset(record, 0, GRANITE_WIRE_PROVIDER_SIZE);
    return granite_wire_put_u16(out, offset, GRANITE_WIRE_PROVIDER_SIZE);
}
static inline bool granite_wire_init_registration(granite_wire_mut out,
    uint32_t offset) {
    uint8_t *record;
    if (!granite_wire_span(out, offset, GRANITE_WIRE_REGISTRATION_SIZE, &record))
        return false;
    memset(record, 0, GRANITE_WIRE_REGISTRATION_SIZE);
    return granite_wire_put_u16(out, offset, GRANITE_WIRE_REGISTRATION_SIZE);
}

/*
 * A signed descriptor keeps SIGNED, signature offset and signature length in the
 * header. Signing/verifying covers total_size bytes while treating every byte in the
 * signature span as zero. This removes circularity without changing the descriptor's
 * layout. The signature envelope's algorithm and trust chain are loader policy.
 */

#endif /* GRANITE_EXT_WIRE_H */
