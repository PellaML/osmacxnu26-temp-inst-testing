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

static inline void granite_wire_put_u16(uint8_t *at, uint16_t value) {
    at[0] = (uint8_t)value;
    at[1] = (uint8_t)(value >> 8);
}
static inline void granite_wire_put_u32(uint8_t *at, uint32_t value) {
    at[0] = (uint8_t)value;
    at[1] = (uint8_t)(value >> 8);
    at[2] = (uint8_t)(value >> 16);
    at[3] = (uint8_t)(value >> 24);
}
static inline void granite_wire_put_i32(uint8_t *at, int32_t value) {
    granite_wire_put_u32(at, (uint32_t)value);
}
static inline void granite_wire_put_u64(uint8_t *at, uint64_t value) {
    granite_wire_put_u32(at, (uint32_t)value);
    granite_wire_put_u32(at + 4, (uint32_t)(value >> 32));
}
static inline void granite_wire_put_ref(uint8_t *at, uint32_t offset,
    uint32_t length) {
    granite_wire_put_u32(at, offset);
    granite_wire_put_u32(at + 4, length);
}

static inline void granite_wire_init_header(uint8_t out[GRANITE_WIRE_HEADER_SIZE]) {
    static const uint8_t magic[8] = {'G','R','A','N','E','X','T',0};
    memset(out, 0, GRANITE_WIRE_HEADER_SIZE);
    memcpy(out + GRANITE_WIRE_H_MAGIC, magic, sizeof(magic));
    granite_wire_put_u16(out + GRANITE_WIRE_H_HEADER_SIZE, GRANITE_WIRE_HEADER_SIZE);
    granite_wire_put_u16(out + GRANITE_WIRE_H_ABI_MAJOR, GRANITE_WIRE_ABI_MAJOR);
    granite_wire_put_u16(out + GRANITE_WIRE_H_ABI_MINOR, GRANITE_WIRE_ABI_MINOR);
    out[GRANITE_WIRE_H_ENDIAN] = GRANITE_WIRE_ENDIAN_LITTLE;
    granite_wire_put_u16(out + GRANITE_WIRE_H_PROVIDER_STRIDE,
        GRANITE_WIRE_PROVIDER_SIZE);
    granite_wire_put_u16(out + GRANITE_WIRE_H_REGISTRATION_STRIDE,
        GRANITE_WIRE_REGISTRATION_SIZE);
}
static inline void granite_wire_init_provider(
    uint8_t out[GRANITE_WIRE_PROVIDER_SIZE]) {
    memset(out, 0, GRANITE_WIRE_PROVIDER_SIZE);
    granite_wire_put_u16(out + GRANITE_WIRE_P_RECORD_SIZE,
        GRANITE_WIRE_PROVIDER_SIZE);
}
static inline void granite_wire_init_registration(
    uint8_t out[GRANITE_WIRE_REGISTRATION_SIZE]) {
    memset(out, 0, GRANITE_WIRE_REGISTRATION_SIZE);
    granite_wire_put_u16(out + GRANITE_WIRE_R_RECORD_SIZE,
        GRANITE_WIRE_REGISTRATION_SIZE);
}

/*
 * A signed descriptor keeps SIGNED, signature offset and signature length in the
 * header. Signing/verifying covers total_size bytes while treating every byte in the
 * signature span as zero. This removes circularity without changing the descriptor's
 * layout. The signature envelope's algorithm and trust chain are loader policy.
 */

#endif /* GRANITE_EXT_WIRE_H */
