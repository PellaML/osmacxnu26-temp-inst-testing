// security_probe.c — code-trust, sandbox, SIP, and executable-memory baseline.
// Our code; it does not request credentials or weaken a machine setting.

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#ifndef MAP_JIT
#define MAP_JIT 0x800
#endif
#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif
#ifndef CS_OPS_ENTITLEMENTS_BLOB
#define CS_OPS_ENTITLEMENTS_BLOB 7
#endif

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

typedef int (*sandbox_check_fn)(pid_t, const char *, int, ...);
typedef int (*csr_get_active_config_fn)(uint32_t *);

static void print_sysctl(const char *name) {
    uint8_t value[4096] = {0};
    size_t size = sizeof(value);
    errno = 0;
    int result = sysctlbyname(name, value, &size, NULL, 0);
    printf("  %-40s result=%d errno=%d size=%zu", name, result, errno, size);
    if (result == 0) {
        BOOL printable = size > 0 && value[size - 1] == 0;
        for (size_t i = 0; printable && i + 1 < size; ++i) {
            if (value[i] < 0x20 || value[i] > 0x7e) printable = NO;
        }
        if (printable) printf(" string=\"%s\"", value);
        else {
            printf(" bytes=");
            for (size_t i = 0; i < size && i < 64; ++i) printf("%02x", value[i]);
            if (size > 64) printf("...");
        }
    }
    puts("");
}

static void print_cf(CFTypeRef value) {
    if (value == NULL) { puts("<null>"); return; }
    CFErrorRef error = NULL;
    CFDataRef xml = CFPropertyListCreateData(kCFAllocatorDefault, value,
        kCFPropertyListXMLFormat_v1_0, 0, &error);
    if (xml != NULL) {
        fwrite(CFDataGetBytePtr(xml), 1, (size_t)CFDataGetLength(xml), stdout);
        CFRelease(xml);
        return;
    }
    CFStringRef text = CFCopyDescription(value);
    if (text != NULL) {
        CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(text),
            kCFStringEncodingUTF8) + 1;
        char *bytes = calloc(1, (size_t)max);
        if (bytes != NULL && CFStringGetCString(text, bytes, max, kCFStringEncodingUTF8))
            printf("%s\n", bytes);
        free(bytes);
        CFRelease(text);
    }
    if (error != NULL) CFRelease(error);
}

static void probe_signature(void) {
    puts("\n===== SELF CODE SIGNATURE =====");
    uint32_t flags = 0;
    errno = 0;
    int result = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    printf("  csops(status): result=%d errno=%d flags=0x%08x\n", result, errno, flags);

    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    printf("  SecCodeCopySelf=%d\n", (int)status);
    if (code == NULL) return;
    SecCSFlags validations[] = {
        kSecCSDefaultFlags,
        kSecCSStrictValidate,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures,
    };
    for (size_t i = 0; i < sizeof(validations) / sizeof(validations[0]); ++i) {
        CFErrorRef error = NULL;
        status = SecCodeCheckValidityWithErrors(code, validations[i], NULL, &error);
        printf("  validity flags=0x%x status=%d error=", validations[i], (int)status);
        if (error != NULL) { print_cf(error); CFRelease(error); }
        else puts("<none>");
    }

    CFDictionaryRef info = NULL;
    status = SecCodeCopySigningInformation(code,
        kSecCSSigningInformation | kSecCSRequirementInformation, &info);
    printf("  signing-information status=%d\n", (int)status);
    if (info != NULL) { print_cf(info); CFRelease(info); }

    SecRequirementRef requirement = NULL;
    status = SecCodeCopyDesignatedRequirement(code, kSecCSDefaultFlags, &requirement);
    printf("  designated-requirement status=%d\n", (int)status);
    if (requirement != NULL) {
        CFStringRef text = NULL;
        if (SecRequirementCopyString(requirement, kSecCSDefaultFlags, &text) == errSecSuccess) {
            print_cf(text);
            CFRelease(text);
        }
        CFRelease(requirement);
    }
    CFRelease(code);
}

static void region_info(void *pointer) {
    mach_vm_address_t address = (mach_vm_address_t)(uintptr_t)pointer;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &address, &size,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    printf("    region kr=0x%x start=0x%llx size=0x%llx prot=%d max=%d shared=%d\n",
        (unsigned)kr, (unsigned long long)address, (unsigned long long)size,
        (int)info.protection, (int)info.max_protection, (int)info.shared);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
}

static BOOL put_return_42(void *memory) {
#if defined(__x86_64__)
    const uint8_t code[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};
#elif defined(__aarch64__)
    const uint32_t code[] = {0x52800540u, 0xd65f03c0u};
#else
    return NO;
#endif
    memcpy(memory, code, sizeof(code));
    sys_icache_invalidate(memory, sizeof(code));
    return YES;
}

static int call_generated(void *memory) {
    int (*function)(void) = NULL;
    _Static_assert(sizeof(function) == sizeof(memory), "function pointer size");
    memcpy(&function, &memory, sizeof(function));
    return function();
}

static void probe_mapping(const char *name, int initial_protection, int flags,
    BOOL toggle_jit) {
    size_t page = (size_t)getpagesize();
    errno = 0;
    void *memory = mmap(NULL, page, initial_protection, flags, -1, 0);
    printf("  %s: mmap=%p errno=%d\n", name, memory, errno);
    if (memory == MAP_FAILED) return;
    region_info(memory);

    if (toggle_jit) pthread_jit_write_protect_np(0);
    BOOL wrote = put_return_42(memory);
    if (toggle_jit) pthread_jit_write_protect_np(1);

    int protect_result = 0;
    int protect_errno = 0;
    if ((initial_protection & PROT_EXEC) == 0) {
        errno = 0;
        protect_result = mprotect(memory, page, PROT_READ | PROT_EXEC);
        protect_errno = errno;
    }
    printf("    wrote=%d mprotect_rx=%d errno=%d\n", wrote, protect_result, protect_errno);
    region_info(memory);
    if (wrote && protect_result == 0) printf("    execution-return=%d\n", call_generated(memory));
    munmap(memory, page);
}

static void probe_executable_memory(void) {
    puts("\n===== EXECUTABLE MEMORY =====");
    int jit_supported = pthread_jit_write_protect_supported_np();
    printf("  pthread_jit_write_protect_supported_np=%d\n", jit_supported);
    probe_mapping("anonymous-rw-then-rx", PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, NO);
    probe_mapping("anonymous-rwx", PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANON, NO);
    probe_mapping("map-jit", PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANON | MAP_JIT, jit_supported != 0);
}

static void probe_sandbox_and_sip(void) {
    puts("\n===== SANDBOX / SIP =====");
    void *sandbox_symbol = dlsym(RTLD_DEFAULT, "sandbox_check");
    sandbox_check_fn sandbox_check = NULL;
    _Static_assert(sizeof(sandbox_check) == sizeof(sandbox_symbol), "dlsym pointer size");
    memcpy(&sandbox_check, &sandbox_symbol, sizeof(sandbox_check));
    printf("  sandbox_check symbol=%s\n", sandbox_check != NULL ? "present" : "absent");
    if (sandbox_check != NULL) {
        const char *paths[] = {"/", "/etc/hosts", "/Library/Apple/System/Library", getenv("HOME")};
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
            if (paths[i] == NULL) continue;
            errno = 0;
            int result = sandbox_check(getpid(), "file-read-data", 1, paths[i]);
            printf("  sandbox file-read-data %-36s result=%d errno=%d\n",
                paths[i], result, errno);
        }
    }
    void *csr_symbol = dlsym(RTLD_DEFAULT, "csr_get_active_config");
    csr_get_active_config_fn csr = NULL;
    _Static_assert(sizeof(csr) == sizeof(csr_symbol), "dlsym pointer size");
    memcpy(&csr, &csr_symbol, sizeof(csr));
    uint32_t config = 0;
    int result = csr != NULL ? csr(&config) : -1;
    printf("  csr_get_active_config symbol=%s result=%d config=0x%08x\n",
        csr != NULL ? "present" : "absent", result, config);

    const char *databases[] = {
        "/Library/Application Support/com.apple.TCC/TCC.db",
        NULL,
    };
    char user_db[4096];
    const char *home = getenv("HOME");
    if (home != NULL) {
        snprintf(user_db, sizeof(user_db), "%s/Library/Application Support/com.apple.TCC/TCC.db", home);
        databases[1] = user_db;
    }
    for (size_t i = 0; i < sizeof(databases) / sizeof(databases[0]); ++i) {
        if (databases[i] == NULL) continue;
        errno = 0;
        int fd = open(databases[i], O_RDONLY);
        printf("  open TCC database %-70s fd=%d errno=%d\n", databases[i], fd, errno);
        if (fd >= 0) close(fd);
    }
}

int main(void) {
    puts("Darwin security baseline\n========================");
    printf("  pid=%d uid=%d euid=%d gid=%d egid=%d\n", getpid(), getuid(), geteuid(), getgid(), getegid());
    const char *nodes[] = {
        "kern.osproductversion", "kern.osversion", "kern.version",
        "kern.secure_kernel", "kern.development", "kern.hv_vmm_present",
        "security.mac.sandbox.sentinel", "security.mac.amfi.developer_mode_status",
        "security.mac.amfi.bootstrapped", "security.mac.amfi.launch_constraints",
        "vm.cs_validation", "vm.cs_blob_count", "vm.cs_blob_size",
        "sysctl.proc_native", "sysctl.proc_translated",
    };
    for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); ++i) print_sysctl(nodes[i]);
    probe_signature();
    probe_sandbox_and_sip();
    probe_executable_memory();
    return 0;
}
