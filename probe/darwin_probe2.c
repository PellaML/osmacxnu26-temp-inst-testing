// darwin_probe2.c — second-round measurement harness.
//
// darwin_probe.c measured the commpage and the hw.* sysctls. This one measures
// four things it could not:
//
//   1. apple[] — the fourth argv-family argument the kernel hands every process.
//      It carries the per-boot randomized commpage text-page address, the pointer
//      munge seed, the main stack address, and the dyld/executable paths. Nothing
//      else exposes these, and a Darwin that gets apple[] wrong breaks dyld.
//   2. The real virtual-memory layout of the commpage: how many pages, what
//      protections, where the boundaries are. Read with vm_region_recurse_64,
//      which reports what the kernel actually mapped rather than what a header says.
//   3. Which IOKit services exist. Whether Apple's own virtual machine has a
//      Secure Enclave decides what a virtualized Darwin can do about hardware DRM,
//      biometrics and keychain rooting — and that is a fact, not an opinion.
//   4. The dyld shared cache range and UUID, via public dyld API.
//
// Reads only what any process can read about itself. Ships no Apple code.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOBSD.h>
#include <dlfcn.h>

// dyld_priv.h is in the SDK but not a stable public header; declare what we use.
extern const void *_dyld_get_shared_cache_range(size_t *length);
extern bool _dyld_get_shared_cache_uuid(uuid_t uuid);

#define COMMPAGE_BASE 0x0000000FFFFFC000ULL

// ---------------------------------------------------------------------------
// 1. apple[]
// ---------------------------------------------------------------------------

static void dump_apple(char **apple) {
    printf("\n===== 1. apple[] =====\n");
    if (!apple) { printf("  <null>\n"); return; }
    for (int i = 0; apple[i]; i++) {
        printf("  apple[%2d] = %s\n", i, apple[i]);
    }
    printf("  (terminated)\n");
}

// ---------------------------------------------------------------------------
// 2. Commpage VM layout
// ---------------------------------------------------------------------------

static const char *prot_str(vm_prot_t p, char *buf) {
    buf[0] = (p & VM_PROT_READ)    ? 'r' : '-';
    buf[1] = (p & VM_PROT_WRITE)   ? 'w' : '-';
    buf[2] = (p & VM_PROT_EXECUTE) ? 'x' : '-';
    buf[3] = 0;
    return buf;
}

static void dump_vm_layout(void) {
    printf("\n===== 2. COMMPAGE VM LAYOUT =====\n");
    printf("  page size: %d\n", getpagesize());

    // Walk from a little below the commpage base to well past it, so the
    // separate read-only and text pages show up wherever they landed.
    mach_vm_address_t addr = COMMPAGE_BASE - 0x10000;
    for (int i = 0; i < 24; i++) {
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        natural_t depth = 0;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &addr, &size,
                                                  &depth, (vm_region_recurse_info_t)&info,
                                                  &count);
        if (kr != KERN_SUCCESS) { printf("  (end of map at 0x%llx: %d)\n", addr, kr); break; }
        char cur[4], max[4];
        printf("  0x%016llx - 0x%016llx  %6llu KB  cur=%s max=%s  tag=%u depth=%u%s\n",
               (unsigned long long)addr, (unsigned long long)(addr + size),
               (unsigned long long)(size / 1024),
               prot_str(info.protection, cur), prot_str(info.max_protection, max),
               info.user_tag, depth,
               (addr <= COMMPAGE_BASE && COMMPAGE_BASE < addr + size) ? "   <== commpage data" : "");
        addr += size;
        if (addr > COMMPAGE_BASE + 0x100000) break;
    }
}

// Try to locate the commpage TEXT page, whose address is randomized per boot and
// delivered in apple[]. Confirm it is executable and read its two routines.
static void dump_commpage_text(char **apple) {
    printf("\n===== 3. COMMPAGE TEXT PAGE (randomized per boot) =====\n");
    unsigned long long va = 0;
    for (int i = 0; apple && apple[i]; i++) {
        const char *k = "cpu_capabilities64=";           // not it, but keep scanning
        (void)k;
        if (strncmp(apple[i], "com.apple.commpage.text=", 24) == 0) {
            va = strtoull(apple[i] + 24, NULL, 0);
        }
    }
    if (!va) {
        printf("  no explicit apple[] key matched; scanning for a hex-looking value\n");
        for (int i = 0; apple && apple[i]; i++) {
            const char *eq = strchr(apple[i], '=');
            if (!eq) continue;
            if (strncmp(eq + 1, "0x", 2) != 0) continue;
            unsigned long long v = strtoull(eq + 1, NULL, 16);
            if (v > 0x0000000F00000000ULL && v < 0x0000001000000000ULL) {
                printf("  candidate from %.*s : 0x%llx\n", (int)(eq - apple[i]), apple[i], v);
                if (!va) va = v;
            }
        }
    }
    if (!va) { printf("  not found in apple[]\n"); return; }

    printf("  text page VA = 0x%llx\n", va);
    mach_vm_address_t a = (mach_vm_address_t)va;
    mach_vm_size_t size = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    natural_t depth = 0;
    if (mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                               (vm_region_recurse_info_t)&info, &count) == KERN_SUCCESS) {
        char cur[4], max[4];
        printf("  region 0x%llx + %llu, cur=%s max=%s\n", (unsigned long long)a,
               (unsigned long long)size, prot_str(info.protection, cur),
               prot_str(info.max_protection, max));
    }
    const uint32_t *insn = (const uint32_t *)(uintptr_t)va;
    printf("  +0x0 (ATOMIC_ENQUEUE) = 0x%08x\n", insn[0]);
    printf("  +0x4 (ATOMIC_DEQUEUE) = 0x%08x\n", insn[1]);
    printf("  first 8 words:");
    for (int i = 0; i < 8; i++) printf(" %08x", insn[i]);
    printf("\n");
}

// ---------------------------------------------------------------------------
// 4. IOKit service presence
// ---------------------------------------------------------------------------

static void probe_iokit(void) {
    printf("\n===== 4. IOKIT SERVICES =====\n");
    printf("(does Apple's own VM have the hardware a DRM / biometric / keychain\n"
           " root-of-trust story depends on?)\n\n");
    const char *classes[] = {
        // Secure Enclave and friends
        "AppleSEPManager", "AppleSEPKeyStore", "AppleKeyStore", "AppleSEPCredentialManager",
        "AppleMesaSEPDriver", "AppleSEPPKA",
        // Content protection
        "AppleFairPlayIOKitUserClient", "IOFairPlayIOKitUserClient",
        "AppleFairPlaySEPDriver", "IOHDCPMessageDriver",
        // Media / GPU
        "AppleParavirtGPU", "IOGPU", "AGXAcceleratorG13X", "AppleAVD", "AppleH13CameraInterface",
        "IOSurfaceRoot", "IOMobileFramebuffer",
        // Platform
        "AppleARMPE", "IOPlatformExpertDevice", "AppleARMPlatformExpert",
        "AppleT8103PMGR", "AppleEmbeddedNVMeController",
        // Virtualization
        "AppleVirtIO", "AppleParavirtDevice", "AppleVirtualPlatformExpert",
        // Entropy / trust
        "AppleEffaceableStorage", "AppleImage4", "AppleCredentialManager",
    };
    for (size_t i = 0; i < sizeof classes / sizeof classes[0]; i++) {
        CFMutableDictionaryRef m = IOServiceMatching(classes[i]);
        if (!m) { printf("  %-32s <no matching dict>\n", classes[i]); continue; }
        io_iterator_t it = IO_OBJECT_NULL;
        kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, m, &it);
        int n = 0;
        if (kr == KERN_SUCCESS) {
            io_object_t o;
            while ((o = IOIteratorNext(it))) { n++; IOObjectRelease(o); }
            IOObjectRelease(it);
        }
        printf("  %-32s %s\n", classes[i], n ? "PRESENT" : "absent");
    }

    // The primary built-in NIC MAC, which is the App Store receipt GUID (R818).
    printf("\n  -- IOMACAddress on the primary built-in interface (receipt GUID) --\n");
    static const char *ifaces[] = {"en0", "en1"};
    for (size_t i = 0; i < sizeof ifaces / sizeof ifaces[0]; i++) {
        const char *bsd = ifaces[i];
        CFMutableDictionaryRef m = IOBSDNameMatching(kIOMainPortDefault, 0, bsd);
        if (!m) continue;
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
        if (!svc) { printf("  %-4s absent\n", bsd); continue; }
        io_registry_entry_t parent = IO_OBJECT_NULL;
        if (IORegistryEntryGetParentEntry(svc, kIOServicePlane, &parent) == KERN_SUCCESS) {
            CFDataRef d = (CFDataRef)IORegistryEntryCreateCFProperty(parent, CFSTR("IOMACAddress"),
                                                                     kCFAllocatorDefault, 0);
            if (d) {
                const UInt8 *b = CFDataGetBytePtr(d);
                printf("  %-4s IOMACAddress = %02x:%02x:%02x:%02x:%02x:%02x  (len %ld)\n",
                       bsd, b[0], b[1], b[2], b[3], b[4], b[5], (long)CFDataGetLength(d));
                CFRelease(d);
            } else {
                printf("  %-4s present, no IOMACAddress property\n", bsd);
            }
            IOObjectRelease(parent);
        }
        IOObjectRelease(svc);
    }
}

// ---------------------------------------------------------------------------
// 5. dyld shared cache
// ---------------------------------------------------------------------------

static void probe_shared_cache(void) {
    printf("\n===== 5. DYLD SHARED CACHE =====\n");
    size_t len = 0;
    const void *base = _dyld_get_shared_cache_range(&len);
    if (!base) { printf("  no shared cache in this process\n"); return; }
    printf("  range: %p .. %p  (%zu bytes, %.2f GB)\n", base, (const char *)base + len, len,
           (double)len / (1024.0 * 1024.0 * 1024.0));

    uuid_t u;
    if (_dyld_get_shared_cache_uuid(u)) {
        printf("  uuid : ");
        for (int i = 0; i < 16; i++) printf("%02x%s", u[i], (i==3||i==5||i==7||i==9) ? "-" : "");
        printf("\n");
    }
    printf("  image count (this process): %u\n", _dyld_image_count());
}

// ---------------------------------------------------------------------------
// 6. A few sysctls the first probe did not read
// ---------------------------------------------------------------------------

static void sysctl_show(const char *name) {
    char buf[512];
    size_t len = sizeof buf;
    if (sysctlbyname(name, buf, &len, NULL, 0) != 0) { printf("  %-34s <error>\n", name); return; }
    if (len <= 8) {
        uint64_t v = 0; memcpy(&v, buf, len);
        printf("  %-34s = %llu (0x%llx)  [%zu bytes]\n", name, v, v, len);
    } else {
        buf[len < sizeof buf ? len : sizeof buf - 1] = 0;
        printf("  %-34s = \"%s\"  [%zu bytes]\n", name, buf, len);
    }
}

static void probe_more_sysctls(void) {
    printf("\n===== 6. TRUST / SECURITY SYSCTLS =====\n");
    const char *names[] = {
        "kern.bootargs", "kern.securelevel", "kern.osvariant_status",
        "kern.development", "kern.osreleasetype",
        "security.mac.amfi.trust_level", "security.mac.amfi.developer_mode_status",
        "security.mac.sandbox.sentinel",
        "hw.features.allows_security_research",
        "kern.hv_support", "kern.hv_vmm_present",
        "kern.ipc_portbt", "kern.num_taskthreads",
        "vm.pagesize", "vm.compressor_mode",
        "machdep.virtual_address_size",
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) sysctl_show(names[i]);
}

int main(int argc, char **argv, char **envp, char **apple) {
    (void)argc; (void)argv; (void)envp;
    printf("Darwin userspace probe, round 2\n");
    printf("===============================\n");
    sysctl_show("kern.osproductversion");
    sysctl_show("kern.version");

    dump_apple(apple);
    dump_vm_layout();
    dump_commpage_text(apple);
    probe_iokit();
    probe_shared_cache();
    probe_more_sysctls();

    printf("\ndone.\n");
    return 0;
}
