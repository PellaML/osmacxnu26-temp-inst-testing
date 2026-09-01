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

// Descend through nested submaps to the entry that actually describes pages.
// At depth 0 the commpage reports as a 1 GB region with `---` protections: that
// is the submap's own entry and says nothing about what is inside it.
static kern_return_t region_at(mach_vm_address_t *addr, mach_vm_size_t *size,
                               vm_region_submap_info_data_64_t *info, natural_t *out_depth) {
    natural_t depth = 0;
    kern_return_t kr;
    for (;;) {
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = mach_vm_region_recurse(mach_task_self(), addr, size, &depth,
                                    (vm_region_recurse_info_t)info, &count);
        if (kr != KERN_SUCCESS) break;
        if (!info->is_submap || depth > 8) break;
        depth++;
    }
    *out_depth = depth;
    return kr;
}

static void dump_vm_layout(void) {
    printf("\n===== 2. COMMPAGE VM LAYOUT =====\n");
    printf("  page size: %d\n", getpagesize());

    mach_vm_address_t addr = COMMPAGE_BASE - 0x100000;
    for (int i = 0; i < 32; i++) {
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info;
        natural_t depth = 0;
        kern_return_t kr = region_at(&addr, &size, &info, &depth);
        if (kr != KERN_SUCCESS) { printf("  (end of map at 0x%llx: %d)\n", addr, kr); break; }
        char cur[4], max[4];
        printf("  0x%016llx - 0x%016llx  %8llu KB  cur=%s max=%s  tag=%2u depth=%u sub=%d%s\n",
               (unsigned long long)addr, (unsigned long long)(addr + size),
               (unsigned long long)(size / 1024),
               prot_str(info.protection, cur), prot_str(info.max_protection, max),
               info.user_tag, depth, (int)info.is_submap,
               (addr <= COMMPAGE_BASE && COMMPAGE_BASE < addr + size) ? "   <== commpage data" : "");
        addr += size;
        if (addr > COMMPAGE_BASE + 0x100000) break;
    }
}

// The commpage TEXT page (the PFZ, preemption-free zone). Its user VA is
// randomized per boot and handed to the process as apple[1] = "pfz=0x...".
// libplatform's __pfz_setup() reads it before main() and does
// bzero(p - 4, strlen(p) + 4) -- backing up exactly strlen("pfz=") so the key
// goes too. It is therefore always empty by the time we can look. kern.pfz is
// the authoritative read; it is CTLFLAG_MASKED so `sysctl -a` never lists it,
// but sysctlbyname works.
static void dump_commpage_text(char **apple) {
    printf("\n===== 3. COMMPAGE TEXT PAGE / PFZ (randomized per boot) =====\n");

    for (int i = 0; apple && apple[i]; i++) {
        if (strncmp(apple[i], "pfz", 3) == 0) {
            printf("  apple[%d] still carries a pfz key: \"%s\"\n", i, apple[i]);
        }
    }
    printf("  apple[1] = \"%s\"  (empty => libplatform scrubbed it, as expected)\n",
           (apple && apple[0] && apple[1]) ? apple[1] : "<none>");

    uint64_t pfz = 0;
    size_t len = sizeof pfz;
    if (sysctlbyname("kern.pfz", &pfz, &len, NULL, 0) != 0) {
        printf("  kern.pfz -> <error>\n");
        return;
    }
    printf("  kern.pfz = 0x%llx   [%zu bytes returned]\n", (unsigned long long)pfz, len);
    if (!pfz) { printf("  (zero: no PFZ mapped)\n"); return; }
    printf("  commpage data base - pfz = 0x%llx\n",
           (unsigned long long)(COMMPAGE_BASE - pfz));

    mach_vm_address_t a = (mach_vm_address_t)pfz;
    mach_vm_size_t size = 0;
    vm_region_submap_info_data_64_t info;
    natural_t depth = 0;
    if (region_at(&a, &size, &info, &depth) == KERN_SUCCESS) {
        char cur[4], max[4];
        printf("  region 0x%llx + %llu  cur=%s max=%s depth=%u\n",
               (unsigned long long)a, (unsigned long long)size,
               prot_str(info.protection, cur), prot_str(info.max_protection, max), depth);
    }

    const uint32_t *insn = (const uint32_t *)(uintptr_t)pfz;
    printf("  +0x0 (ATOMIC_ENQUEUE) = 0x%08x\n", insn[0]);
    printf("  +0x4 (ATOMIC_DEQUEUE) = 0x%08x\n", insn[1]);
    printf("  first 16 words:");
    for (int i = 0; i < 16; i++) printf(" %08x", insn[i]);
    printf("\n");
    // XNU pads the rest of the page with BRK_666_OPCODE; find where code stops.
    int words = getpagesize() / 4;
    uint32_t filler = insn[words - 1];
    int last = 0;
    for (int i = 0; i < words; i++) if (insn[i] != filler) last = i;
    printf("  filler word = 0x%08x, last non-filler index %d => %d bytes of code\n",
           filler, last, (last + 1) * 4);
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
    int printable = len > 1 && buf[len - 1] == 0;
    for (size_t i = 0; printable && i + 1 < len; i++) {
        if (buf[i] < 32 || buf[i] > 126) printable = 0;
    }
    if (!printable && len <= 8) {
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
        "kern.pfz", "kern.slide", "kern.bootsessionuuid", "kern.osbuildconfig",
        "kern.dyld_system_order", "vm.shared_region_pager_count",
        "sysctl.proc_native", "sysctl.proc_translated",
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
