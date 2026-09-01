// darwin_probe.c — userspace measurement harness for the Darwin compatibility work.
//
// Reads only what any process can read on its own machine: the commpage, a set of
// hw.* sysctls, and two Apple IMPL-DEF system registers that userspace is allowed
// to read. Prints facts; ships no Apple code and copies no Apple data.
//
// The load-bearing experiment is section 3: read SPRR_PERM_EL0 either side of a
// pthread_jit_write_protect_np() flip and match the values against the commpage
// words at +0x110 and +0x118. That identifies which commpage field carries which
// permission state — a thing we have so far only inferred from disassembly.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <pthread.h>
#include <dlfcn.h>

#define COMMPAGE_BASE   0x0000000FFFFFC000ULL

// Offsets from osfmk/arm/cpu_capabilities.h, plus the three recovered ones.
#define OFF_SIGNATURE       0x000
#define OFF_CAPS64          0x010
#define OFF_VERSION         0x01E
#define OFF_CAPS32          0x020
#define OFF_NCPUS           0x022
#define OFF_CACHE_LINESIZE  0x026
#define OFF_CPU_CLUSTERS    0x02F
#define OFF_ACTIVE_CPUS     0x034
#define OFF_PHYSICAL_CPUS   0x035
#define OFF_LOGICAL_CPUS    0x036
#define OFF_MEMORY_SIZE     0x038
#define OFF_CPUFAMILY       0x080
#define OFF_TIMEBASE_OFFSET 0x088
#define OFF_KDEBUG_ENABLE   0x100
#define OFF_ATM_DIAG        0x104
#define OFF_MULTIUSER       0x108
#define OFF_SPRR_SELECTOR   0x10C   // recovered: uint8 + 3 pad
#define OFF_SPRR_PERM_0     0x110   // recovered: uint64
#define OFF_SPRR_PERM_1     0x118   // recovered: uint64
#define OFF_NEWTIMEOFDAY    0x120

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_faulted;

static void fault_handler(int sig) {
    (void)sig;
    g_faulted = 1;
    siglongjmp(g_jmp, 1);
}

#define TRY(body, onfault)                        \
    do {                                          \
        g_faulted = 0;                            \
        if (sigsetjmp(g_jmp, 1) == 0) { body; }   \
        else { onfault; }                         \
    } while (0)

static void install_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
}

// ---------------------------------------------------------------------------
// 1. Commpage
// ---------------------------------------------------------------------------

static uint8_t  rd8 (uint64_t off) { return *(volatile uint8_t  *)(COMMPAGE_BASE + off); }
static uint16_t rd16(uint64_t off) { return *(volatile uint16_t *)(COMMPAGE_BASE + off); }
static uint32_t rd32(uint64_t off) { return *(volatile uint32_t *)(COMMPAGE_BASE + off); }
static uint64_t rd64(uint64_t off) { return *(volatile uint64_t *)(COMMPAGE_BASE + off); }

static void dump_commpage(void) {
    printf("\n===== 1. COMMPAGE =====\n");
    printf("base = 0x%016llx\n\n", COMMPAGE_BASE);

    TRY({
        uint64_t sig = rd64(OFF_SIGNATURE);
        char s[9]; memcpy(s, &sig, 8); s[8] = 0;
        for (int i = 0; i < 8; i++) if (s[i] && (s[i] < 32 || s[i] > 126)) s[i] = '.';
        printf("+0x%03x SIGNATURE          0x%016llx  \"%s\"\n", OFF_SIGNATURE, sig, s);
    }, printf("+0x%03x SIGNATURE          <fault>\n", OFF_SIGNATURE));

    TRY(printf("+0x%03x CPU_CAPABILITIES64 0x%016llx\n", OFF_CAPS64, rd64(OFF_CAPS64)),
        printf("+0x%03x CPU_CAPABILITIES64 <fault>\n", OFF_CAPS64));
    TRY(printf("+0x%03x VERSION            0x%04x\n", OFF_VERSION, rd16(OFF_VERSION)),
        printf("+0x%03x VERSION            <fault>\n", OFF_VERSION));
    TRY(printf("+0x%03x CPU_CAPABILITIES32 0x%08x\n", OFF_CAPS32, rd32(OFF_CAPS32)),
        printf("+0x%03x CPU_CAPABILITIES32 <fault>\n", OFF_CAPS32));
    TRY(printf("+0x%03x NCPUS              %u\n", OFF_NCPUS, rd8(OFF_NCPUS)), {});
    TRY(printf("+0x%03x CACHE_LINESIZE     %u\n", OFF_CACHE_LINESIZE, rd16(OFF_CACHE_LINESIZE)), {});
    TRY(printf("+0x%03x CPU_CLUSTERS       %u\n", OFF_CPU_CLUSTERS, rd8(OFF_CPU_CLUSTERS)), {});
    TRY(printf("+0x%03x ACTIVE_CPUS        %u\n", OFF_ACTIVE_CPUS, rd8(OFF_ACTIVE_CPUS)), {});
    TRY(printf("+0x%03x PHYSICAL_CPUS      %u\n", OFF_PHYSICAL_CPUS, rd8(OFF_PHYSICAL_CPUS)), {});
    TRY(printf("+0x%03x LOGICAL_CPUS       %u\n", OFF_LOGICAL_CPUS, rd8(OFF_LOGICAL_CPUS)), {});
    TRY(printf("+0x%03x MEMORY_SIZE        0x%016llx\n", OFF_MEMORY_SIZE, rd64(OFF_MEMORY_SIZE)), {});

    printf("\n-- the field the header calls \"used by memcpy() resolver\" --\n");
    TRY(printf("+0x%03x CPUFAMILY          0x%08x\n", OFF_CPUFAMILY, rd32(OFF_CPUFAMILY)),
        printf("+0x%03x CPUFAMILY          <fault>\n", OFF_CPUFAMILY));
    TRY(printf("+0x%03x TIMEBASE_OFFSET    0x%016llx\n", OFF_TIMEBASE_OFFSET, rd64(OFF_TIMEBASE_OFFSET)), {});

    printf("\n-- published, either side of the redacted hole --\n");
    TRY(printf("+0x%03x KDEBUG_ENABLE      0x%08x\n", OFF_KDEBUG_ENABLE, rd32(OFF_KDEBUG_ENABLE)), {});
    TRY(printf("+0x%03x ATM_DIAG_CONFIG    0x%08x\n", OFF_ATM_DIAG, rd32(OFF_ATM_DIAG)), {});
    TRY(printf("+0x%03x MULTIUSER_CONFIG   0x%08x\n", OFF_MULTIUSER, rd32(OFF_MULTIUSER)), {});

    printf("\n-- THE RECOVERED BLOCK (redacted from the public header) --\n");
    TRY(printf("+0x%03x SPRR selector      0x%02x   (1 => alt register encoding)\n",
               OFF_SPRR_SELECTOR, rd8(OFF_SPRR_SELECTOR)),
        printf("+0x%03x SPRR selector      <fault>\n", OFF_SPRR_SELECTOR));
    TRY(printf("+0x%03x SPRR perm word 0   0x%016llx\n", OFF_SPRR_PERM_0, rd64(OFF_SPRR_PERM_0)),
        printf("+0x%03x SPRR perm word 0   <fault>\n", OFF_SPRR_PERM_0));
    TRY(printf("+0x%03x SPRR perm word 1   0x%016llx\n", OFF_SPRR_PERM_1, rd64(OFF_SPRR_PERM_1)),
        printf("+0x%03x SPRR perm word 1   <fault>\n", OFF_SPRR_PERM_1));
    TRY(printf("+0x%03x NEWTIMEOFDAY[0]    0x%016llx  (published; block must end here)\n",
               OFF_NEWTIMEOFDAY, rd64(OFF_NEWTIMEOFDAY)), {});

    printf("\n-- raw hexdump 0x000..0x200 --\n");
    for (uint64_t o = 0; o < 0x200; o += 16) {
        TRY({
            printf("+0x%03llx  ", o);
            for (int i = 0; i < 16; i++) printf("%02x ", rd8(o + i));
            printf("\n");
        }, printf("+0x%03llx  <fault>\n", o));
    }
}

// ---------------------------------------------------------------------------
// 2 & 3. SPRR system registers
// ---------------------------------------------------------------------------

static uint64_t read_sprr_primary(void) {   // S3_6_C15_C1_5
    uint64_t v = 0;
    __asm__ __volatile__("isb sy\n\tmrs %0, S3_6_c15_c1_5" : "=r"(v) :: "memory");
    return v;
}

static uint64_t read_sprr_alt(void) {       // S3_4_C15_C2_7
    uint64_t v = 0;
    __asm__ __volatile__("isb sy\n\tmrs %0, S3_4_c15_c2_7" : "=r"(v) :: "memory");
    return v;
}

static void probe_sprr(void) {
    printf("\n===== 2. SPRR SYSTEM REGISTERS (read from EL0) =====\n");

    uint64_t v;
    TRY({ v = read_sprr_primary();
          printf("S3_6_C15_C1_5 (SPRR_PERM_EL0)     = 0x%016llx\n", v); },
        printf("S3_6_C15_C1_5 (SPRR_PERM_EL0)     = <trapped>\n"));
    TRY({ v = read_sprr_alt();
          printf("S3_4_C15_C2_7 (alt encoding)      = 0x%016llx\n", v); },
        printf("S3_4_C15_C2_7 (alt encoding)      = <trapped>\n"));

    printf("\n===== 3. W^X FLIP: which commpage word is which state? =====\n");

    int (*supported)(void) = (int (*)(void))dlsym(RTLD_DEFAULT,
                                "pthread_jit_write_protect_supported_np");
    if (supported) printf("pthread_jit_write_protect_supported_np() = %d\n", supported());
    else           printf("pthread_jit_write_protect_supported_np   = <not found>\n");

    uint64_t sz = 64 * 1024;
    void *jit = mmap(NULL, (size_t)sz, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (jit == MAP_FAILED) {
        printf("mmap(MAP_JIT) failed — cannot run the flip test\n");
        return;
    }
    printf("MAP_JIT region at %p (%llu bytes)\n\n", jit, sz);

    // Anything assigned inside TRY must be volatile: siglongjmp may clobber
    // non-volatile locals modified after sigsetjmp.
    volatile uint64_t w0 = 0, w1 = 0;
    volatile int have_words = 0;
    TRY({ w0 = rd64(OFF_SPRR_PERM_0); w1 = rd64(OFF_SPRR_PERM_1); have_words = 1; }, {});

    volatile uint64_t before = 0, writable = 0, executable = 0;
    volatile int ok = 1;

    TRY(before = read_sprr_primary(), ok = 0);
    if (!ok) {
        printf("cannot read SPRR from EL0; flip test skipped\n");
        munmap(jit, (size_t)sz);
        return;
    }

    pthread_jit_write_protect_np(0);            // writable
    TRY(writable = read_sprr_primary(), ok = 0);
    *(volatile uint32_t *)jit = 0xd503201f;     // prove it really is writable (nop)

    pthread_jit_write_protect_np(1);            // executable
    TRY(executable = read_sprr_primary(), ok = 0);

    printf("SPRR before any flip   = 0x%016llx\n", (unsigned long long)before);
    printf("SPRR while WRITABLE    = 0x%016llx\n", (unsigned long long)writable);
    printf("SPRR while EXECUTABLE  = 0x%016llx\n", (unsigned long long)executable);

    if (have_words) {
        printf("\ncommpage +0x110        = 0x%016llx  -> %s\n", (unsigned long long)w0,
               w0 == writable ? "WRITABLE state" :
               w0 == executable ? "EXECUTABLE state" : "matches neither");
        printf("commpage +0x118        = 0x%016llx  -> %s\n", (unsigned long long)w1,
               w1 == writable ? "WRITABLE state" :
               w1 == executable ? "EXECUTABLE state" : "matches neither");
    }
    munmap(jit, (size_t)sz);
}

// ---------------------------------------------------------------------------
// 4. Identity and capability sysctls
// ---------------------------------------------------------------------------

static void sysctl_str(const char *name) {
    char buf[256];
    size_t len = sizeof buf;
    if (sysctlbyname(name, buf, &len, NULL, 0) == 0) {
        buf[sizeof buf - 1] = 0;
        printf("  %-28s = \"%s\"   (returned len %zu)\n", name, buf, len);
    } else {
        printf("  %-28s = <error>\n", name);
    }
}

static void sysctl_int(const char *name) {
    uint64_t v = 0;
    size_t len = sizeof v;
    if (sysctlbyname(name, &v, &len, NULL, 0) == 0)
        printf("  %-28s = %llu (0x%llx)   [%zu bytes]\n", name, v, v, len);
    else
        printf("  %-28s = <error>\n", name);
}

static void probe_sysctls(void) {
    printf("\n===== 4. IDENTITY SYSCTLS =====\n");
    sysctl_str("hw.machine");
    sysctl_str("hw.model");
    sysctl_str("hw.target");
    sysctl_str("hw.product");
    sysctl_str("hw.targettype");
    printf("\n");
    sysctl_int("hw.cputype");
    sysctl_int("hw.cpusubtype");
    sysctl_int("hw.cpufamily");
    sysctl_int("hw.cpusubfamily");
    sysctl_int("hw.cpu64bit_capable");
    sysctl_int("hw.vectorunit");
    sysctl_int("hw.ncpu");
    sysctl_int("hw.nperflevels");
    sysctl_int("hw.pagesize");
    sysctl_int("hw.cachelinesize");

    printf("\n===== 5. hw.optional.arm.caps (CAP_BYTE_NB) =====\n");
    size_t need = 0;
    if (sysctlbyname("hw.optional.arm.caps", NULL, &need, NULL, 0) == 0)
        printf("  length probe (oldp=NULL)      -> %zu bytes\n", need);
    else
        printf("  length probe                  -> <error>\n");

    uint8_t buf[128];
    memset(buf, 0xAA, sizeof buf);
    size_t len = sizeof buf;                       // deliberately oversized: R790
    if (sysctlbyname("hw.optional.arm.caps", buf, &len, NULL, 0) == 0) {
        printf("  oversized oldlen (%zu) -> returned len %zu\n", sizeof buf, len);
        printf("  bytes:");
        for (size_t i = 0; i < len && i < 32; i++) printf(" %02x", buf[i]);
        printf("\n");
        if (len < sizeof buf) {
            printf("  first byte past the reported length: 0x%02x %s\n",
                   buf[len], buf[len] == 0xAA ? "(untouched — good)" : "(WRITTEN past len)");
        }
        unsigned __int128 caps = 0;
        for (size_t i = 0; i < len && i < 16; i++)
            caps |= (unsigned __int128)buf[i] << (8 * i);
        printf("  as integer: 0x%016llx%016llx\n",
               (unsigned long long)(caps >> 64), (unsigned long long)caps);
        printf("  AMX version field (bits 37..39) = %u\n",
               (unsigned)((caps >> 37) & 0x7));
    } else {
        printf("  read                          -> <error>\n");
    }

    printf("\n===== 6. per-feature cross-check =====\n");
    const char *feats[] = {
        "hw.optional.AdvSIMD", "hw.optional.armv8_crc32",
        "hw.optional.arm.FEAT_FP16", "hw.optional.arm.FEAT_LSE",
        "hw.optional.arm.FEAT_LSE2", "hw.optional.arm.FEAT_PAuth",
        "hw.optional.arm.FEAT_DotProd", "hw.optional.arm.FEAT_BF16",
        "hw.optional.arm.FEAT_SME", "hw.optional.arm.FEAT_SME2",
        "hw.optional.arm.FEAT_MTE", "hw.optional.arm.FEAT_MTE4",
        "hw.optional.arm.FEAT_SVE", "hw.optional.arm.FEAT_CSSC",
        "hw.optional.arm.FEAT_HBC", "hw.optional.arm.FEAT_SPECRES2",
        "hw.optional.arm.FP_SyncExceptions",
    };
    for (size_t i = 0; i < sizeof feats / sizeof feats[0]; i++) sysctl_int(feats[i]);
}

int main(void) {
    install_handlers();
    printf("Darwin userspace probe\n");
    printf("======================\n");
    sysctl_str("kern.osproductversion");
    sysctl_str("kern.osversion");
    sysctl_str("kern.version");
    sysctl_int("kern.hv_vmm_present");

    dump_commpage();
    probe_sprr();
    probe_sysctls();

    printf("\ndone.\n");
    return 0;
}
