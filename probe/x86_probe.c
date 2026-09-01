// x86_probe.c — Intel half of the Darwin identity/commpage oracle.
// Our code; reads only this runner's own public userspace state.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cpuid.h>

#define COMMPAGE 0x00007fffffe00000ULL

static uint8_t  rd8 (uint64_t o) { return *(volatile uint8_t  *)(COMMPAGE + o); }
static uint16_t rd16(uint64_t o) { return *(volatile uint16_t *)(COMMPAGE + o); }
static uint32_t rd32(uint64_t o) { return *(volatile uint32_t *)(COMMPAGE + o); }
static uint64_t rd64(uint64_t o) { return *(volatile uint64_t *)(COMMPAGE + o); }

static void string(const char *name) {
    char b[1024]; size_t n = sizeof b;
    int e = sysctlbyname(name, b, &n, NULL, 0);
    if (e) printf("  %-36s = <error>\n", name);
    else { b[n < sizeof b ? n : sizeof b - 1] = 0; printf("  %-36s = \"%s\" [%zu]\n", name, b, n); }
}
static void number(const char *name) {
    uint64_t v = 0; size_t n = sizeof v;
    int e = sysctlbyname(name, &v, &n, NULL, 0);
    if (e) printf("  %-36s = <error>\n", name);
    else printf("  %-36s = %llu (0x%llx) [%zu]\n", name, v, v, n);
}

static void cpuid(void) {
    printf("\n===== CPUID =====\n");
    unsigned a,b,c,d;
    unsigned max = __get_cpuid_max(0, NULL);
    char vendor[13] = {0};
    __cpuid(0, a,b,c,d); memcpy(vendor,&b,4); memcpy(vendor+4,&d,4); memcpy(vendor+8,&c,4);
    printf("  vendor=%s max_basic=0x%x\n", vendor, max);
    for (unsigned leaf=0; leaf<=max && leaf<=0x20; leaf++) {
        unsigned submax = (leaf == 7) ? 1 : 0;
        for (unsigned sub=0; sub<=submax; sub++) {
            __cpuid_count(leaf,sub,a,b,c,d);
            printf("  %08x:%02x  eax=%08x ebx=%08x ecx=%08x edx=%08x\n", leaf,sub,a,b,c,d);
        }
    }
    unsigned ext = __get_cpuid_max(0x80000000, NULL);
    for (unsigned leaf=0x80000000; leaf<=ext && leaf<=0x80000008; leaf++) {
        __cpuid(leaf,a,b,c,d);
        printf("  %08x:00  eax=%08x ebx=%08x ecx=%08x edx=%08x\n", leaf,a,b,c,d);
    }
}

static void commpage(void) {
    printf("\n===== X86_64 COMMPAGE =====\n");
    uint64_t sig=rd64(0); char s[9]; memcpy(s,&sig,8); s[8]=0;
    for (unsigned i=0; i<8; ++i) if (s[i] && (s[i] < 32 || s[i] > 126)) s[i]='.';
    printf("  base=0x%016llx signature=\"%s\"\n", COMMPAGE,s);
    printf("  +0x010 capabilities64 = 0x%016llx\n", rd64(0x10));
    printf("  +0x01e version        = %u\n", rd16(0x1e));
    printf("  +0x020 capabilities32 = 0x%08x\n", rd32(0x20));
    printf("  +0x022 ncpus          = %u\n", rd8(0x22));
    printf("  +0x026 cache line     = %u\n", rd16(0x26));
    printf("  +0x040 cpu family     = 0x%08x\n", rd32(0x40));
    printf("  +0x044 kdebug         = 0x%08x\n", rd32(0x44));
    printf("  +0x04d kernel pgshift = %u\n", rd8(0x4d));
    printf("  +0x04e user pgshift   = %u\n", rd8(0x4e));
    printf("  +0x080 approx time    = 0x%016llx\n", rd64(0x80));
    printf("\n  raw 0x000..0x100:\n");
    for (unsigned o=0;o<0x100;o+=16) {
        printf("  +%03x ",o); for(unsigned i=0;i<16;i++) printf("%02x ",rd8(o+i)); puts("");
    }
}

int main(void) {
    puts("Darwin x86_64 probe\n===================");
    string("kern.osproductversion"); string("kern.version");
    number("kern.hv_vmm_present"); number("kern.pfz");
    number("sysctl.proc_native"); number("sysctl.proc_translated");
    puts("\n===== IDENTITY =====");
    string("hw.machine"); string("hw.model"); string("hw.target"); string("hw.product"); string("hw.targettype");
    number("hw.cputype"); number("hw.cpusubtype"); number("hw.cpufamily"); number("hw.cpusubfamily");
    number("hw.cpu64bit_capable"); number("hw.vectorunit"); number("hw.pagesize"); number("hw.cachelinesize");
    puts("\n===== FEATURES =====");
    const char *n[] = {"hw.optional.x86_64","hw.optional.sse4_1","hw.optional.sse4_2","hw.optional.avx1_0","hw.optional.avx2_0","hw.optional.avx512f","hw.optional.bmi1","hw.optional.bmi2","hw.optional.fma","hw.optional.rdrand","hw.optional.rdseed","machdep.cpu.family","machdep.cpu.model","machdep.cpu.stepping","machdep.cpu.features","machdep.cpu.leaf7_features","machdep.cpu.extfeatures","machdep.cpu.brand_string"};
    for(size_t i=0;i<sizeof n/sizeof n[0];i++) {
        if (strstr(n[i],"features") || strstr(n[i],"brand")) string(n[i]); else number(n[i]);
    }
    cpuid(); commpage();
    return 0;
}
