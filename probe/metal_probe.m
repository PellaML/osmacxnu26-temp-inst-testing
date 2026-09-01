// metal_probe.m — Metal, IOSurface, and accelerator-registry behavior oracle.
// Our code; contains no Apple binary or private credential material.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#include <sys/sysctl.h>

static void print_string_sysctl(const char *name) {
    char value[1024];
    size_t size = sizeof(value);
    if (sysctlbyname(name, value, &size, NULL, 0) != 0) {
        printf("  %s=<error>\n", name);
        return;
    }
    value[size < sizeof(value) ? size : sizeof(value) - 1] = 0;
    printf("  %s=%s\n", name, value);
}

static void print_registry_value(io_registry_entry_t service, CFStringRef key) {
    CFTypeRef value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
    if (value == NULL) return;
    CFStringRef description = CFCopyDescription(value);
    char text[2048];
    if (description != NULL && CFStringGetCString(description, text, sizeof(text), kCFStringEncodingUTF8)) {
        char key_text[256];
        if (CFStringGetCString(key, key_text, sizeof(key_text), kCFStringEncodingUTF8)) {
            printf("      %s = %s\n", key_text, text);
        }
    }
    if (description != NULL) CFRelease(description);
    CFRelease(value);
}

static void probe_registry_class(const char *class_name) {
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault,
        IOServiceMatching(class_name), &iterator);
    printf("  class %-24s match=0x%x\n", class_name, (unsigned)kr);
    if (kr != KERN_SUCCESS) return;

    io_registry_entry_t service;
    unsigned count = 0;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        io_name_t name = {0};
        io_name_t actual_class = {0};
        char path[4096] = {0};
        uint64_t registry_id = 0;
        IORegistryEntryGetName(service, name);
        IOObjectGetClass(service, actual_class);
        IORegistryEntryGetRegistryEntryID(service, &registry_id);
        IORegistryEntryGetPath(service, kIOServicePlane, path);
        printf("    [%u] name=%s class=%s id=0x%llx path=%s\n",
            count++, name, actual_class, (unsigned long long)registry_id, path);
        const CFStringRef keys[] = {
            CFSTR("model"), CFSTR("vendor-id"), CFSTR("device-id"),
            CFSTR("revision-id"), CFSTR("subsystem-id"), CFSTR("IOClass"),
            CFSTR("IOProviderClass"), CFSTR("MetalPluginName"),
            CFSTR("MetalPluginClassName"), CFSTR("IONameMatched"),
            CFSTR("compatible"), CFSTR("AAPL,slot-name"), CFSTR("VRAM,totalMB"),
            CFSTR("unified-memory"), CFSTR("gpu-core-count"),
            CFSTR("firmwareVersion"), CFSTR("IOFBDependentID")
        };
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
            print_registry_value(service, keys[i]);
        }
        IOObjectRelease(service);
    }
    printf("    count=%u\n", count);
    IOObjectRelease(iterator);
}

static void probe_registry(void) {
    puts("\n===== IOKIT ACCELERATOR SERVICES =====");
    const char *classes[] = {
        "IOGPU", "AppleParavirtGPU", "AGXAccelerator", "IOAccelerator",
        "IOFramebuffer", "IOSurfaceRoot"
    };
    for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); ++i) {
        probe_registry_class(classes[i]);
    }
}

static void print_device(id<MTLDevice> device, NSUInteger index) {
    printf("\n  device[%lu]\n", (unsigned long)index);
    printf("    name=%s\n", device.name.UTF8String);
    printf("    registryID=0x%llx location=%lu locationNumber=%lu\n",
        (unsigned long long)device.registryID, (unsigned long)device.location,
        (unsigned long)device.locationNumber);
    printf("    lowPower=%d headless=%d removable=%d unifiedMemory=%d\n",
        device.isLowPower, device.isHeadless, device.isRemovable,
        device.hasUnifiedMemory);
    printf("    maxBufferLength=%llu recommendedWorkingSet=%llu currentAllocated=%llu\n",
        (unsigned long long)device.maxBufferLength,
        (unsigned long long)device.recommendedMaxWorkingSetSize,
        (unsigned long long)device.currentAllocatedSize);
    MTLSize threads = device.maxThreadsPerThreadgroup;
    printf("    maxThreadsPerThreadgroup=%lux%lux%lu argumentBuffersTier=%lu\n",
        (unsigned long)threads.width, (unsigned long)threads.height,
        (unsigned long)threads.depth, (unsigned long)device.argumentBuffersSupport);
    printf("    readWriteTextureTier=%lu maxThreadgroupMemory=%lu\n",
        (unsigned long)device.readWriteTextureSupport,
        (unsigned long)device.maxThreadgroupMemoryLength);

    if (@available(macOS 10.15, *)) {
        printf("    architecture=%s peerGroup=%llu peerIndex=%u peerCount=%u\n",
            device.architecture.name.UTF8String, (unsigned long long)device.peerGroupID,
            device.peerIndex, device.peerCount);
    }
    if (@available(macOS 11.0, *)) {
        printf("    dynamicLibraries=%d functionPointers=%d rayTracing=%d barycentrics=%d\n",
            device.supportsDynamicLibraries, device.supportsFunctionPointers,
            device.supportsRaytracing, device.areBarycentricCoordsSupported);
    }

    static const NSUInteger families[] = {
        1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,
        2001,2002,3001,3002,3003,4001,4002,5001,5002
    };
    printf("    supportedFamilies=");
    BOOL any = NO;
    for (size_t i = 0; i < sizeof(families) / sizeof(families[0]); ++i) {
        if ([device supportsFamily:(MTLGPUFamily)families[i]]) {
            printf("%s%lu", any ? "," : "", (unsigned long)families[i]);
            any = YES;
        }
    }
    puts(any ? "" : "<none>");

    static const NSUInteger feature_sets[] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,
        10000,10001,10002,10003,10004,10005,
        20000,20001,20002,20003,20004,30000,30001,30002
    };
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    printf("    supportedFeatureSets="); any = NO;
    for (size_t i = 0; i < sizeof(feature_sets) / sizeof(feature_sets[0]); ++i) {
        if ([device supportsFeatureSet:(MTLFeatureSet)feature_sets[i]]) {
            printf("%s%lu", any ? "," : "", (unsigned long)feature_sets[i]);
            any = YES;
        }
    }
#pragma clang diagnostic pop
    puts(any ? "" : "<none>");
}

static void exercise_metal(id<MTLDevice> device) {
    puts("\n===== METAL COMPUTE EXECUTION =====");
    NSError *error = nil;
    NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
        "kernel void add_one(device uint *v [[buffer(0)]], uint i [[thread_position_in_grid]]) { v[i] += 1; }";
    id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
    printf("  compile=%s", library != nil ? "ok" : "failed");
    if (error != nil) printf(" error=%s", error.description.UTF8String);
    puts("");
    if (library == nil) return;

    id<MTLFunction> function = [library newFunctionWithName:@"add_one"];
    id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:function error:&error];
    printf("  pipeline=%s width=%lu maxThreads=%lu\n", pipeline != nil ? "ok" : "failed",
        (unsigned long)pipeline.threadExecutionWidth,
        (unsigned long)pipeline.maxTotalThreadsPerThreadgroup);
    if (pipeline == nil) return;

    uint32_t input[64];
    for (uint32_t i = 0; i < 64; ++i) input[i] = i;
    id<MTLBuffer> buffer = [device newBufferWithBytes:input length:sizeof(input)
        options:MTLResourceStorageModeShared];
    id<MTLCommandQueue> queue = [device newCommandQueue];
    id<MTLCommandBuffer> commands = [queue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [commands computeCommandEncoder];
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:buffer offset:0 atIndex:0];
    [encoder dispatchThreads:MTLSizeMake(64, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)64, pipeline.maxTotalThreadsPerThreadgroup), 1, 1)];
    [encoder endEncoding];
    [commands commit];
    [commands waitUntilCompleted];

    uint32_t *output = buffer.contents;
    BOOL valid = YES;
    for (uint32_t i = 0; i < 64; ++i) if (output[i] != i + 1) valid = NO;
    printf("  status=%lu valid=%d gpuStart=%.9f gpuEnd=%.9f",
        (unsigned long)commands.status, valid, commands.GPUStartTime, commands.GPUEndTime);
    if (commands.error != nil) printf(" error=%s", commands.error.description.UTF8String);
    puts("");
}

static void exercise_iosurface(id<MTLDevice> device) {
    puts("\n===== IOSURFACE / METAL INTEROP =====");
    NSDictionary *properties = @{
        (id)kIOSurfaceWidth: @64,
        (id)kIOSurfaceHeight: @64,
        (id)kIOSurfaceBytesPerElement: @4,
        (id)kIOSurfaceBytesPerRow: @256,
        (id)kIOSurfaceAllocSize: @(64 * 64 * 4),
        (id)kIOSurfacePixelFormat: @(0x42475241u), /* 'BGRA' */
    };
    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)properties);
    printf("  create=%s", surface != NULL ? "ok" : "failed");
    if (surface == NULL) { puts(""); return; }
    printf(" id=%u width=%zu height=%zu rowBytes=%zu alloc=%zu planes=%zu\n",
        IOSurfaceGetID(surface), IOSurfaceGetWidth(surface), IOSurfaceGetHeight(surface),
        IOSurfaceGetBytesPerRow(surface), IOSurfaceGetAllocSize(surface),
        IOSurfaceGetPlaneCount(surface));

    IOReturn lock = IOSurfaceLock(surface, 0, NULL);
    void *base = IOSurfaceGetBaseAddress(surface);
    if (lock == kIOReturnSuccess && base != NULL) memset(base, 0x5a, IOSurfaceGetAllocSize(surface));
    IOReturn unlock = IOSurfaceUnlock(surface, 0, NULL);
    printf("  lock=0x%x base=%s unlock=0x%x useCount=%d seed=%u\n",
        (unsigned)lock, base != NULL ? "non-null" : "null", (unsigned)unlock,
        (int)IOSurfaceGetUseCount(surface), IOSurfaceGetSeed(surface));

    if (device != nil) {
        MTLTextureDescriptor *descriptor = [MTLTextureDescriptor
            texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
            width:64 height:64 mipmapped:NO];
        descriptor.usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite |
            MTLTextureUsageRenderTarget;
        descriptor.storageMode = MTLStorageModeShared;
        id<MTLTexture> texture = [device newTextureWithDescriptor:descriptor
            iosurface:surface plane:0];
        printf("  metalTexture=%s width=%lu height=%lu format=%lu storage=%lu usage=0x%lx\n",
            texture != nil ? "ok" : "failed", (unsigned long)texture.width,
            (unsigned long)texture.height, (unsigned long)texture.pixelFormat,
            (unsigned long)texture.storageMode, (unsigned long)texture.usage);
    }
    CFRelease(surface);
}

int main(void) {
    @autoreleasepool {
        puts("Darwin Metal/IOSurface probe\n============================");
        print_string_sysctl("kern.osproductversion");
        print_string_sysctl("kern.osversion");
        print_string_sysctl("hw.machine");
        print_string_sysctl("hw.model");

        puts("\n===== METAL DEVICES =====");
        NSArray<id<MTLDevice>> *devices = MTLCopyAllDevices();
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        const char *default_name = device != nil ? device.name.UTF8String : "<none>";
        printf("  count=%lu default=%s\n", (unsigned long)devices.count, default_name);
        for (NSUInteger i = 0; i < devices.count; ++i) print_device(devices[i], i);
        if (device != nil) exercise_metal(device);
        else puts("\n===== METAL COMPUTE EXECUTION =====\n  skipped: no Metal device");
        exercise_iosurface(device);
        probe_registry();
    }
    return 0;
}
