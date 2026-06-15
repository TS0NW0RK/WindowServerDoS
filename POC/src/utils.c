#include "ca_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint32_t g_state = 0xCAFEBABE;

void ca_seed_rng(uint32_t seed) {
    g_state = seed ? seed : (uint32_t)time(NULL);
}

uint32_t ca_rand_u32(void) {
    g_state ^= g_state << 13;
    g_state ^= g_state >> 17;
    g_state ^= g_state << 5;
    return g_state;
}

uint64_t ca_rand_u64(void) {
    return ((uint64_t)ca_rand_u32() << 32) | ca_rand_u32();
}

void ca_fill_random(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        p[i] = (uint8_t)(ca_rand_u32() & 0xFF);
    }
}

static char g_kr_buf[64];

const char *ca_kr_string(kern_return_t kr) {
    switch (kr) {
    case KERN_SUCCESS: return "KERN_SUCCESS";
    case KERN_INVALID_ARGUMENT: return "KERN_INVALID_ARGUMENT";
    case KERN_FAILURE: return "KERN_FAILURE";
    case KERN_RESOURCE_SHORTAGE: return "KERN_RESOURCE_SHORTAGE";
    case KERN_NOT_RECEIVER: return "KERN_NOT_RECEIVER";
    case KERN_NO_ACCESS: return "KERN_NO_ACCESS";
    case KERN_MEMORY_ERROR: return "KERN_MEMORY_ERROR";
    case KERN_INVALID_ADDRESS: return "KERN_INVALID_ADDRESS";
    case KERN_PROTECTION_FAILURE: return "KERN_PROTECTION_FAILURE";
    case KERN_ABORTED: return "KERN_ABORTED";
    default:
        snprintf(g_kr_buf, sizeof(g_kr_buf), "0x%08x", (unsigned)kr);
        return g_kr_buf;
    }
}

static char *ca_copy_cfstring(CFStringRef s) {
    if (!s) return NULL;
    CFIndex len = CFStringGetLength(s);
    CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    char *buf = calloc(1, (size_t)max);
    if (!buf) return NULL;
    if (!CFStringGetCString(s, buf, max, kCFStringEncodingUTF8)) {
        free(buf);
        return NULL;
    }
    return buf;
}

char *ca_registry_get_string(io_registry_entry_t entry, const char *key) {
    CFStringRef cfkey = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
    if (!cfkey) return NULL;
    CFTypeRef val = IORegistryEntryCreateCFProperty(entry, cfkey, kCFAllocatorDefault, 0);
    CFRelease(cfkey);
    if (!val) return NULL;
    char *out = NULL;
    if (CFGetTypeID(val) == CFStringGetTypeID()) {
        out = ca_copy_cfstring((CFStringRef)val);
    }
    CFRelease(val);
    return out;
}

bool ca_str_contains(const char *haystack, const char *needle) {
    if (!needle || !needle[0]) return true;
    if (!haystack) return false;
    return strstr(haystack, needle) != NULL;
}
