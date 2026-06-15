#include "ca_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char *ca_registry_get_string(io_registry_entry_t entry, const char *key);
extern bool ca_str_contains(const char *haystack, const char *needle);

typedef struct {
    char *io_class;
    char *user_client_class;
} ca_class_pair_t;

static const char *k_seed_classes[] = {
    "IOSurfaceRoot",
    "IOPMrootDomain",
    "AppleKeyStore",
    "IOHIDSystem",
    "AGXAcceleratorG13X",
    "AppleAPFSContainerScheme",
    "AppleMobileFileIntegrity",
    "AppleCredentialManager",
    "IOAVFamily",
    NULL,
};

static bool ca_ends_with(const char *s, const char *suffix) {
    if (!s || !suffix) return false;
    size_t sl = strlen(s), sufl = strlen(suffix);
    if (sufl > sl) return false;
    return strcmp(s + sl - sufl, suffix) == 0;
}

static bool ca_target_matches(const ca_target_t *t, const ca_config_t *cfg) {
    if (!t->user_client_class || !t->user_client_class[0]) return false;
    if (cfg->filter_class && !ca_str_contains(t->io_class, cfg->filter_class)) return false;
    if (cfg->filter_uc && !ca_str_contains(t->user_client_class, cfg->filter_uc)) return false;
    return true;
}

static bool ca_pair_seen(ca_class_pair_t *pairs, size_t count, const char *io_class, const char *uc) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(pairs[i].io_class, io_class) == 0 &&
            strcmp(pairs[i].user_client_class, uc) == 0) {
            return true;
        }
    }
    return false;
}

static int ca_push_pair(ca_class_pair_t **pairs, size_t *count, size_t *cap,
                        const char *io_class, const char *uc) {
    if (!io_class || !io_class[0] || !uc || !uc[0]) return 0;
    if (ca_ends_with(io_class, "UserClient")) return 0;
    if (strcmp(io_class, uc) == 0) return 0;
    if (ca_pair_seen(*pairs, *count, io_class, uc)) return 0;

    if (*count == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 32;
        ca_class_pair_t *grown = realloc(*pairs, new_cap * sizeof(ca_class_pair_t));
        if (!grown) return -1;
        *pairs = grown;
        *cap = new_cap;
    }

    (*pairs)[*count].io_class = strdup(io_class);
    (*pairs)[*count].user_client_class = strdup(uc);
    if (!(*pairs)[*count].io_class || !(*pairs)[*count].user_client_class) return -1;
    (*count)++;
    return 0;
}

static int ca_push_target(ca_target_t **targets, size_t *count, size_t *cap,
                          io_service_t service, const char *io_class, const char *uc) {
    if (*count == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 32;
        ca_target_t *grown = realloc(*targets, new_cap * sizeof(ca_target_t));
        if (!grown) return -1;
        *targets = grown;
        *cap = new_cap;
    }

    char *name = ca_registry_get_string((io_registry_entry_t)service, "IORegistryEntryName");

    ca_target_t *slot = &(*targets)[*count];
    memset(slot, 0, sizeof(*slot));
    slot->service = service;
    IOObjectRetain(service);
    slot->service_name = name ? name : strdup(io_class);
    slot->io_class = strdup(io_class);
    slot->user_client_class = strdup(uc);
    if (!slot->io_class || !slot->user_client_class || !slot->service_name) return -1;
    (*count)++;
    return 0;
}

static int ca_collect_pairs_from_registry(ca_class_pair_t **pairs, size_t *count, size_t *cap) {
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = IORegistryCreateIterator(kIOMainPortDefault,
                                                kIOServicePlane,
                                                kIORegistryIterateRecursively,
                                                &iterator);
    if (kr != KERN_SUCCESS) return -1;

    io_registry_entry_t entry;
    while ((entry = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        char *io_class = ca_registry_get_string(entry, "IOClass");
        char *uc_class = ca_registry_get_string(entry, "IOUserClientClass");
        if (io_class && uc_class) {
            ca_push_pair(pairs, count, cap, io_class, uc_class);
        }
        free(io_class);
        free(uc_class);
        IOObjectRelease(entry);
    }
    IOObjectRelease(iterator);
    return 0;
}

static int ca_collect_seed_pairs(ca_class_pair_t **pairs, size_t *count, size_t *cap) {
    for (int i = 0; k_seed_classes[i]; i++) {
        const char *io_class = k_seed_classes[i];
        CFDictionaryRef matching = IOServiceMatching(io_class);
        if (!matching) continue;

        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, matching);
        if (!svc) continue;

        char *uc = ca_registry_get_string((io_registry_entry_t)svc, "IOUserClientClass");
        if (uc) {
            ca_push_pair(pairs, count, cap, io_class, uc);
            free(uc);
        } else {
            char synthetic[128];
            snprintf(synthetic, sizeof(synthetic), "%sUserClient", io_class);
            ca_push_pair(pairs, count, cap, io_class, synthetic);
        }
        IOObjectRelease(svc);
    }
    return 0;
}

static int ca_resolve_pair(const ca_class_pair_t *pair, ca_target_t **targets,
                           size_t *count, size_t *cap) {
    CFDictionaryRef matching = IOServiceMatching(pair->io_class);
    if (!matching) return 0;

    io_iterator_t iter = IO_OBJECT_NULL;
    IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iter);

    io_service_t svc;
    while ((svc = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
        if (ca_push_target(targets, count, cap, svc, pair->io_class, pair->user_client_class) < 0) {
            IOObjectRelease(svc);
            IOObjectRelease(iter);
            return -1;
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(iter);
    return 0;
}

static void ca_free_pairs(ca_class_pair_t *pairs, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(pairs[i].io_class);
        free(pairs[i].user_client_class);
    }
    free(pairs);
}

int ca_enumerate_targets(ca_target_t **out_targets, size_t *out_count, const ca_config_t *cfg) {
    *out_targets = NULL;
    *out_count = 0;

    ca_class_pair_t *pairs = NULL;
    size_t pair_count = 0, pair_cap = 0;

    if (ca_collect_pairs_from_registry(&pairs, &pair_count, &pair_cap) < 0) {
        ca_free_pairs(pairs, pair_count);
        return -1;
    }
    ca_collect_seed_pairs(&pairs, &pair_count, &pair_cap);

    size_t cap = 0;
    ca_target_t *targets = NULL;

    for (size_t i = 0; i < pair_count; i++) {
        if (!ca_target_matches(&(ca_target_t){
                .io_class = pairs[i].io_class,
                .user_client_class = pairs[i].user_client_class,
            }, cfg)) {
            continue;
        }
        if (ca_resolve_pair(&pairs[i], &targets, out_count, &cap) < 0) {
            ca_free_targets(targets, *out_count);
            ca_free_pairs(pairs, pair_count);
            return -1;
        }
    }

    ca_free_pairs(pairs, pair_count);
    *out_targets = targets;
    return 0;
}

void ca_free_targets(ca_target_t *targets, size_t count) {
    if (!targets) return;
    for (size_t i = 0; i < count; i++) {
        ca_close_target(&targets[i]);
        if (targets[i].service) IOObjectRelease(targets[i].service);
        free((void *)targets[i].service_name);
        free((void *)targets[i].io_class);
        free((void *)targets[i].user_client_class);
    }
    free(targets);
}

kern_return_t ca_open_target(ca_target_t *target, const ca_config_t *cfg) {
    if (!target || target->connect) return KERN_INVALID_ARGUMENT;

    for (uint32_t type = cfg->open_type; type < cfg->open_type + 16; type++) {
        io_connect_t conn = IO_OBJECT_NULL;
        kern_return_t kr = IOServiceOpen(target->service, mach_task_self(), type, &conn);
        if (kr == KERN_SUCCESS) {
            target->connect = conn;
            target->open_type = type;
            target->open_status = kr;
            return kr;
        }
        target->open_status = kr;
    }
    return target->open_status;
}

void ca_close_target(ca_target_t *target) {
    if (!target || !target->connect) return;
    IOServiceClose(target->connect);
    target->connect = IO_OBJECT_NULL;
}

void ca_log_target_info(FILE *log, const ca_target_t *target) {
    fprintf(log, "  service=%s\n", target->service_name);
    fprintf(log, "  IOClass=%s\n", target->io_class);
    fprintf(log, "  IOUserClientClass=%s\n", target->user_client_class);
    fprintf(log, "  open_type=%u status=%s\n", target->open_type, ca_kr_string(target->open_status));
}
