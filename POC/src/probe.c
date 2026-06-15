#include "ca_io.h"

#include <getopt.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int s) {
    (void)s;
    g_stop = 1;
}

static void fill_pattern(uint8_t *buf, size_t len, int variant) {
    switch (variant % 4) {
    case 0: memset(buf, 0x00, len); break;
    case 1: memset(buf, 0xFF, len); break;
    case 2:
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(i & 0xFF);
        break;
    default: ca_fill_random(buf, len); break;
    }
}

static kern_return_t probe_call(io_connect_t conn, uint32_t selector, uint32_t kind,
                               const uint64_t *scalars, uint32_t scalar_count,
                               const void *input, size_t input_size) {
    if (kind == 0) {
        uint64_t out_scalars[CA_MAX_SCALARS] = {0};
        uint32_t out_scalar_count = CA_MAX_SCALARS;
        size_t out_struct_cnt = 0;
        char out_struct[CA_MAX_STRUCT_SIZE];
        return IOConnectCallMethod(conn, selector, scalars, scalar_count, input, input_size,
                                   out_scalars, &out_scalar_count, out_struct, &out_struct_cnt);
    }
    if (kind == 1) {
        size_t out_cnt = CA_MAX_STRUCT_SIZE;
        char out_struct[CA_MAX_STRUCT_SIZE];
        return IOConnectCallStructMethod(conn, selector, input, input_size, out_struct, &out_cnt);
    }
    mach_port_t wake = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake) != KERN_SUCCESS) {
        return KERN_FAILURE;
    }
    kern_return_t kr = IOConnectCallAsyncMethod(conn, selector, wake, NULL, 0,
                                                scalars, scalar_count, input, input_size,
                                                NULL, NULL, NULL, NULL);
    mach_port_deallocate(mach_task_self(), wake);
    return kr;
}

static bool status_notable(kern_return_t kr) {
    if (kr == KERN_SUCCESS) return true;
    if (kr == 0xe00002c2 || kr == 0xe00002c1 || kr == 0xe00002bc || kr == 0xe00002cd) return false;
    return true;
}

static const char *kind_name(uint32_t k) {
    static const char *names[] = {"CallMethod", "CallStructMethod", "CallAsyncMethod"};
    return names[k % 3];
}

int main(int argc, char **argv) {
    ca_config_t cfg = {
        .filter_uc = NULL,
        .open_type = 0,
        .max_selectors = 512,
        .iterations_per_target = 0,
        .seed = (uint32_t)time(NULL),
        .verbose = true,
        .dry_run = false,
        .log_path = "probe.log",
    };

    uint32_t selector = UINT32_MAX;
    uint32_t kind_mask = 7; /* all kinds */
    uint32_t rounds = 200;

    static struct option opts[] = {
        {"userclient", required_argument, 0, 'u'},
        {"selector", required_argument, 0, 'p'},
        {"kind", required_argument, 0, 'k'},
        {"rounds", required_argument, 0, 'r'},
        {"seed", required_argument, 0, 'S'},
        {"output", required_argument, 0, 'o'},
        {0, 0, 0, 0},
    };

    int c;
    while ((c = getopt_long(argc, argv, "u:p:k:r:S:o:", opts, NULL)) != -1) {
        switch (c) {
        case 'u': cfg.filter_uc = optarg; break;
        case 'p': selector = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'k': kind_mask = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'r': rounds = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'S': cfg.seed = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'o': cfg.log_path = optarg; break;
        default:
            fprintf(stderr, "Usage: %s -u FILTER [-p selector] [-k kind_mask] [-r rounds]\n", argv[0]);
            return 1;
        }
    }

    if (!cfg.filter_uc) {
        fprintf(stderr, "Need -u IOUserClient filter\n");
        return 1;
    }

    signal(SIGINT, on_signal);
    ca_seed_rng(cfg.seed);

    ca_target_t *targets = NULL;
    size_t count = 0;
    if (ca_enumerate_targets(&targets, &count, &cfg) < 0 || count == 0) {
        fprintf(stderr, "No targets for %s\n", cfg.filter_uc);
        return 1;
    }

    FILE *log = fopen(cfg.log_path, "a");
    if (!log) {
        perror(cfg.log_path);
        ca_free_targets(targets, count);
        return 1;
    }

    static const size_t sizes[] = {
        0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
        255, 256, 512, 1023, 1024, 2047, 2048, 4095, 4096, 8192,
    };

    fprintf(log, "\n=== PROBE %s selector=%u seed=%u ===\n",
            cfg.filter_uc, selector, cfg.seed);
    fflush(log);

    for (size_t ti = 0; ti < count && !g_stop; ti++) {
        if (ca_open_target(&targets[ti], &cfg) != KERN_SUCCESS) continue;

        fprintf(stderr, "[+] probe %s (%s)\n", targets[ti].service_name, targets[ti].user_client_class);

        for (uint32_t round = 0; round < rounds && !g_stop; round++) {
            uint32_t sel = selector;
            if (sel == UINT32_MAX) sel = ca_rand_u32() % cfg.max_selectors;

            for (uint32_t kind = 0; kind < 3; kind++) {
                if (!(kind_mask & (1u << kind))) continue;

                for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
                    size_t sz = sizes[si];
                    uint8_t *buf = NULL;
                    if (sz) {
                        buf = calloc(1, sz);
                        if (!buf) continue;
                        fill_pattern(buf, sz, (int)(round + si));
                    }

                    uint64_t scalars[CA_MAX_SCALARS];
                    uint32_t sc = (uint32_t)(sizes[si % (sizeof(sizes) / sizeof(sizes[0]))] & 0xF);
                    for (uint32_t i = 0; i < sc; i++) scalars[i] = ca_rand_u64();

                    kern_return_t kr = probe_call(targets[ti].connect, sel, kind,
                                                  scalars, sc, buf, sz);
                    if (status_notable(kr)) {
                        fprintf(log,
                                "PROBE service=%s sel=%u kind=%s scalars=%u struct=%zu status=%s\n",
                                targets[ti].service_name, sel, kind_name(kind), sc, sz,
                                ca_kr_string(kr));
                        fflush(log);
                        fprintf(stderr, "  [!] sel=%u %s sz=%zu -> %s\n",
                                sel, kind_name(kind), sz, ca_kr_string(kr));
                    }
                    free(buf);
                }
            }
        }
        ca_close_target(&targets[ti]);
    }

    fclose(log);
    ca_free_targets(targets, count);
    return 0;
}
