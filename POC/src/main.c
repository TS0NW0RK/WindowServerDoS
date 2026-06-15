#include "ca_io.h"

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_interrupted = 0;

static void on_signal(int sig) {
    (void)sig;
    g_interrupted = 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "ConfederationAve IOKit fuzzer — macOS kernel attack surface research\n\n"
            "Usage: %s [options]\n\n"
            "Options:\n"
            "  -l, --list              List reachable IOUserClient targets and exit\n"
            "  -c, --class FILTER      Filter by IOClass substring\n"
            "  -u, --userclient FILTER Filter by IOUserClientClass substring\n"
            "  -t, --type TYPE         IOServiceOpen connection type (default 0)\n"
            "  -n, --iterations N      Fuzz iterations per opened target (default 5000)\n"
            "  -s, --selectors N       Max selector range (default 256)\n"
            "  -S, --seed N            RNG seed (default: time)\n"
            "  -o, --output FILE       Log file (default: fuzz.log)\n"
            "  -v, --verbose           Log every fuzz attempt\n"
            "  -d, --dry-run           Enumerate only, do not open/fuzz\n"
            "  -h, --help              Show help\n\n"
            "Examples:\n"
            "  %s --list\n"
            "  %s -u IOSurface -n 20000 -v\n"
            "  %s -u AppleCLPC -n 10000\n"
            "  %s -c IOHID -n 8000\n",
            prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    ca_config_t cfg = {
        .filter_class = NULL,
        .filter_uc = NULL,
        .open_type = 0,
        .max_selectors = 256,
        .iterations_per_target = 5000,
        .seed = 0,
        .verbose = false,
        .dry_run = false,
        .log_path = "fuzz.log",
    };

    bool list_only = false;

    static struct option long_opts[] = {
        {"list", no_argument, 0, 'l'},
        {"class", required_argument, 0, 'c'},
        {"userclient", required_argument, 0, 'u'},
        {"type", required_argument, 0, 't'},
        {"iterations", required_argument, 0, 'n'},
        {"selectors", required_argument, 0, 's'},
        {"seed", required_argument, 0, 'S'},
        {"output", required_argument, 0, 'o'},
        {"verbose", no_argument, 0, 'v'},
        {"dry-run", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "lc:u:t:n:s:S:o:vdh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'l': list_only = true; break;
        case 'c': cfg.filter_class = optarg; break;
        case 'u': cfg.filter_uc = optarg; break;
        case 't': cfg.open_type = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'n': cfg.iterations_per_target = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 's': cfg.max_selectors = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'S': cfg.seed = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'o': cfg.log_path = optarg; break;
        case 'v': cfg.verbose = true; break;
        case 'd': cfg.dry_run = true; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    ca_seed_rng(cfg.seed);

    ca_target_t *targets = NULL;
    size_t count = 0;
    if (ca_enumerate_targets(&targets, &count, &cfg) < 0) {
        return 1;
    }

    fprintf(stderr, "[*] Found %zu IOUserClient targets", count);
    if (cfg.filter_class) fprintf(stderr, " (IOClass~'%s')", cfg.filter_class);
    if (cfg.filter_uc) fprintf(stderr, " (UC~'%s')", cfg.filter_uc);
    fprintf(stderr, "\n");

    if (list_only || cfg.dry_run) {
        for (size_t i = 0; i < count; i++) {
            printf("%-40s  IOClass=%-35s  UC=%s\n",
                   targets[i].service_name,
                   targets[i].io_class,
                   targets[i].user_client_class);
        }
        ca_free_targets(targets, count);
        return 0;
    }

    FILE *log = fopen(cfg.log_path, "a");
    if (!log) {
        perror(cfg.log_path);
        ca_free_targets(targets, count);
        return 1;
    }

    time_t now = time(NULL);
    fprintf(log, "\n=== ConfederationAve session %s", ctime(&now));
    fprintf(log, "seed=%u iterations=%u selectors=%u\n", cfg.seed, cfg.iterations_per_target, cfg.max_selectors);
    fflush(log);

    size_t opened = 0;
    for (size_t i = 0; i < count && !g_interrupted; i++) {
        kern_return_t kr = ca_open_target(&targets[i], &cfg);
        if (kr != KERN_SUCCESS) {
            if (cfg.verbose) {
                fprintf(stderr, "[-] skip %s (%s): %s\n",
                        targets[i].service_name,
                        targets[i].user_client_class,
                        ca_kr_string(kr));
            }
            continue;
        }

        opened++;
        fprintf(stderr, "[+] fuzzing %s (%s) type=%u\n",
                targets[i].service_name,
                targets[i].user_client_class,
                targets[i].open_type);

        ca_log_target_info(log, &targets[i]);
        ca_fuzz_target(&targets[i], &cfg, log);
        ca_close_target(&targets[i]);
    }

    fprintf(stderr, "[*] Opened and fuzzed %zu/%zu targets. Log: %s\n", opened, count, cfg.log_path);
    fprintf(log, "SESSION_DONE opened=%zu total=%zu\n", opened, count);
    fclose(log);
    ca_free_targets(targets, count);
    return 0;
}
