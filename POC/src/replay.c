#include "ca_fuzz.h"
#include "ca_io.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s dump -u FILTER -n COUNT -S SEED [-o file]   # dump RNG sequence (no IOKit)\n"
            "  %s run  -u FILTER -n COUNT -S SEED [--limit N]  # replay fuzz on first N targets\n"
            "  %s run  -u FILTER -n COUNT -S SEED --proxies P  # fuzz first P matching targets\n",
            prog, prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    argc--;
    argv++;

    ca_config_t cfg = {
        .filter_uc = NULL,
        .max_selectors = 256,
        .iterations_per_target = 5000,
        .seed = 0,
        .verbose = true,
        .struct_only = false,
        .log_path = "replay.log",
    };
    uint32_t proxy_limit = 1;

    static struct option opts[] = {
        {"userclient", required_argument, 0, 'u'},
        {"iterations", required_argument, 0, 'n'},
        {"seed", required_argument, 0, 'S'},
        {"selectors", required_argument, 0, 's'},
        {"output", required_argument, 0, 'o'},
        {"proxies", required_argument, 0, 'p'},
        {"struct-only", no_argument, 0, '1'},
        {0, 0, 0, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "u:n:S:s:o:p:1", opts, NULL)) != -1) {
        switch (opt) {
        case 'u': cfg.filter_uc = optarg; break;
        case 'n': cfg.iterations_per_target = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'S': cfg.seed = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 's': cfg.max_selectors = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'o': cfg.log_path = optarg; break;
        case 'p': proxy_limit = (uint32_t)strtoul(optarg, NULL, 0); break;
        case '1': cfg.struct_only = true; break;
        default: usage(argv[0]); return 1;
        }
    }

    if (!cfg.filter_uc) {
        fprintf(stderr, "Need -u filter\n");
        return 1;
    }

    ca_seed_rng(cfg.seed);

    if (strcmp(mode, "dump") == 0) {
        FILE *out = stdout;
        if (strcmp(cfg.log_path, "replay.log") != 0) {
            out = fopen(cfg.log_path, "w");
            if (!out) {
                perror(cfg.log_path);
                return 1;
            }
        }
        /* Simulate full campaign: proxy_limit targets × iterations */
        uint32_t total = proxy_limit * cfg.iterations_per_target;
        fprintf(stderr, "[*] dump %u ops (proxies=%u x iters=%u) seed=%u\n",
                total, proxy_limit, cfg.iterations_per_target, cfg.seed);
        ca_fuzz_dump_sequence(&cfg, total, out);
        if (out != stdout) fclose(out);
        return 0;
    }

    if (strcmp(mode, "run") != 0) {
        usage(argv[0]);
        return 1;
    }

    ca_target_t *targets = NULL;
    size_t count = 0;
    if (ca_enumerate_targets(&targets, &count, &cfg) < 0 || count == 0) {
        fprintf(stderr, "No targets\n");
        return 1;
    }

    FILE *log = fopen(cfg.log_path, "a");
    if (!log) {
        perror(cfg.log_path);
        ca_free_targets(targets, count);
        return 1;
    }

    size_t opened = 0;
    for (size_t i = 0; i < count && opened < proxy_limit; i++) {
        if (ca_open_target(&targets[i], &cfg) != KERN_SUCCESS) continue;
        opened++;
        fprintf(stderr, "[+] replay proxy %zu/%u: %s\n", opened, proxy_limit, targets[i].service_name);
        ca_fuzz_replay_target(&targets[i], &cfg, log);
        ca_close_target(&targets[i]);
    }

    fprintf(stderr, "[*] replay done, %zu proxies, log=%s\n", opened, cfg.log_path);
    fclose(log);
    ca_free_targets(targets, count);
    return 0;
}
