#pragma once

#include <IOKit/IOKitLib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define CA_MAX_SELECTORS   512
#define CA_MAX_STRUCT_SIZE 8192
#define CA_MAX_SCALARS     16

typedef struct {
    const char *service_name;
    const char *io_class;
    const char *user_client_class;
    io_service_t service;
    io_connect_t connect;
    uint32_t open_type;
    kern_return_t open_status;
} ca_target_t;

typedef struct {
    const char *filter_class;      /* IOClass substring, NULL = all */
    const char *filter_uc;         /* IOUserClientClass substring */
    uint32_t open_type;
    uint32_t max_selectors;
    uint32_t iterations_per_target;
    uint32_t seed;
    bool verbose;
    bool dry_run;
    bool struct_only;   /* only CallStructMethod (investigation mode) */
    const char *log_path;
} ca_config_t;

void ca_seed_rng(uint32_t seed);
uint32_t ca_rand_u32(void);
uint64_t ca_rand_u64(void);
void ca_fill_random(void *buf, size_t len);

int ca_enumerate_targets(ca_target_t **out_targets, size_t *out_count, const ca_config_t *cfg);
void ca_free_targets(ca_target_t *targets, size_t count);

kern_return_t ca_open_target(ca_target_t *target, const ca_config_t *cfg);
void ca_close_target(ca_target_t *target);

typedef struct {
    uint32_t selector;
    uint32_t in_scalar_count;
    uint64_t in_scalars[CA_MAX_SCALARS];
    size_t in_struct_size;
    bool used_struct;
    kern_return_t status;
    const char *method_kind;
} ca_fuzz_result_t;

int ca_fuzz_target(ca_target_t *target, const ca_config_t *cfg, FILE *log);

void ca_log_target_info(FILE *log, const ca_target_t *target);
const char *ca_kr_string(kern_return_t kr);
