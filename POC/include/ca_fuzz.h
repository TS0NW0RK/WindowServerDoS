#pragma once

#include "ca_io.h"

typedef struct {
    uint32_t selector;
    uint32_t variant;       /* 0=Method 1=Struct 2=Async */
    uint32_t in_scalar_count;
    uint64_t in_scalars[CA_MAX_SCALARS];
    size_t in_struct_size;
} ca_fuzz_op_t;

void ca_fuzz_op_generate(const ca_config_t *cfg, ca_fuzz_op_t *op);
kern_return_t ca_fuzz_op_execute(io_connect_t conn, const ca_fuzz_op_t *op, ca_fuzz_result_t *res);

int ca_fuzz_replay_target(ca_target_t *target, const ca_config_t *cfg, FILE *log);
int ca_fuzz_dump_sequence(const ca_config_t *cfg, uint32_t count, FILE *out);
