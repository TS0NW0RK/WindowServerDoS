#include "ca_fuzz.h"

#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>

void ca_fuzz_op_generate(const ca_config_t *cfg, ca_fuzz_op_t *op) {
    memset(op, 0, sizeof(*op));
    op->selector = ca_rand_u32() % cfg->max_selectors;
    op->in_scalar_count = ca_rand_u32() % (CA_MAX_SCALARS + 1);
    for (uint32_t s = 0; s < op->in_scalar_count; s++) {
        op->in_scalars[s] = ca_rand_u64();
    }
    op->in_struct_size = ca_rand_u32() % (CA_MAX_STRUCT_SIZE + 1);
    if (cfg->struct_only) {
        op->variant = 1;
    } else {
        op->variant = ca_rand_u32() % 3;
    }
}

kern_return_t ca_fuzz_op_execute(io_connect_t conn, const ca_fuzz_op_t *op, ca_fuzz_result_t *res) {
    ca_fuzz_result_t req = {0};
    req.selector = op->selector;
    req.in_scalar_count = op->in_scalar_count;
    memcpy(req.in_scalars, op->in_scalars, sizeof(req.in_scalars));
    req.in_struct_size = op->in_struct_size;

    if (op->variant == 0) {
        uint64_t out_scalars[CA_MAX_SCALARS] = {0};
        uint32_t out_scalar_count = CA_MAX_SCALARS;
        size_t out_struct_cnt = 0;
        char out_struct[CA_MAX_STRUCT_SIZE];
        kern_return_t kr = IOConnectCallMethod(conn, op->selector,
                                               op->in_scalars, op->in_scalar_count,
                                               NULL, 0,
                                               out_scalars, &out_scalar_count,
                                               out_struct, &out_struct_cnt);
        *res = req;
        res->status = kr;
        res->method_kind = "CallMethod";
        return kr;
    }

    if (op->variant == 1) {
        size_t out_cnt = CA_MAX_STRUCT_SIZE;
        char out_struct[CA_MAX_STRUCT_SIZE];
        uint8_t *in_struct = NULL;
        if (op->in_struct_size) {
            in_struct = malloc(op->in_struct_size);
            if (!in_struct) return KERN_RESOURCE_SHORTAGE;
            ca_fill_random(in_struct, op->in_struct_size);
        }
        kern_return_t kr = IOConnectCallStructMethod(conn, op->selector,
                                                     in_struct, op->in_struct_size,
                                                     out_struct, &out_cnt);
        free(in_struct);
        *res = req;
        res->status = kr;
        res->method_kind = "CallStructMethod";
        res->used_struct = true;
        return kr;
    }

    mach_port_t wake = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake) != KERN_SUCCESS) {
        return KERN_FAILURE;
    }
    kern_return_t kr = IOConnectCallAsyncMethod(conn, op->selector, wake, NULL, 0,
                                                op->in_scalars, op->in_scalar_count,
                                                NULL, 0, NULL, NULL, NULL, NULL);
    mach_port_deallocate(mach_task_self(), wake);
    *res = req;
    res->status = kr;
    res->method_kind = "CallAsyncMethod";
    return kr;
}

int ca_fuzz_replay_target(ca_target_t *target, const ca_config_t *cfg, FILE *log) {
    if (!target->connect) return -1;
    fprintf(log, "BEGIN_REPLAY service=%s uc=%s iters=%u\n",
            target->service_name, target->user_client_class, cfg->iterations_per_target);
    fflush(log);

    for (uint32_t i = 0; i < cfg->iterations_per_target; i++) {
        ca_fuzz_op_t op;
        ca_fuzz_result_t res;
        ca_fuzz_op_generate(cfg, &op);
        kern_return_t kr = ca_fuzz_op_execute(target->connect, &op, &res);

        if (cfg->verbose) {
            fprintf(log,
                    "REPLAY idx=%u sel=%u kind=%s scalars=%u struct=%zu status=%s\n",
                    i, res.selector, res.method_kind, res.in_scalar_count,
                    res.in_struct_size, ca_kr_string(kr));
            fflush(log);
        }
        if ((i % 1000) == 999) usleep(1000);
    }

    fprintf(log, "END_REPLAY service=%s\n", target->service_name);
    fflush(log);
    return 0;
}

static void ca_consume_struct_rng(size_t len) {
    if (!len) return;
    uint8_t *tmp = malloc(len);
    if (tmp) {
        ca_fill_random(tmp, len);
        free(tmp);
    }
}

int ca_fuzz_dump_sequence(const ca_config_t *cfg, uint32_t count, FILE *out) {
    for (uint32_t i = 0; i < count; i++) {
        ca_fuzz_op_t op;
        ca_fuzz_op_generate(cfg, &op);
        if (op.variant == 1) {
            ca_consume_struct_rng(op.in_struct_size);
        }
        fprintf(out,
                "%u sel=%u var=%u scalars=%u struct=%zu s0=%llu\n",
                i, op.selector, op.variant, op.in_scalar_count, op.in_struct_size,
                (unsigned long long)op.in_scalars[0]);
    }
    return 0;
}
