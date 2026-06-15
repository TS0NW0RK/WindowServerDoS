#include "ca_io.h"

#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void ca_log_fuzz_hit(FILE *log, const ca_target_t *target, const ca_fuzz_result_t *r) {
    fprintf(log,
            "FUZZ service=%s uc=%s selector=%u kind=%s in_scalars=%u struct=%zu status=%s\n",
            target->service_name,
            target->user_client_class,
            r->selector,
            r->method_kind,
            r->in_scalar_count,
            r->in_struct_size,
            ca_kr_string(r->status));
    fflush(log);
}

static kern_return_t ca_try_call_method(io_connect_t conn, uint32_t selector,
                                        const ca_fuzz_result_t *in, ca_fuzz_result_t *out) {
    uint64_t out_scalars[CA_MAX_SCALARS] = {0};
    uint32_t out_scalar_count = CA_MAX_SCALARS;
    size_t out_struct_cnt = 0;
    char out_struct[CA_MAX_STRUCT_SIZE];

    kern_return_t kr = IOConnectCallMethod(conn,
                                           selector,
                                           in->in_scalars,
                                           in->in_scalar_count,
                                           NULL,
                                           0,
                                           out_scalars,
                                           &out_scalar_count,
                                           out_struct,
                                           &out_struct_cnt);

    *out = *in;
    out->status = kr;
    out->method_kind = "CallMethod";
    out->used_struct = false;
    return kr;
}

static kern_return_t ca_try_call_struct_method(io_connect_t conn, uint32_t selector,
                                               const ca_fuzz_result_t *in, ca_fuzz_result_t *out) {
    size_t out_struct_cnt = CA_MAX_STRUCT_SIZE;
    char out_struct[CA_MAX_STRUCT_SIZE];

    uint8_t *in_struct = NULL;
    if (in->in_struct_size) {
        in_struct = malloc(in->in_struct_size);
        if (!in_struct) return KERN_RESOURCE_SHORTAGE;
        ca_fill_random(in_struct, in->in_struct_size);
    }

    kern_return_t kr = IOConnectCallStructMethod(conn,
                                                 selector,
                                                 in_struct,
                                                 in->in_struct_size,
                                                 out_struct,
                                                 &out_struct_cnt);

    free(in_struct);

    *out = *in;
    out->status = kr;
    out->method_kind = "CallStructMethod";
    out->used_struct = true;
    return kr;
}

static kern_return_t ca_try_call_async_method(io_connect_t conn, uint32_t selector,
                                              const ca_fuzz_result_t *in, ca_fuzz_result_t *out) {
    mach_port_t wake_port = MACH_PORT_NULL;
    kern_return_t port_kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake_port);
    if (port_kr != KERN_SUCCESS) return port_kr;

    kern_return_t kr = IOConnectCallAsyncMethod(conn,
                                                selector,
                                                wake_port,
                                                NULL,
                                                0,
                                                in->in_scalars,
                                                in->in_scalar_count,
                                                NULL,
                                                0,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL);

    if (wake_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), wake_port);
    }

    *out = *in;
    out->status = kr;
    out->method_kind = "CallAsyncMethod";
    out->used_struct = false;
    return kr;
}

static bool ca_status_interesting(kern_return_t kr) {
    return kr == KERN_MEMORY_ERROR || kr == KERN_PROTECTION_FAILURE || kr == KERN_ABORTED;
}

int ca_fuzz_target(ca_target_t *target, const ca_config_t *cfg, FILE *log) {
    if (!target->connect) return -1;

    fprintf(log, "BEGIN_FUZZ service=%s uc=%s\n", target->service_name, target->user_client_class);
    fflush(log);

    for (uint32_t i = 0; i < cfg->iterations_per_target; i++) {
        ca_fuzz_result_t req = {0};
        ca_fuzz_result_t res = {0};

        req.selector = ca_rand_u32() % cfg->max_selectors;
        req.in_scalar_count = ca_rand_u32() % (CA_MAX_SCALARS + 1);
        for (uint32_t s = 0; s < req.in_scalar_count; s++) {
            req.in_scalars[s] = ca_rand_u64();
        }
        req.in_struct_size = ca_rand_u32() % (CA_MAX_STRUCT_SIZE + 1);

        uint32_t variant = ca_rand_u32() % 3;
        kern_return_t kr = KERN_FAILURE;

        if (variant == 0) {
            kr = ca_try_call_method(target->connect, req.selector, &req, &res);
        } else if (variant == 1) {
            kr = ca_try_call_struct_method(target->connect, req.selector, &req, &res);
        } else {
            kr = ca_try_call_async_method(target->connect, req.selector, &req, &res);
        }

        if (cfg->verbose || ca_status_interesting(kr)) {
            ca_log_fuzz_hit(log, target, &res);
        }

        /* Brief pause every 1000 iterations to keep system responsive */
        if ((i % 1000) == 999) {
            usleep(1000);
        }
    }

    fprintf(log, "END_FUZZ service=%s uc=%s\n", target->service_name, target->user_client_class);
    fflush(log);
    return 0;
}
