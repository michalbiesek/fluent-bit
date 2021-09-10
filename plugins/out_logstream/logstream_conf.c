/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>

#include "logstream.h"
#include "logstream_conf.h"

struct flb_out_logstream *flb_logstream_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    const char *tmp;
    struct flb_upstream *upstream;
    struct flb_out_logstream *ctx = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_logstream));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Set default network configuration if not set */
    flb_output_net_default("127.0.0.1", 10090, ins);

    /* Check if SSL/TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }
#else
    io_flags = FLB_IO_TCP;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Auth Token */
    tmp = flb_output_get_property("auth_token", ins);
    if (tmp) {
        ctx->auth_token = tmp;
    } else {
        ctx->auth_token = NULL;
    }

    /* Upstream context */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags, ins->tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "could not create upstream context");
        flb_free(ctx);
        return NULL;
    }

    ctx->u = upstream;
    flb_output_upstream_set(ctx->u, ins);

    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    return ctx;
}

void flb_logstream_conf_destroy(struct flb_out_logstream *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_free(ctx);
    ctx = NULL;
}
