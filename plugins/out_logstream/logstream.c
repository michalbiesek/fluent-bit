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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "logstream.h"
#include "logstream_conf.h"

static int cb_logstream_init(struct flb_output_instance *ins,
                       struct flb_config *config, void *data)
{
    struct flb_out_logstream *ctx = NULL;
    (void) data;

    ctx = flb_logstream_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_logstream_flush(const void *data, size_t bytes,
                         const char *tag, int tag_len,
                         struct flb_input_instance *i_ins,
                         void *out_context,
                         struct flb_config *config)
{
    int ret = FLB_ERROR;
    size_t bytes_sent;
    flb_sds_t json = NULL;
    flb_sds_t json_header = NULL;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_out_logstream *ctx = out_context;
    (void) i_ins;
    char header[256];

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available to %s:%i",
                      u->tcp_host, u->tcp_port);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Send connection header to logstream on a new connection and if Auth Token is set */
    if (ctx->auth_token) {
        if (u_conn->ka_count == 0) {
            snprintf(header, sizeof(header), "{\"authToken\": \"%s\"}\n", ctx->auth_token);
            json_header = flb_sds_create(header);
            ret = flb_io_net_write(u_conn, json_header, flb_sds_len(json_header), &bytes_sent);
            flb_sds_destroy(json_header);
            if (ret == -1) {
                flb_errno();
                flb_upstream_conn_release(u_conn);
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
        }
    }

    /* Format JSON payload and send data */
    json = flb_pack_msgpack_to_json_format(data, bytes,
            FLB_PACK_JSON_FORMAT_LINES,
            FLB_PACK_JSON_DATE_DOUBLE,
            NULL);
    if (!json) {
        flb_plg_error(ctx->ins, "error formatting JSON payload");
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    ret = flb_io_net_write(u_conn, json, flb_sds_len(json), &bytes_sent);
    flb_sds_destroy(json);
    if (ret == -1) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_logstream_exit(void *data, struct flb_config *config)
{
    struct flb_out_logstream *ctx = data;

    flb_logstream_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "auth_token", "",
     0, FLB_FALSE, 0,
     "Specify an Auth Token if set in LogStream."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_logstream_plugin = {
    .name           = "logstream",
    .description    = "LogStream Output",
    .cb_init        = cb_logstream_init,
    .cb_flush       = cb_logstream_flush,
    .cb_exit        = cb_logstream_exit,
    .config_map     = config_map,
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
