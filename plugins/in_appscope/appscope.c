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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <msgpack.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

#include "appscope.h"
#include "appscope_conf.h"
#include "appscope_conn.h"
#include "appscope_prot.h"
#include "appscope_server.h"

/* cb_collect callback */
static int in_appscope_collect(struct flb_input_instance *i_ins,
                                 struct flb_config *config, void *in_context)
{
    int fd;
    struct flb_appscope *ctx = in_context;
    struct appscope_conn *conn;
    (void) i_ins;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_plg_error(ctx->ins, "could not accept new connection");
        return -1;
    }

    flb_plg_debug(ctx->ins, "new Unix connection arrived FD=%i", fd);
    conn = appscope_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }

    return 0;
}

/* Initialize plugin */
static int in_appscope_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_appscope *ctx;

    /* Allocate space for the configuration */
    ctx = appscope_conf_create(in, config);
    if (!ctx) {
        flb_plg_error(in, "could not initialize plugin");
        return -1;
    }

    if (!ctx->unix_path) {
        flb_plg_error(ctx->ins, "Unix path not defined");
        appscope_conf_destroy(ctx);
        return -1;
    }
    ctx->unix_fs_socket = ctx->unix_path[0] != '@'; 

    /* Create Unix Socket */
    ret = appscope_server_create(ctx);
    if (ret == -1) {
        appscope_conf_destroy(ctx);
        return -1;
    }

    /* Set context */
    flb_input_set_context(in, ctx);

    /* Collect events for every opened connection to our socket */
    ret = flb_input_set_collector_socket(in,
                                         in_appscope_collect,
                                         ctx->server_fd,
                                         config);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector");
        appscope_conf_destroy(ctx);
    }

    return 0;
}

static int in_appscope_exit(void *data, struct flb_config *config)
{
    struct flb_appscope *ctx = data;
    (void) config;

    appscope_conn_exit(ctx);
    appscope_conf_destroy(ctx);

    return 0;
}

struct flb_input_plugin in_appscope_plugin = {
    .name         = "appscope",
    .description  = "AppScope",
    .cb_init      = in_appscope_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_exit      = in_appscope_exit,
    .flags        = FLB_INPUT_NET
};
