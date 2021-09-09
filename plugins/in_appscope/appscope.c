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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_socket.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "appscope.h"
#include "appscope_conf.h"
#include "appscope_conn.h"
#include "appscope_prot.h"

static int appscope_unix_create(struct flb_appscope *ctx)
{
    flb_sockfd_t fd = -1;
    unsigned long len;
    size_t address_length;
    struct sockaddr_un address;

    fd = flb_net_socket_create(AF_UNIX, FLB_TRUE);

    if (fd == -1) {
        return -1;
    }

    ctx->server_fd = fd;

    /* Prepare the unix socket path */
    // TODO: HANDLE ABSTRACT UNIX omit unlink if file path
    unlink(ctx->unix_path);
    len = strlen(ctx->unix_path);

    address.sun_family = AF_UNIX;
    sprintf(address.sun_path, "%s", ctx->unix_path);
    address_length = sizeof(address.sun_family) + len + 1;
    if (bind(fd, (struct sockaddr *) &address, address_length) != 0) {
        flb_errno();
        flb_socket_close(fd);
        return -1;
    }

    // TODO: HANDLE ABSTRACT UNIX omit chmod if file path
    if (chmod(address.sun_path, ctx->unix_perm)) {
        flb_errno();
        flb_error("[in_appscope] cannot set permission on '%s' to %04o",
                  address.sun_path, ctx->unix_perm);
        flb_socket_close(fd);
        return -1;
    }

    if (listen(fd, 5) != 0) {
        flb_errno();
        flb_socket_close(fd);
        return -1;
}

    return 0;
}

static int in_appscope_collect(struct flb_input_instance *in,
                          struct flb_config *config, void *in_context)
{
    int fd;
    struct flb_appscope *ctx = in_context;
    struct appscope_conn *conn;
    (void) in;

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
    (void) config;
    (void) data;
    ctx = appscope_conf_init(in, config);
    if (!ctx) {
        flb_plg_error(in, "could not initialize plugin");
        return -1;
    }

    /* Set context */
    flb_input_set_context(in, ctx);

    /* Create Unix Socket */
    ret = appscope_unix_create(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not listen on unix://%s", ctx->unix_path);
        appscope_conf_destroy(ctx);
        return -1;
    }
    flb_plg_info(ctx->ins, "listening on unix://%s", ctx->unix_path);


    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(in,
                                         in_appscope_collect,
                                         ctx->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set server socket collector");
        appscope_conf_destroy(ctx);
        return -1;
    }

    return 0;
}

static int in_appscope_exit(void *data, struct flb_config *config)
{
    struct flb_appscope *ctx = data;
    (void) config;

    appscope_conn_event(ctx);
    appscope_conf_destroy(ctx);

    return 0;
}

/* Configuration properties map */

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "unix_path", DEFAULT_UNIX_SOCKET_PATH_APPSCOPE,
     0, FLB_TRUE, offsetof(struct flb_appscope, unix_path),
     "Define Appscope unix socket path to read events"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_appscope_plugin = {
    .name         = "appscope",
    .description  = "AppScope",
    .cb_init      = in_appscope_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_exit      = in_appscope_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET
};
