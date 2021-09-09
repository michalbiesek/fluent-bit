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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "appscope.h"

int appscope_server_create(struct flb_appscope *ctx)
{
    flb_sockfd_t fd = -1;
    unsigned long len;
    size_t address_length;
    struct sockaddr_un address;
    fd = flb_net_socket_create(AF_UNIX, ctx->unix_fs_socket);

    if (fd == -1) {
        return -1;
    }

    ctx->server_fd = fd;

    /* Prepare the unix socket path */
    len = strlen(ctx->unix_path);

    memset(&address, 0, sizeof(address));
    sprintf(address.sun_path, "%s", ctx->unix_path);
    if (ctx->unix_fs_socket) {
        unlink(ctx->unix_path);
        address_length = sizeof(address);
    }
    else {
        address.sun_path[0] = 0;
        address_length = sizeof(address.sun_family) + len;
    }
    address.sun_family = AF_UNIX;

    if (bind(fd, (struct sockaddr *) &address, address_length) != 0) {
        flb_errno();
        close(fd);
        return -1;
    }

    if (ctx->unix_fs_socket && chmod(address.sun_path, ctx->unix_perm)) {
        flb_errno();
        flb_error("[in_appscope] cannot set permission on '%s' to %04o",
                  address.sun_path, ctx->unix_perm);
        close(fd);
        return -1;
    }

    if (listen(fd, 5) != 0) {
        flb_errno();
        close(fd);
        return -1;
    }

    return 0;
}

int appscope_server_destroy(struct flb_appscope *ctx)
{
    if (ctx->unix_path) {
        if (ctx->unix_fs_socket) {
            unlink(ctx->unix_path);
        }
        flb_free(ctx->unix_path);
    }

    close(ctx->server_fd);

    return 0;
}
