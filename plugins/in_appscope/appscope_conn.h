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

#ifndef FLB_IN_APPSCOPE_CONN_H
#define FLB_IN_APPSCOPE_CONN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>

#include "appscope.h"

/* Respresents a connection */
struct appscope_conn {
    struct mk_event event;           /* Built-in event data for mk_events */
    int fd;                          /* Socket file descriptor            */
    int status;                      /* Connection status                 */

    /* Buffer */
    char *buf_data;                  /* Buffer data                       */
    size_t buf_size;                 /* Buffer size                       */
    size_t buf_len;                  /* Buffer length                     */
    size_t buf_parsed;               /* Parsed buffer (offset)            */
    struct flb_input_instance *ins;  /* Parent plugin instance            */
    struct flb_appscope *ctx;        /* Plugin configuration context      */

    struct mk_list _head;
};

struct appscope_conn *appscope_conn_add(int fd, struct flb_appscope *ctx);
int appscope_conn_exit(struct flb_appscope *ctx);

#endif
