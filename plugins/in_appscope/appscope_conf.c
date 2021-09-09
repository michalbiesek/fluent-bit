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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_utils.h>

#include "appscope.h"
#include "appscope_conf.h"
#include "appscope_server.h"

struct flb_appscope *appscope_conf_create(struct flb_input_instance *ins,
                                      struct flb_config *config)
{
    const char *tmp;
    struct flb_appscope *ctx;
    struct flb_parser *parser;

    ctx = flb_calloc(1, sizeof(struct flb_appscope));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->evl = config->evl;
    ctx->ins = ins;
    mk_list_init(&ctx->connections);

    tmp = flb_input_get_property("path", ins);
    if (tmp) {
        ctx->unix_path = flb_strdup(tmp);
    }

    tmp = flb_input_get_property("unix_perm", ins);
    if (tmp) {
        ctx->unix_perm = strtol(tmp, NULL, 8) & 07777;
    } else {
        ctx->unix_perm = 0644;
    }

    /* Buffer Chunk Size */
    tmp = flb_input_get_property("buffer_chunk_size", ins);
    if (!tmp) {
        ctx->buffer_chunk_size = FLB_APPSCOPE_CHUNK; /* 32KB */
    } else {
        ctx->buffer_chunk_size = flb_utils_size_to_bytes(tmp);
    }

    /* Buffer Max Size */
    tmp = flb_input_get_property("buffer_max_size", ins);
    if (!tmp) {
        ctx->buffer_max_size = ctx->buffer_chunk_size;
    } else {
        ctx->buffer_max_size = flb_utils_size_to_bytes(tmp);
    }

    /* Parser */
    parser = flb_parser_get(FLB_APPSCOPE_IN_PARSER, config);
    if (!parser) {
        parser = flb_parser_create(FLB_APPSCOPE_IN_PARSER, "json", "%d/%b/%Y:%H:%M:%S %z",
                                   NULL, NULL, NULL, MK_FALSE, 
                                   MK_TRUE, NULL, 0, NULL, config);
        ctx->is_parser_created = FLB_TRUE;
    }

    ctx->parser = parser;

    return ctx;
}

int appscope_conf_destroy(struct flb_appscope *ctx)
{
    appscope_server_destroy(ctx);

    if (ctx->is_parser_created && ctx->parser) {
        flb_parser_destroy(ctx->parser);
    }
    flb_free(ctx);

    return 0;
}
