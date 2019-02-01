/**
 * @file snabb.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for snabb.c.
 *
 * @copyright
 * Copyright (C) 2017 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SNABB_H
#define SNABB_H

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "config.h"
#include "snabb.h"
#include "cfg.h"

#define XPATH_MAX_LEN     128
#define UNIX_PATH_MAX     108
#define SNABB_MESSAGE_MAX 256
#define SNABB_SOCKET_MAX  100000000

char ch[SNABB_SOCKET_MAX];

typedef struct global_ctx_s {
    const char *yang_model;
    struct ly_ctx *libyang_ctx;
    const struct lys_module *module;
    int socket_fd;
    char socket_path[UNIX_PATH_MAX];
    sr_subscription_ctx_t *sub;
    sr_session_ctx_t *sess;
    sr_conn_ctx_t *startup_conn;
    sr_session_ctx_t *startup_sess;
    cfg_ctx *cfg;
} global_ctx_t;

typedef struct iter_change_s {
    sr_val_t *old_val; // data passed from sysrepo
    sr_val_t *new_val; // data passed from sysrepo
    sr_change_oper_t oper; // data passed from sysrepo
} iter_change_t;

#endif /* SNABB_H */
