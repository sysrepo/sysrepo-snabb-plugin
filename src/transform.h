/**
 * @file snabb.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for transofrm.c.
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

#ifndef TRANSFORM_H
#define TRANSFORM_H

#include <sysrepo.h>
#include <sys/queue.h>


#define XPATH_MAX_LEN     128
#define UNIX_PATH_MAX     256
#define SNABB_MESSAGE_MAX 1024
#define SNABB_SOCKET_MAX  100000000

char ch[SNABB_SOCKET_MAX];

typedef enum sb_command_e {
    SB_GET = 0,   /* read configuration data */
    SB_GET_STATE, /* read state data */
    SB_LOAD,      /* load a new configuration */
    SB_SET,       /* incrementally update configuration */
    SB_ADD,       /* augment configuration, for example by adding a routing table entry */
    SB_REMOVE,    /* remove a component from a configuration, for example removing a routing table entry */
} sb_command_t;

typedef struct ctx_s {
	const char *yang_model;
	int pid;
	int socket_fd;
	char socket_path[UNIX_PATH_MAX];
	sr_subscription_ctx_t *sub;
	sr_session_ctx_t *sess;
} ctx_t;

typedef struct action_s {
	char *xpath;
	char *snabb_xpath;
	char *value;
	sr_type_t type;
	sr_change_oper_t op;
	LIST_ENTRY(action_s) actions;
} action_t;
LIST_HEAD(listhead, action_s) head;

int socket_connect(ctx_t *ctx);
int socket_send(ctx_t *ctx, char *message, sb_command_t command);
void socket_close(ctx_t *ctx);

int format_xpath(ctx_t *ctx, action_t *action);
int xpath_to_snabb(char **message, char *xpath, sr_session_ctx_t *sess);
int sysrepo_to_snabb(ctx_t *ctx, action_t *action);

int add_action(sr_val_t *val, sr_change_oper_t op);
void clear_all_actions();
int apply_all_actions(ctx_t *ctx);
void free_action(action_t *action);
int apply_action(ctx_t *ctx, action_t *action);

#endif /* TRANSFORM_H */
