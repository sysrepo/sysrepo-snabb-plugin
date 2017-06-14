/**
 * @file transofrm.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief A bridge for connecting snabb and sysrepo data plane.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/plugins.h>

#include "common.h"
#include "transform.h"

bool list_or_container(sr_type_t type) {
	return type == SR_LIST_T || type == SR_CONTAINER_T || type == SR_CONTAINER_PRESENCE_T;
}

bool leaf_without_value(sr_type_t type) {
	return type == SR_UNKNOWN_T || type == SR_LEAF_EMPTY_T;
}

char *concat(const char *s1, const char *s2) {
	char *result = NULL;

	result = malloc(strlen(s1)+strlen(s2)+1);

	strcpy(result, s1);
	strcat(result, s2);

	return result;
}

char *format_message(char *message) {
	char *tmp, *formated = NULL;
	char snum[7];

	int len = strlen(message);
	//TODO error handling
	snprintf(snum, 7, "%d", len);

	tmp = concat(&snum[0], "\n");
	formated = concat(tmp, message);
	free(tmp);

	return formated;
}

void socket_close(ctx_t *ctx) {
	if (-1 != ctx->socket_fd) {
		close(ctx->socket_fd);
	}
}

int socket_connect(ctx_t *ctx) {
	struct sockaddr_un address;
	int  rc;

	INF("connect to snabb socket /run/snabb/%d/config-leader-socket", ctx->pid);

	ctx->socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (ctx->socket_fd < 0) {
		WRN("failed to create UNIX socket: %d", ctx->socket_fd);
		goto error;
	}

	snprintf(ctx->socket_path, UNIX_PATH_MAX, "/run/snabb/%d/config-leader-socket", ctx->pid);

	/* start with a clean address structure */
	memset(&address, 0, sizeof(struct sockaddr_un));

	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, UNIX_PATH_MAX, "/run/snabb/%d/config-leader-socket", ctx->pid);

	rc = connect(ctx->socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un));
	CHECK_RET_MSG(rc, error, "failed connection to snabb socket");

	return SR_ERR_OK;
error:
	socket_close(ctx);
	return SR_ERR_INTERNAL;
}

int socket_send(ctx_t *ctx, char *message, sb_command_t command) {
	char buffer[SNABB_MESSAGE_MAX];
	int  nbytes;

	char *formated = format_message(message);
	nbytes = snprintf(buffer, SNABB_MESSAGE_MAX, "%s", formated);

	nbytes = write(ctx->socket_fd, buffer, nbytes);
	if ((int) strlen(formated) != (int) nbytes) {
		ERR("Failed to write full messaget o server: written %d, expected %d", (int) nbytes, (int) strlen(formated));
		free(formated);
		return SR_ERR_INTERNAL;
	}
	free(formated);

	nbytes = read(ctx->socket_fd, ch, SNABB_SOCKET_MAX);
	ch[nbytes] = 0;

	/* count new lines */
	int counter = 0;
	for (int i = 0; i < (int) strlen(ch); i++) {
		if ('\n' == ch[i]) {
			counter++;
		}
	}
	/* if it has 5 new lines that means it has 'status' parameter */

	if (0 == nbytes) {
		goto failed;
	} else if (5 == counter) {
		goto failed;
	} else if (SB_SET == command && 18 != nbytes) {
		goto failed;
	} else if (SB_GET == command && 0 == nbytes) {
		goto failed;
	} else {
		INF("Operation:\n%s", message);
		INF("Respons:\n%s", ch);
	}

	/* set null terminated string at the beggining */
	ch[0] = 0;

	/* based on the leader.lua file */

	return SR_ERR_OK;
failed:
	WRN("Operation faild for:\n%s", message);
	WRN("Respons:\n%s", ch);
	return SR_ERR_INTERNAL;
}

int
sysrepo_to_snabb(ctx_t *ctx, sb_command_t command, char *xpath, char *value) {
	int  rc = SR_ERR_OK;
	char *xpath_substring;

	/* transform sysrepo xpath to snabb xpath
	 * skip the first N characters '/<yang_model>:'
	 */
	xpath_substring = xpath + ((2 + strlen(ctx->yang_model)) * sizeof *xpath_substring);

	//TODO make dynamic
	char message[SNABB_MESSAGE_MAX];
	snprintf(message, SNABB_MESSAGE_MAX, "set-config {path '/%s'; config '%s'; schema %s;}", xpath_substring, value, ctx->yang_model);

	/* send to socket */
	INF_MSG("send to socket");
	socket_send(ctx, message, command);

	return rc;
}

int
add_action(sr_val_t *val, sr_change_oper_t op) {
	int rc = SR_ERR_OK;

	action_t *action = malloc(sizeof(action_t));
    if (!list_or_container(val->type) && !leaf_without_value(val->type) && SR_OP_MODIFIED == op) {
		action->value = sr_val_to_str(val);
		if (NULL == action->value) {
			free(action);
			return SR_ERR_DATA_MISSING;
		}
	} else if (!list_or_container(val->type) && SR_OP_CREATED == op) {
		/* check if a list/container is already in the list */
		action_t *tmp;
		LIST_FOREACH(tmp, &head, actions) {
				if (NULL == action) {
					continue;
				}
			if (strncmp(val->xpath, tmp->xpath, strlen(val->xpath)) && list_or_container(tmp->type)) {
				free(action);
				return rc;
			}
		}
		action->value = NULL;
	} else {
		action->value = NULL;
	}
	action->xpath = strdup(val->xpath);
	action->op = op;
	action->type = val->type;
	LIST_INSERT_HEAD(&head, action, actions);

	INF("Add liste entry: xpath: %s, value: %s, op: %d", action->xpath, action->value, action->op);

	return rc;
}

void
free_action(action_t *action) {
	free(action->xpath);
	if (NULL != action->value) {
		free(action->value);
	}
	free(action);
}

int
apply_action(ctx_t *ctx, action_t *action) {
	char *xpath_substring;
	sb_command_t command;
	int rc = SR_ERR_OK;

	/* translate sysrepo operation to snabb command */
	switch(action->op) {
	case SR_OP_MODIFIED:
		command = SB_SET;
	default:
		command = SB_SET;
	}

	/* transform sysrepo xpath to snabb xpath
	 * skip the first N characters '/<yang_model>:'
	 * N = '/' + ':' + 'length of yang model'
	 */
	xpath_substring = action->xpath + ((2 + strlen(ctx->yang_model)) * sizeof *action->xpath);

	rc = sysrepo_to_snabb(ctx, command, xpath_substring, action->value);

	return rc;
}
