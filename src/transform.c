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
#include "xpath.h"
#include "transform.h"

int socket_send(ctx_t *ctx, char *message, sb_command_t command);
int xpath_to_snabb(ctx_t *ctx, action_t *action, char **message);
int sysrepo_to_snabb(ctx_t *ctx, action_t *action);
int add_action(sr_val_t *val, sr_change_oper_t op);
void clear_all_actions();
void free_action(action_t *action);
int apply_action(ctx_t *ctx, action_t *action);


bool list_or_container(sr_type_t type) {
	return type == SR_LIST_T || type == SR_CONTAINER_T || type == SR_CONTAINER_PRESENCE_T;
}

bool leaf_without_value(sr_type_t type) {
	return type == SR_UNKNOWN_T || type == SR_LEAF_EMPTY_T;
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
	int len = 0;
	int nbytes;

	if (NULL == message) {
		return SR_ERR_INTERNAL;
	}

	/* get message length in char* format */
	char str[30];
	sprintf(str, "%d", (int) strlen(message));

	len = (int) strlen(&str[0]) + 1 + (int) strlen(message) + 1;

	char *buffer = malloc(sizeof(buffer) * len);
	if (NULL == buffer) {
		return SR_ERR_NOMEM;
	}

	nbytes = snprintf(buffer, len, "%s\n%s", str, message);

	//TODO add timeout check
	nbytes = write(ctx->socket_fd, buffer, nbytes);
	if ((int) strlen(buffer) != (int) nbytes) {
		ERR("Failed to write full messaget o server: written %d, expected %d", (int) nbytes, (int) strlen(buffer));
		free(buffer);
		return SR_ERR_INTERNAL;
	}
	free(buffer);

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
		INF("Response:\n%s", ch);
	}

	/* set null terminated string at the beggining */
	ch[0] = '\0';

	/* based on the leader.lua file */

	return SR_ERR_OK;
failed:
	WRN("Operation faild for:\n%s", message);
	WRN("Respons:\n%s", ch);
	return SR_ERR_INTERNAL;
}

int double_message_size(char **message, int *len) {
	int rc = SR_ERR_OK;
	char *tmp = NULL;

	*len = *len * 2;
	tmp = (char *) realloc(*message, (*len));
	if (NULL == tmp) {
		return SR_ERR_NOMEM;
	}

	*message = tmp;

	return rc;
}

int fill_list(sr_node_t *tree, char **message, int *len) {
	int rc = SR_ERR_OK;

	if (NULL == tree) {
		return rc;
	}
	while(true) {
		if (*len < XPATH_MAX_LEN + (int) strlen(*message)) {
			rc = double_message_size(message, len);
			CHECK_RET(rc, cleanup, "failed to double the buffer size: %s", sr_strerror(rc));
		}
		if (NULL == tree) {
			break;
		} else if (list_or_container(tree->type)) {
			//TODO check for error
			strcat(*message, tree->name);
			strcat(*message, " { ");
			rc = fill_list(tree->first_child, message, len);
			CHECK_RET(rc, cleanup, "failed fill_list: %s", sr_strerror(rc));
			strcat(*message, " } ");
		} else {
			//TODO check for error
			strcat(*message, tree->name);
			strcat(*message, " ");
			char *value = sr_val_to_str((sr_val_t *) tree);
			strcat(*message, value);
			free(value);
			strcat(*message, "; ");
		}
		tree = tree->next;
	}

cleanup:
	return rc;
}

int
xpath_to_snabb(ctx_t *ctx, action_t *action, char **message) {
	int rc = SR_ERR_OK;
	int len = SNABB_MESSAGE_MAX;
	*message = malloc(sizeof(*message) * len);
	if (NULL == *message) {
		return SR_ERR_NOMEM;
	}
	*message[0] = '\0';

	sr_node_t *trees = NULL;
	long unsigned int tree_cnt = 0;
	rc = sr_get_subtrees(ctx->sess, action->xpath, SR_GET_SUBTREE_DEFAULT, &trees, &tree_cnt);
	CHECK_RET(rc, error, "failed sr_get_subtrees: %s", sr_strerror(rc));

	if (1 == tree_cnt) {
		if (SR_LIST_T == trees[0].type) {
			strcat(*message, " { ");
		}
		rc = fill_list(trees->first_child, message, &len);
		CHECK_RET(rc, error, "failed to create snabb configuration data: %s", sr_strerror(rc));
		if (SR_LIST_T == trees[0].type) {
			strcat(*message, " } ");
		}
	} else {
		for (int i = 0; i < (int) tree_cnt; i++) {
			rc = fill_list(&trees[i], message, &len);
			CHECK_RET(rc, error, "failed to create snabb configuration data: %s", sr_strerror(rc));
		}
	}

	sr_free_trees(trees, tree_cnt);
	return rc;
error:
	if (NULL != *message) {
		free(*message);
	}
	if (NULL != trees) {
		sr_free_trees(trees, tree_cnt);
	}
	return rc;
}

int
format_xpath_old(ctx_t *ctx, action_t *action) {
	int  rc = SR_ERR_OK;
	int i,j = 0; /* iterators in for loop */

	/* transform sysrepo xpath to snabb xpath
	 * skip the first N characters '/<yang_model>:'
	 * N = '/' + ':' + 'length of yang model'
	 */
	action->snabb_xpath = strdup(action->xpath + ((2 + strlen(ctx->yang_model)) * sizeof *action->snabb_xpath));
	if (NULL == action->snabb_xpath) {
		return SR_ERR_NOMEM;
	}

	/* remove "'" from the key values in the xpath
	 * transform psid-map[addr='178.79.150.1'] to psid-map[addr=178.79.150.1]
	 */
	for(i = 0; i < (int) strlen(action->snabb_xpath); i++) {
		if (action->snabb_xpath[i] == '\'' && action->snabb_xpath[i+1] == ']') {
			i = i + 1;
		}
		action->snabb_xpath[j] = action->snabb_xpath[i];
		j++;
		if (action->snabb_xpath[i] == '=' && action->snabb_xpath[i+1] == '\'') {
			i = i + 1;
		}
	}
	/* add null terminated character */
	action->snabb_xpath[j] = action->snabb_xpath[(int) strlen(action->snabb_xpath)];

	return rc;
}

int
sysrepo_to_snabb(ctx_t *ctx, action_t *action) {
	sb_command_t command;
	char *message = NULL;
	int  rc = SR_ERR_OK;

	char *tmp = NULL;
	char **value = &tmp;

	rc = format_xpath(action);
	CHECK_RET(rc, error, "failed to format xpath: %s", sr_strerror(rc));

	/* translate sysrepo operation to snabb command */
	switch(action->op) {
	case SR_OP_MODIFIED:
		message = malloc(sizeof(message) + SNABB_MESSAGE_MAX + strlen(action->snabb_xpath) + strlen(ctx->yang_model));
		if (NULL == message) {
			return SR_ERR_NOMEM;
		}
		snprintf(message, SNABB_MESSAGE_MAX, "set-config {path '%s'; config '%s'; schema %s;}", action->snabb_xpath, action->value, ctx->yang_model);
		command = SB_SET;
		break;
	case SR_OP_CREATED:
		rc = xpath_to_snabb(ctx, action, value);
		CHECK_RET(rc, error, "failed xpath_to_snabb: %s", sr_strerror(rc));

		int len = SNABB_MESSAGE_MAX + (int) strlen(action->snabb_xpath) + strlen(*value) + (int) strlen(ctx->yang_model);
		message = malloc(sizeof(message) * len);
		if (NULL == message) {
			return SR_ERR_NOMEM;
		}
		snprintf(message, len, "set-config {path '%s'; config '%s'; schema %s;}", action->snabb_xpath, *value, ctx->yang_model);
		free(*value);
		command = SB_ADD;
		break;
	case SR_OP_DELETED:
		message = malloc(sizeof(message) + SNABB_MESSAGE_MAX + strlen(action->snabb_xpath) + strlen(ctx->yang_model));
		if (NULL == message) {
			return SR_ERR_NOMEM;
		}
		snprintf(message, SNABB_MESSAGE_MAX, "remove-config {path '%s'; schema %s;}", action->snabb_xpath, ctx->yang_model);
		command = SB_REMOVE;
		break;
	default:
		command = SB_SET;
	}

	/* send to socket */
	INF_MSG("send to socket");
	rc = socket_send(ctx, message, command);
	CHECK_RET(rc, error, "failed to send message to snabb socket: %s", sr_strerror(rc));

error:
	if (NULL != message) {
		free(message);
	}
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
	} else if (!list_or_container(val->type) && (SR_OP_CREATED == op || SR_OP_DELETED == op)) {
		/* check if a list/container is already in the list */
		action_t *tmp;
		LIST_FOREACH(tmp, &head, actions) {
			if (0 == strncmp(val->xpath, tmp->xpath, strlen(tmp->xpath)) && list_or_container(tmp->type)) {
				free(action);
				return rc;
			}
		}
		action->value = NULL;
	} else if (list_or_container(val->type) && (SR_OP_CREATED == op || SR_OP_DELETED == op)) {
		/* if a list/container is created/deleted remove previous entries of child nodes */
		action_t *tmp, *tmp2;
		tmp = LIST_FIRST(&head);
		while (NULL != tmp) {
			tmp2 = LIST_NEXT(tmp, actions);
			if (0 == strncmp(val->xpath, tmp->xpath, strlen(val->xpath))) {
				LIST_REMOVE(tmp, actions);
				free_action(tmp);
			}
			tmp = tmp2;
		}
		action->value = NULL;
	} else {
		action->value = NULL;
	}
	action->xpath = strdup(val->xpath);
	action->snabb_xpath = NULL;
	action->op = op;
	action->type = val->type;
	LIST_INSERT_HEAD(&head, action, actions);

	return rc;
}

void
free_action(action_t *action) {
	if (NULL != action->value) {
		free(action->value);
	}
	if (NULL != action->xpath) {
		free(action->xpath);
	}
	if (NULL != action->snabb_xpath) {
		free(action->snabb_xpath);
	}
	free(action);
}

void
clear_all_actions() {
	action_t *tmp = NULL;
	while (!LIST_EMPTY(&head)) {
		tmp = LIST_FIRST(&head);
		LIST_REMOVE(tmp, actions);
		free_action(tmp);
	}
}

int
apply_all_actions(ctx_t *ctx) {
	int rc = SR_ERR_OK;
	action_t *tmp;
	LIST_FOREACH(tmp, &head, actions) {
		rc = apply_action(ctx, tmp);
		CHECK_RET(rc, rollback, "failed apply action: %s", sr_strerror(rc));
	}

	clear_all_actions();
	return rc;

rollback:
	//TODO do a rollback
	clear_all_actions();
	return rc;
}

int
apply_action(ctx_t *ctx, action_t *action) {
	int rc = SR_ERR_OK;

	rc = sysrepo_to_snabb(ctx, action);
	CHECK_RET(rc, error, "failed to create snabb message: %s", sr_strerror(rc));

	//TODO create revrse list for rollback

error:
	return rc;
}

int
sysrepo_datastore_to_snabb(ctx_t *ctx) {
	action_t *action = NULL;
	sr_node_t *trees = NULL;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL, *tmp_session = NULL;

	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0};

	snprintf(xpath, XPATH_MAX_LEN, "/%s:*", ctx->yang_model);

	/* connect to sysrepo */
	rc = sr_connect(ctx->yang_model, SR_CONN_DEFAULT, &connection);
	CHECK_RET(rc, error, "failed sr_connect: %s", sr_strerror(rc));

	/* start session */
	rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_CONFIG_ONLY, &session);
	CHECK_RET(rc, error, "failed sr_session_start: %s", sr_strerror(rc));

	tmp_session = ctx->sess;
	ctx->sess = session;

	long unsigned int tree_cnt = 0;
	rc = sr_get_subtrees(session, xpath, SR_GET_SUBTREE_DEFAULT, &trees, &tree_cnt);
	CHECK_RET(rc, error, "failed sr_get_subtrees: %s", sr_strerror(rc));

	for (int i = 0; i < (int) tree_cnt; i++) {
		action = malloc(sizeof(action_t));
		if (NULL == action) {
			goto error;
		}
			snprintf(xpath, XPATH_MAX_LEN, "/%s:%s", ctx->yang_model, trees[i].name);
		action->xpath = strdup(xpath);
		action->snabb_xpath = NULL;
		action->op = SR_OP_CREATED;
		action->type = trees[i].type;
		LIST_INSERT_HEAD(&head, action, actions);
	}

	//action_t *tmp = NULL;
	//LIST_FOREACH(tmp, &head, actions) {
	//	INF("Add liste entry: xpath: %s, value: %s, op: %d", tmp->xpath, tmp->value, tmp->op);
	//}

	rc = apply_all_actions(ctx);
	CHECK_RET(rc, error, "failed execute all operations: %s", sr_strerror(rc));

error:
	if (NULL != trees) {
		sr_free_trees(trees, tree_cnt);
	}
	if (NULL != session) {
		sr_session_stop(session);
	}
	if (NULL != connection) {
		sr_disconnect(connection);
	}

	ctx->sess = tmp_session;
	return rc;
}
