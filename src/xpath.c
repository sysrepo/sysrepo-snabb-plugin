/**
 * @file xpath.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief functions for handling sysrepo/snabb xpath.
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
#include <string.h>

#include <libyang/libyang.h>
#include <libyang/tree_data.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include "common.h"
#include "transform.h"
#include "xpath.h"

#define MAX_NODES 10

int
get_yang_type(ctx_t *ctx, action_t *action) {
	struct lys_node *node = NULL;
	struct ly_set *set = NULL;
	int rc = SR_ERR_OK;

	/* check if leaf-list */
	set = lys_find_path(ctx->module, NULL, action->xpath);
	if (NULL == set) {
		/* for choice leafs function return NULL */
		action->yang_type = LYS_CHOICE;
		return rc;
	}

	/* we expect only one node */
	if (set->number > 1) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

	node = set->set.s[0];

	action->yang_type = node->nodetype;

error:
	if (NULL != set) {
		ly_set_free(set);
	}
	return rc;
}

bool
list_or_container(sr_type_t type) {
	return type == SR_LIST_T || type == SR_CONTAINER_T || type == SR_CONTAINER_PRESENCE_T;
}

bool
leaf_without_value(sr_type_t type) {
	return type == SR_UNKNOWN_T || type == SR_LEAF_EMPTY_T;
}

/* transform xpath to snabb compatible format
 * 1) remove yang model from xpath
 * 2) remove "'" from the key value
 * 3) remove key's from the last node for set/add operation
 */
int
format_xpath(action_t *action) {
	char *xpath = NULL, *node = NULL, *tmp = NULL;
	sr_xpath_ctx_t state = {0,0,0,0};
	int rc = SR_ERR_OK;

	/* snabb xpath is always smaller than sysrepo's xpath */
	xpath = malloc(sizeof(xpath) * strlen(action->xpath));
	CHECK_NULL_MSG(xpath, &rc, error, "failed to allocate memory");
	strcpy(xpath, "");

	tmp = malloc(sizeof(tmp) * strlen(action->xpath));
	CHECK_NULL_MSG(tmp, &rc, error, "failed to allocate memory");

	node = sr_xpath_next_node(action->xpath, &state);
	if (NULL == node) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

	while(true) {
		strcat(xpath, "/");
		if (NULL != node) {
			strcat(xpath, node);
		}

		strcpy(tmp,"");
		while(true) {
			char *key, *value;
			key = sr_xpath_next_key_name(NULL, &state);
			if (NULL == key) {
				break;
			}
			strcat(tmp,"[");
			strcat(tmp,key);
			strcat(tmp,"=");
			value = sr_xpath_next_key_value(NULL, &state);
			strcat(tmp,value);
			strcat(tmp,"]");
		}
		node = sr_xpath_next_node(NULL, &state);
		if (list_or_container(action->type) && action->op == SR_OP_CREATED) {
			if (NULL == node) {
				break;
			}
			strcat(xpath, tmp);
		} else {
			strcat(xpath, tmp);
			if (NULL == node) {
				break;
			}
		}
	}

#ifdef LEAFLIST
	/* check if leaf-list for empty list's*/
	if (LYS_LEAFLIST == action->yang_type) {
		node = sr_xpath_last_node(NULL, &state);
		if (NULL == node) {
			rc = SR_ERR_INTERNAL;
			goto error;
		}
		/* remove last node from xpath */
		action->snabb_xpath = strndup(xpath, strlen(xpath) - 1 - strlen(node));
		/* set action to created regardlse what the original is */
		action->op = SR_OP_CREATED;
	} else {
		action->snabb_xpath = strdup(xpath);
	}
#else
	action->snabb_xpath = strdup(xpath);
#endif

error:
	sr_xpath_recover(&state);
	if (NULL != tmp) {
		free(tmp);
	}
	if (NULL != xpath) {
		free(xpath);
	}
	return rc;
}

void add_default_nodes(ctx_t *ctx, struct lyd_node *root) {
	const struct lyd_node *node = NULL, *next = NULL;

	LY_TREE_DFS_BEGIN(root, next, node) {
		if (LYS_LIST == node->schema->nodetype || LYS_CONTAINER == node->schema->nodetype) {
			struct lys_node *next = NULL, *elem = NULL;
			LY_TREE_FOR_SAFE(node->schema->child, next, elem) {
				if (elem->nodetype == LYS_LEAF || elem->nodetype == LYS_LEAFLIST) {
					struct lys_node_leaf *leaf = (struct lys_node_leaf *) elem;
					/* check if node exists
					 * if not add a data node with default value
					 */
					if (NULL != leaf->dflt) {
						struct lyd_node *lyd_next = NULL, *lyd_elem = NULL;
						bool found = false;
						LY_TREE_FOR_SAFE(node->child, lyd_next, lyd_elem) {
							if (0 == strncmp(lyd_elem->schema->name, leaf->name, strlen(leaf->name))) {
								found = true;
							}
						}
						if (false == found) {
							lyd_new_leaf((struct lyd_node *) node, ctx->module, leaf->name, leaf->dflt);
						}
					}
				}

			}
		}
		LY_TREE_DFS_END(root, next, node);
	}

	return;
}

/* TODO refactor this */
int
transform_data_to_array(ctx_t *ctx, char *xpath, char *data, struct lyd_node **node) {
	int rc = SR_ERR_OK;
	char *token, *tmp, *last;
	int i = 0, counter = 0;
	struct lyd_node *parent = NULL, *top_parent = NULL, *check = NULL;

	/* replace escaped new lines */
	for (i = 0; i < (int) strlen(data); i++) {
		if ('\\' == data[i] && 'n' == data[i+1]) {
			data[i] = '\n';
			i++;
			data[i] = ' ';
			counter++;
		}
	}
	counter = counter + 2;

	/* transform xpath to lyd_node's
	 * ignore key nodes if they exist
	 */
	if (NULL != xpath) {
		sr_xpath_ctx_t state = {0,0,0,0};
		char *xpath_elem = NULL;
		while (true) {
			if (NULL == xpath_elem) {
				xpath_elem = sr_xpath_next_node(xpath, &state);
			} else {
				xpath_elem = sr_xpath_next_node(NULL, &state);
			}
			if (NULL == xpath_elem) {
				break;
			}
			parent = lyd_new(parent, ctx->module, xpath_elem);
			if (NULL == top_parent) {
				top_parent = parent;
			}
		}
	}

	i = 0;
	while ((token = strsep(&data, "\n")) != NULL) {
		i++;
		while (token != '\0') {
			if (' ' == *token) {
				token++;
			} else {
				break;
			}
		}
		if (0 == i || 1 == i || 2 == i || counter < i) {
			continue;
		}
		/* TODO make more general case, remove continue */
		if (3 == i) {
			/* skip the config or state part */
			/* TODO check NULl */
			token = (NULL == xpath) ? token + 8 : token + 7;
		}
		if (0 == strlen(token)) {
			continue;
		} else if ('}' == *token) {
			/* when list/container are closed set new parent */
			parent = parent->parent;
			continue;
		} else {
			last = &token[strlen(token) - 1];
			tmp = strchr(token, ' ');
			*tmp = '\0';
			tmp++;
			if ('{' == *last) {
				/* only list/container's have the last element '{' */
				/* TODO check NULl */
				parent = lyd_new(parent, ctx->module, token);
				if (NULL == parent) {
					rc = SR_ERR_INTERNAL;
					goto error;
				}
				if (NULL == top_parent) {
					top_parent = parent;
				}
				continue;
			} else if ('}' == *last) {
				/* when list/container are closed set new parent */
				parent = parent->parent;
				continue;
			} else {
				*last = '\0';
				/* add leafs */
				/* TODO check NULl */
				check = lyd_new_leaf(parent, ctx->module, token, tmp);
				if (NULL == check) {
					rc = SR_ERR_INTERNAL;
					goto error;
				}
			}
		}
	}
	/* add default values */
	add_default_nodes(ctx, top_parent);

	/* validate the libyang data nodes */
	if (0 != lyd_validate(&top_parent, LYD_OPT_GET, NULL)) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

error:
	*node = top_parent;

	return rc;
}
