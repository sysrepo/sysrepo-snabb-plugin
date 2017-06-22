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

#include <sysrepo.h>
#include <sysrepo/xpath.h>
#include <libyang/tree_data.h>

#include "common.h"
#include "transform.h"
#include "xpath.h"

#define MAX_NODES 10

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
format_xpath(ctx_t *ctx, action_t *action) {
	struct ly_set *schema_node = NULL;
	char *xpath = NULL, *node = NULL, *tmp = NULL;
	struct lys_node *lys = NULL;
	sr_xpath_ctx_t state = {0,0,0,0};
	int rc = SR_ERR_OK;

	/* snabb xpath is always smaller than sysrepo's xpath */
	xpath = malloc(sizeof(xpath) * strlen(action->xpath));
	if (NULL == xpath) {
		rc = SR_ERR_NOMEM;
		goto error;
	}		
	strcpy(xpath, "");

	tmp = malloc(sizeof(tmp) * strlen(action->xpath));
	if (NULL == tmp) {
		rc = SR_ERR_NOMEM;
		goto error;
	}		

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

	/* check if leaf-list */
	schema_node = lys_find_xpath(ctx->libyang_ctx, NULL, action->xpath, 0);
	if (NULL == schema_node) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

	if (schema_node->number > 1) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

	lys = schema_node->set.s[0];

	if (LYS_LEAFLIST == lys->nodetype) {
		node = sr_xpath_last_node(NULL, &state);
		if (NULL == node) {
			rc = SR_ERR_INTERNAL;
			goto error;
		}
		/* remove last node from xpath */
		action->snabb_xpath = strndup(xpath, strlen(xpath) - 1 - strlen(node));
	} else {
		action->snabb_xpath = strdup(xpath);
	}

error:
	if (NULL != schema_node) {
		ly_set_free(schema_node);
	}
	if (NULL != tmp) {
		free(tmp);
	}
	if (NULL != xpath) {
		free(xpath);
	}
	return rc;
}

void add_default_nodes(ctx_t *ctx, struct lyd_node *root) {
    const struct lyd_node *node, *next;

	LY_TREE_DFS_BEGIN(root, next, node) {
		if (LYS_LIST == node->schema->nodetype || LYS_CONTAINER == node->schema->nodetype) {
			//printf("XPATH:%s\n", lyd_path(node));
			struct lys_node *next, *elem;
			LY_TREE_FOR_SAFE(node->schema->child, next, elem) {
				if (elem->nodetype == LYS_LEAF || elem->nodetype == LYS_LEAFLIST) {
					struct lys_node_leaf *leaf = (struct lys_node_leaf *) elem;
					/* check if node exists 
					 * if not add a data node with default value
					 */
					if (NULL != leaf->dflt) {
						//printf("default value for node %s is %s\n", leaf->name, leaf->dflt);
						struct lyd_node *lyd_next, *lyd_elem;
						bool found = false;
						LY_TREE_FOR_SAFE(node->child, lyd_next, lyd_elem) {
							if (0 == strncmp(lyd_elem->schema->name, leaf->name, strlen(leaf->name))) {
								found = true;
							}
						}
						if (false == found) {
							lyd_new_leaf(node, ctx->module, leaf->name, leaf->dflt);
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
transform_data_to_array(ctx_t *ctx, char *data, struct lyd_node **node) {
	int rc = SR_ERR_OK;
	char *token, *tmp, *last;
	int i = 0, counter = 0;
	struct lyd_node *parent = NULL, *top_parent = NULL;

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
		if (3 == i) {
			/* skip the config part */
			token = token + 8;
			tmp = strchr(token, ' ');
			*tmp = '\0';
			/* TODO check NULl */
			parent = lyd_new(parent, ctx->module, token);
			top_parent = parent;
			continue;
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
			/* get last character in splited line */
			if ('{' == *last) {
				/* only list/container's have the last element '{' */
				/* TODO check NULl */
				parent = lyd_new(parent, ctx->module, token);
				continue;
			} else if ('}' == *last) {
				/* check if default nodes are added for keys */
				/* when list/container are closed set new parent */
				parent = parent->parent;
				continue;
			} else {
				*last = '\0';
				/* add leafs */
				/* TODO check NULl */
				lyd_new_leaf(parent, ctx->module, token, tmp);
			}
		}
	}

	/* add default values */
	add_default_nodes(ctx, top_parent);

/*
	char *tmp_data;
	lyd_print_mem(&tmp_data, top_parent, LYD_JSON, LYP_FORMAT);
	printf("%s\n", tmp_data);
	parent = lyd_parse_mem(ctx->libyang_ctx, tmp_data, LYD_JSON, LYP_FORMAT);
	free(tmp_data);
*/
	*node = top_parent;

	if (NULL != data) {
		free(data);
		data = NULL;
	}

	return rc;
}
