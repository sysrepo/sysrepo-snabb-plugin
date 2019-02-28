/**
 * @file libyang.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief functions dependent to libyang.
 *
 * @copyright
 * Copyright (C) 2017 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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

#include <sysrepo/xpath.h>

#include <libyang/libyang.h>
#include <libyang/tree_data.h>
#include <libyang/tree_schema.h>

#include "common.h"
#include "libyang.h"
#include "snabb.h"
#include "transform.h"

int
parse_yang_model(global_ctx_t *ctx) {
	const struct lys_module *module = NULL;
	struct ly_ctx *libyang_ctx = NULL;
	char *schema_content = NULL;
	sr_schema_t *schemas = NULL;
	size_t schema_cnt = 0;
	int rc = SR_ERR_OK;
	int lrc = 0;

	/* TODO get sysrepo yang schema path
	 * will be neede for alarms
	 * */
	libyang_ctx = ly_ctx_new(NULL, LY_CTX_ALLIMPLEMENTED);
	if (NULL == libyang_ctx) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

    /* ietf-softwire-br YANG models depends on ietf-softwire-common */
	if (0 == strcmp("ietf-softwire-br", ctx->yang_model)) {
		rc = sr_get_schema(ctx->sess, "ietf-softwire-common", NULL, NULL, SR_SCHEMA_YIN, &schema_content);
		CHECK_RET(rc, error, "failed sr_get_schema: %s", sr_strerror(rc));

		module = lys_parse_mem(libyang_ctx, schema_content, LYS_IN_YIN);
		if (NULL == module) {
			rc = SR_ERR_INTERNAL;
			goto error;
		}
	}

	rc = sr_get_schema(ctx->sess, ctx->yang_model, NULL, NULL, SR_SCHEMA_YIN, &schema_content);
	CHECK_RET(rc, error, "failed sr_get_schema: %s", sr_strerror(rc));

	module = lys_parse_mem(libyang_ctx, schema_content, LYS_IN_YIN);
	if (NULL == module) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

	/* fetch enbaled features from Sysrepo and enable them in libyang */
	rc = sr_list_schemas(ctx->sess, &schemas, &schema_cnt);
	CHECK_RET(rc, error, "failed sr_list_schemas: %s", sr_strerror(rc));
	for (size_t s = 0; s < schema_cnt; s++) {
		if (0 == strcmp(ctx->yang_model, schemas[s].module_name)){
			for (size_t i = 0; i < schemas[s].enabled_feature_cnt; i++) {
				INF("Enable feature %s in yang model %s", schemas[s].enabled_features[i], ctx->yang_model);
				lrc = lys_features_enable(module, schemas[s].enabled_features[i]);
				if (0 != lrc) {
					ERR("The feature %s is not defined in the yang model %s", schemas[s].enabled_features[i], ctx->yang_model);
				}
			}
		}
	}

	ctx->module = module;

	ctx->libyang_ctx = libyang_ctx;

error:
	if (NULL != schemas && schema_cnt > 0) {
		sr_free_schemas(schemas, schema_cnt);
	}
	if (NULL != schema_content) {
		free(schema_content);
	}
	return rc;
}

void
clear_libyang_ctx(global_ctx_t *ctx) {
    ly_ctx_destroy(ctx->libyang_ctx, NULL);
    INF_MSG("clear libyang context");
}

bool
list_or_container(sr_type_t type) {
    return type == SR_LIST_T || type == SR_CONTAINER_T || type == SR_CONTAINER_PRESENCE_T;
}

/* TODO refactor this */
int
transform_data_to_array(global_ctx_t *ctx, char *xpath, char *data, struct lyd_node **node) {
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

    /* transform xpath to lyd_node's*/
    if (NULL != xpath) {
        sr_xpath_ctx_t state = {0};
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

            /* add key values */
            while(true) {
                char *key, *value, *key_copy;
                /* iterate over key value pairs in xpath */
                key = sr_xpath_next_key_name(NULL, &state);
                if (NULL == key) {
                    break;
                }
                key_copy = strdup(key);
                value = sr_xpath_next_key_value(NULL, &state);
                lyd_new_leaf(parent, ctx->module, key_copy, value);
                free(key_copy);
            }
        }
    }

    i = 0;
    while ((token = strsep(&data, "\n")) != NULL) {
        i++;
        while (*token != '\0') {
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
            parent = parent ? parent->parent : NULL;
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
                parent = parent ? parent->parent : NULL;
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

    /* validate the libyang data nodes */
    if (0 != lyd_validate(&top_parent, LYD_OPT_GET, NULL)) {
        rc = SR_ERR_INTERNAL;
        goto error;
    }

error:
    *node = top_parent;

    return rc;
}
