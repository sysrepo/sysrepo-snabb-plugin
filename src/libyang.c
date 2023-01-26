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
#include <stdbool.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include <libyang/libyang.h>
#include <libyang/tree_data.h>
#include <libyang/tree_schema.h>

#include "common.h"
#include "libyang.h"
#include "snabb.h"
#include "transform.h"

int parse_yang_model(global_ctx_t *ctx) {
  sr_conn_ctx_t *connection = NULL;
  struct lys_module *module = NULL;
  const struct ly_ctx *libyang_ctx = NULL;
  int rc = SR_ERR_OK;

  /* TODO get sysrepo yang schema path
   * will be neede for alarms
   * */
  connection = sr_session_get_connection(ctx->sess);
  CHECK_NULL_MSG(connection, &rc, cleanup, "sr_session_get_connection error");

  libyang_ctx = sr_acquire_context(connection);
  CHECK_NULL_MSG(libyang_ctx, &rc, cleanup, "sr_get_context error");

  /* ietf-softwire-br YANG models depends on ietf-softwire-common */
  if (0 == strcmp("ietf-softwire-br", ctx->yang_model)) {
    module = (struct lys_module *)ly_ctx_get_module(
        libyang_ctx, "ietf-softwire-common", NULL);
    CHECK_NULL_MSG(module, &rc, cleanup, "ly_ctx_get_module error");
  /* snabb-softwire-v2 */
  } else if (0 == strcmp("snabb-softwire-v2", ctx->yang_model)) {
    module = (struct lys_module *)ly_ctx_get_module(
        libyang_ctx, ctx->yang_model, "2021-07-13");
    CHECK_NULL_MSG(module, &rc, cleanup, "ly_ctx_get_module error");
  /* snabb-softwire-v3 */
  } else if (0 == strcmp("snabb-softwire-v3", ctx->yang_model)) {
    module = (struct lys_module *)ly_ctx_get_module(
        libyang_ctx, ctx->yang_model, "2021-11-08");
    CHECK_NULL_MSG(module, &rc, cleanup, "ly_ctx_get_module error");
  } else {
    rc = SR_ERR_NOT_FOUND;
    ERR("unsupported model: %s", ctx->yang_model);
    goto cleanup;
  }


  ctx->module = module;

  ctx->libyang_ctx = (struct ly_ctx *)libyang_ctx;

cleanup:
  return rc;
}
/*
void clear_libyang_ctx(global_ctx_t *ctx) {
  ly_ctx_destroy(ctx->libyang_ctx, NULL);
  INF_MSG("clear libyang context");
}
*/
bool list_or_container(sr_val_type_t type) {
  return type == SR_LIST_T || type == SR_CONTAINER_T ||
         type == SR_CONTAINER_PRESENCE_T;
}

bool is_list_instance(char *node_name) {
  /* Check if a node is a list from the snabb-softwire-v3 YANG module. */
  if (0 == strcmp(node_name, "softwire") ||
      0 == strcmp(node_name, "instance") ||
      0 == strcmp(node_name, "queue")) {
    return true;
  }
  return false;
}

bool found_all_list_keys(char *list_name, char *list_keys) {
  /* list_keys should look like this: "[key1='value1'][key2='value2']..." */
  if (0 == strcmp(list_name, "softwire")) {
    if (strstr(list_keys, "ipv4") && strstr(list_keys, "psid")) {
      return true;
    }
  } else if (0 == strcmp(list_name, "instance")) {
    if (strstr(list_keys, "device")) {
      return true;
    }
  } else if(0 == strcmp(list_name, "queue")) {
    if (strstr(list_keys, "id")) {
      return true;
    }
  }
  return false;
}

/*
 * Transform configuration or state data received over a snabb socket
 * to a libyang data tree with *top_parent as the root node.
 */
int transform_snabb_data_to_tree(global_ctx_t *ctx, char *xpath, char *data,
                                 struct lyd_node **top_parent, bool state_data) {
  int rc = SR_ERR_OK;
  int i = 0, len = 0;
  struct lyd_node *parent = NULL;
  LY_ERR ly_err = LY_SUCCESS;
  uint32_t validation_flags = 0;

  if (NULL == data) {
    ERR_MSG("transform_data_to_array2: data == NULL");
    return -1;
  }

  /* replace escaped new lines */
  len = (int) strlen(data);
  for (i = 0; i < len; i++) {
    if ('\\' == data[i] && 'n' == data[i + 1]) {
      data[i] = '\n';
      i++;
      data[i] = ' ';
    }
  }

  data = strstr(data, "\"") + 1; /* actual config data starts after " */

  if (NULL == data) {
    ERR_MSG("config/state data not present in given data string");
    return -1;
  }

  if (NULL != *top_parent) {
    parent = *top_parent;
  }

  bool searching_for_list_keys = false;
  char *list_name = NULL;
  /* for storing key predicate for list instance definition,
   * eg. [key1='value1'][key2='value2'] */
  char list_keys[256] = {0};

  /* transform config/state data lines to tree nodes */
  char *line = NULL;
  while ((line = strsep(&data, "\n")) != NULL) {
    if (strstr(line, "\"")) {
      /* reached end of config data */
      goto validate;
    }

    /* skip whitespace on the start of the line */
    while (' ' == *line) {
      line++;
    }
    if (0 == strlen(line)) {
      continue;
    }
    char line_end = line[strlen(line) - 1];
    char *line_remaining = line;
    char *node_name = strsep(&line_remaining, " ");

    switch (line_end) {
      case '{': { /* current config line defines a container or list-instance */
        if (is_list_instance(node_name)) {
          /* To create a list instance we need to iterate over upcoming
           * lines until we find the value of all list keys for this instance.
           * Assumption: list nodes are always ordered so that list keys are on top. */
          list_name = node_name;
          searching_for_list_keys = true;
        } else {
          /* add container node */
          ly_err = lyd_new_inner(parent, ctx->module, node_name, false, &parent);
          if (LY_SUCCESS != ly_err) {
            ERR("lyd_new_inner error (%d)", ly_err);
            rc = SR_ERR_INTERNAL;
            goto error;
          }
          if (NULL == *top_parent) {
            *top_parent = parent;
          }
        }
        break;
      }
      case '}': /* current line is the end of a container/list definition */
        parent = (struct lyd_node *) (parent ? parent->parent : NULL);
        break;
      case ';': { /* current line defines a leaf node */
        char *leaf_value = strsep(&line_remaining, " ");
        leaf_value[strlen(leaf_value) - 1] = '\0'; /* set ';' to '\0' */

        if (searching_for_list_keys) {
          /* append list key */
          char key_predicate[64] = {0};
          snprintf(key_predicate, 64, "[%s='%s']", node_name, leaf_value);
          strncat(list_keys, key_predicate, sizeof(list_keys) - strlen(list_keys) - 1);
          if (found_all_list_keys(list_name, list_keys)) {
            /* create the list instance */
            ly_err = lyd_new_list2(parent, ctx->module, list_name, list_keys, false, &parent);
            if (LY_SUCCESS != ly_err) {
              ERR("lyd_new_list2 error (%d)", ly_err);
              rc = SR_ERR_INTERNAL;
              goto error;
            }
            searching_for_list_keys = false;
            list_name = NULL;
            memset(list_keys, 0, sizeof(list_keys));
          }
        } else {
          /* create leaf node */
          ly_err = lyd_new_term(parent, ctx->module, node_name, leaf_value, false, NULL);
          if (LY_SUCCESS != ly_err) {
            ERR("lyd_new_term error (%d)", ly_err);
            rc = SR_ERR_INTERNAL;
            goto error;
          }
        }
        break;
      }
      default:
        /* ignore line */
        break;
    }
  }

validate:
  /* validate only if config data is present (lyd_validate_all requires config data) */
  if (!state_data) {
    validation_flags = LYD_VALIDATE_PRESENT | LYD_VALIDATE_NO_STATE;
    ly_err = lyd_validate_all(top_parent, NULL, validation_flags, NULL);
    if (LY_SUCCESS != ly_err) {
      ERR("lyd_validate_all error (%d)", ly_err);
      rc = SR_ERR_INTERNAL;
      goto error;
    }
  }

error:
  return rc;
}
