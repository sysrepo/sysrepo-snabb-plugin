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
  }

  module = (struct lys_module *)ly_ctx_get_module(libyang_ctx, ctx->yang_model,
                                                  NULL);
  CHECK_NULL_MSG(module, &rc, cleanup, "ly_ctx_get_module error");

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

/* TODO refactor this */
int transform_data_to_array(global_ctx_t *ctx, char *xpath, char *data,
                            struct lyd_node **node) {
  int rc = SR_ERR_OK;
  char *token = NULL, *tmp = NULL, *last = NULL;
  int i = 0, counter = 0;
  struct lyd_node *parent = NULL, *top_parent = NULL, *check = NULL;
  LY_ERR ly_err = LY_SUCCESS;

  /* replace escaped new lines */
  for (i = 0; i < (int)strlen(data); i++) {
    if ('\\' == data[i] && 'n' == data[i + 1]) {
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

      ly_err = lyd_new_inner(parent, ctx->module, xpath_elem, false, &parent);
      CHECK_LY_RET_MSG(ly_err, error, "failed lyd_new_path");
      if (LY_SUCCESS != ly_err) {
        rc = SR_ERR_INTERNAL;
        goto error;
      }

      if (NULL == top_parent) {
        top_parent = parent;
      }

      /* add key values */
      while (true) {
        char *key, *value, *key_copy;
        /* iterate over key value pairs in xpath */
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL == key) {
          break;
        }
        key_copy = strdup(key);
        value = sr_xpath_next_key_value(NULL, &state);

        ly_err = lyd_new_term(parent, ctx->module, key_copy, value, false, NULL);
        if (LY_SUCCESS != ly_err) {
          rc = SR_ERR_INTERNAL;
          goto error;
        }

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
      parent = (struct lyd_node *) (parent ? parent->parent : NULL);
      continue;
    } else {
      last = &token[strlen(token) - 1];
      tmp = strchr(token, ' ');
      *tmp = '\0';
      tmp++;
      if ('{' == *last) {
        /* only list/container's have the last element '{' */
        /* TODO check NULl */
        ly_err = lyd_new_inner(parent, ctx->module, token, false, &parent);
        if (LY_SUCCESS != ly_err) {
          rc = SR_ERR_INTERNAL;
          goto error;
        }
        if (NULL == top_parent) {
          top_parent = parent;
        }
        continue;
      } else if ('}' == *last) {
        /* when list/container are closed set new parent */
        parent = (struct lyd_node *) (parent ? parent->parent : NULL);
        continue;
      } else {
        *last = '\0';
        /* add leafs */
        /* TODO check NULl */
        ly_err = lyd_new_term(parent, ctx->module, token, tmp, false, &check);
        if (LY_SUCCESS != ly_err) {
          rc = SR_ERR_INTERNAL;
          goto error;
        }
      }
    }
  }

  /* validate the libyang data nodes */
  if (LY_SUCCESS != lyd_validate_all(&top_parent, NULL, LYD_VALIDATE_PRESENT, NULL)) {
    rc = SR_ERR_INTERNAL;
    goto error;
  }

error:
  *node = top_parent;

  return rc;
}
