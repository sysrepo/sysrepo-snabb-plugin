/**
 * @file parse.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief functions for parsing loaded yang model.
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

#include <libyang/libyang.h>
#include <libyang/tree_schema.h>

#include "transform.h"
#include "common.h"
#include "parse.h"

int
parse_yang_model(ctx_t *ctx, sr_session_ctx_t *session) {
	const struct lys_module *module = NULL;
    struct ly_ctx *libyang_ctx = NULL;
	char *schema_content = NULL;
	int rc = SR_ERR_OK;

	/* TODO get sysrepo yang schema path
	 * will be neede for alarms
	 * */
	libyang_ctx = ly_ctx_new(NULL);
	if (NULL == libyang_ctx) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

	rc = sr_get_schema(session, ctx->yang_model, NULL, NULL, SR_SCHEMA_YIN, &schema_content);
	CHECK_RET(rc, error, "failed sr_get_schema: %s", sr_strerror(rc));

	INF("content: %s", schema_content);
	module = lys_parse_mem(libyang_ctx, schema_content, LYS_IN_YIN);
	if (NULL == module) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

	ctx->libyang_ctx = libyang_ctx;

error:
	if (NULL != schema_content) {
		free(schema_content);
	}
	return rc;
}
