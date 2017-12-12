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
parse_yang_model(ctx_t *ctx) {
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

	rc = sr_get_schema(ctx->running_sess, ctx->yang_model, NULL, NULL, SR_SCHEMA_YIN, &schema_content);
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
