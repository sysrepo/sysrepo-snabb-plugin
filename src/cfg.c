/**
 * @file xpath.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief application to handle config file data.
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

#include "cfg.h"
#include "../cfg_parse/cfg_parse.h"

const char *config = "/etc/sysrepo_snabb/config.ini";

cfg_ctx *init_cfg_file() {
	cfg_ctx *ctx = NULL;
	int rc = 0;

	ctx = malloc(sizeof(cfg_ctx));
	if (NULL == ctx) {
		return NULL;
	}
	ctx->cfg = NULL;

	/* Initialize config struct */
	ctx->cfg = cfg_init();

	/* load config file */
	rc = cfg_load(ctx->cfg, config);
	if (rc < 0) {
		fprintf(stderr,"Unable to load cfg.ini\n");
		goto error;
	}

	/* get config data */
	/* Retrieve the value for key INFINITY, and print */
	const char *sync_startup = cfg_get(ctx->cfg,"SYNC_STARTUP");
	if (sync_startup == NULL) {
		goto error;
	}

	if (0 == strncmp("TRUE", sync_startup, strlen(sync_startup))) {
		ctx->sync_startup = true;
	} else if (0 == strncmp("FALSE", sync_startup, strlen(sync_startup))) {
		ctx->sync_startup = false;
	} else {
		goto error;
	}

	return ctx;
error:
	if (ctx != NULL) {
		if (ctx->cfg != NULL) {
			cfg_free(ctx->cfg);
		}
		free(ctx);
	}
	return NULL;
}

void clean_cfg(cfg_ctx *ctx) {
	if (ctx != NULL) {
		if (ctx->cfg != NULL) {
			cfg_free(ctx->cfg);
		}
		free(ctx);
	}
}
