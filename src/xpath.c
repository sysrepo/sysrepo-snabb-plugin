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

#include "common.h"
#include "transform.h"
#include "xpath.h"

/* transform xpath to snabb compatible format
 * 1) remove yang model from xpath
 * 2) remove "'" from the key value
 * 3) remove key's from the last node for set/add operation
 */
int
format_xpath(action_t *action) {
	char *xpath = NULL, *node = NULL, *tmp = NULL;
	sr_xpath_ctx_t *xpath_ctx;
	int rc = SR_ERR_OK;

	xpath_ctx = malloc(sizeof(xpath_ctx));
	if (NULL == xpath_ctx) {
		rc = SR_ERR_NOMEM;
		goto error;
	}		

	/* snabb xpath is always smaller than sysrepo's xpath */
	xpath = malloc(sizeof(xpath) * strlen(action->xpath));
	if (NULL == xpath) {
		rc = SR_ERR_NOMEM;
		goto error;
	}		

	tmp = malloc(sizeof(tmp) * strlen(action->xpath));
	if (NULL == tmp) {
		rc = SR_ERR_NOMEM;
		goto error;
	}		

	node = sr_xpath_next_node(action->xpath, xpath_ctx);
	if (NULL == node) {
		rc = SR_ERR_INTERNAL;
		goto error;
	}

	while(true) {
		strcat(xpath, "/");
		if (NULL != node) {
			strcat(xpath, node);
		}

		while(true) {
			char *key, *value;
			key = sr_xpath_next_key_name(NULL, xpath_ctx);
			value = sr_xpath_next_key_value(NULL, xpath_ctx);
			if (NULL == key) {
				break;
			}
			strcat(tmp,"[");
			strcat(tmp,key);
			strcat(tmp,"=");
			strcat(tmp,value);
			strcat(tmp,"]");
		}
		node = sr_xpath_next_node(NULL, xpath_ctx);
		if (NULL == node) {
			break;
		}
		strcat(xpath, tmp);
	}
	action->snabb_xpath = strdup(xpath);

error:
	if (NULL == tmp) {
		free(tmp);
	}
	if (NULL == xpath) {
		free(xpath);
	}
	if (NULL == xpath_ctx) {
		free(xpath_ctx);
	}
	return rc;
}
