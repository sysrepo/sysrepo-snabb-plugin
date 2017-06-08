/**
 * @file snabb.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief Plugin for sysrepo datastore for management of snabb switch.
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
#include <syslog.h>

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/plugins.h>

#include "snabb.h"
#include "parse.h"
#include "common.h"
#include "transform.h"

#define BUFSIZE 256

const char *YANG_MODEL = "snabb-softwire-v1";

static int
apply_change(sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val) {
	int rc = SR_ERR_OK;

	switch(op) {
	case SR_OP_CREATED:
		if (NULL != new_val) {
			printf("CREATED: ");
			sr_print_val(new_val);
			rc = add_action(new_val, op);
			CHECK_RET(rc, error, "failed to add operation: %s", sr_strerror(rc));
		}
		break;
	case SR_OP_DELETED:
		if (NULL != old_val) {
			printf("DELETED: ");
			sr_print_val(old_val);
			rc = add_action(old_val, op);
			CHECK_RET(rc, error, "failed to add operation: %s", sr_strerror(rc));
		}
	break;
	case SR_OP_MODIFIED:
		if (NULL != old_val && NULL != new_val) {
			printf("MODIFIED: ");
			printf("old value ");
			sr_print_val(old_val);
			printf("new value ");
			rc = add_action(new_val, op);
			CHECK_RET(rc, error, "failed to add operation: %s", sr_strerror(rc));
		}
	break;
	case SR_OP_MOVED:
		if (NULL != new_val) {
			//TODO implement this
			printf("MOVED: %s after %s", new_val->xpath, NULL != old_val ? old_val->xpath : NULL);
		}
	break;
	}

	return rc;
error:
	//TODO free list
	return rc;
}

static int
get_snabb_pid(const char *fmt, void *ptr) {
	int rc = SR_ERR_OK;
	FILE *fp;
	char buf[BUFSIZE];

	if ((fp = popen("exec bash -c 'snabb ps | head -n1 | cut -d \" \" -f1'", "r")) == NULL) {
		ERR_MSG("Error opening pipe!");
		return SR_ERR_INTERNAL;
	}

	if (fgets(buf, BUFSIZE, fp) != NULL) {
		sscanf(buf, fmt, ptr);
	} else {
		ERR_MSG("Error running 'snabb ps' command.");
		return SR_ERR_INTERNAL;
	}

	rc = pclose(fp);

	return rc;
}

static int
parse_config(sr_session_ctx_t *session, const char *module_name, ctx_t *ctx) {
	sr_change_iter_t *it = NULL;
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;
	char xpath[XPATH_MAX_LEN] = {0,};

	snprintf(xpath, XPATH_MAX_LEN, "/%s:*", module_name);

	rc = sr_get_changes_iter(session, xpath , &it);
	if (SR_ERR_OK != rc) {
		printf("Get changes iter failed for xpath %s", xpath);
		goto error;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it, &oper, &old_value, &new_value))) {
		rc = apply_change(oper, old_value, new_value);
		sr_free_val(old_value);
		sr_free_val(new_value);
		CHECK_RET(rc, error, "failed to add operation: %s", sr_strerror(rc));
	}

	action_t *tmp = NULL;
	LIST_FOREACH(tmp, &head, actions) {
		INF("Add liste entry: xpath: %s, value: %s, op: %d", tmp->xpath, tmp->value, tmp->op);
	}

	rc = apply_all_actions(ctx);
	CHECK_RET(rc, error, "failed execute all operations: %s", sr_strerror(rc));

error:
	if (NULL != it) {
		sr_free_change_iter(it);
	}
	return rc;
}


static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
	int rc = SR_ERR_OK;
	ctx_t *ctx = private_ctx;
	INF("%s configuration has changed.", ctx->yang_model);

	ctx->sess = session;
	if (true == ctx->skip) {
		ctx->skip = false;
		return rc;
	}

	if (SR_EV_APPLY == event) {
		/* copy running datastore to startup */

		rc = sr_copy_config(ctx->startup_sess, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
		if (SR_ERR_OK != rc) {
			WRN_MSG("Failed to copy running datastore to startup");
			/* TODO handle this error in snabb
			 * there should be no errors at this stage of the process
			 * */
			return rc;
		}
		return SR_ERR_OK;
	}

	rc = parse_config(session, module_name, ctx);
	CHECK_RET(rc, error, "failed to apply sysrepo changes to snabb: %s", sr_strerror(rc));

error:
	return rc;
}

static int
state_data_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;

	ctx_t *ctx = private_ctx;
	rc = snabb_state_data_to_sysrepo(ctx, (char *) xpath, values, values_cnt);
	CHECK_RET(rc, error, "failed to load state data: %s", sr_strerror(rc));

error:
    return rc;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx) {
	sr_subscription_ctx_t *subscription = NULL;
	char xpath[XPATH_MAX_LEN] = {0};
	int rc = SR_ERR_OK;
	ctx_t *ctx = NULL;
	int32_t pid = 0;

	ctx = malloc(sizeof *ctx);
	ctx->yang_model = YANG_MODEL;
	ctx->libyang_ctx = NULL;
	ctx->sub = subscription;
	ctx->sess = session;
	ctx->running_sess = session;
	ctx->socket_fd = -1;
	ctx->skip = false;

	snprintf(xpath, XPATH_MAX_LEN, "/%s:softwire-state", ctx->yang_model);

	/* get snabb process ID */
	rc = get_snabb_pid("%d", &pid);
	CHECK_RET_MSG(rc, error, "failed to get pid from snabb");

	ctx->pid = pid;
	INF("snabb pid is %d", pid);

	rc = sr_module_change_subscribe(session, ctx->yang_model, module_change_cb, ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->sub);
	CHECK_RET(rc, error, "failed sr_module_change_subscribe: %s", sr_strerror(rc));

	INF("%s plugin initialized successfully", ctx->yang_model);

	/* set subscription as our private context */
	*private_ctx = ctx;

	/* connect to snabb UNIX socket */
	rc = socket_connect(ctx);
	CHECK_RET(rc, error, "failed socket_connect: %s", sr_strerror(rc));

	/* initialize action list */
	LIST_HEAD(listhead, action_s) head;
	LIST_INIT(&head);

	/* parse the yang model */
	INF("Parse yang model %s with libyang", ctx->yang_model);
	rc = parse_yang_model(ctx);
	CHECK_RET(rc, error, "failed to parse yang model with libyang: %s", sr_strerror(rc));

	/* load the startup datastore */
	INF_MSG("load sysrepo startup datastore");
	rc = load_startup_datastore(ctx);
	CHECK_RET(rc, error, "failed to load startup datastore: %s", sr_strerror(rc));

	INF_MSG("sync sysrepo and snabb data");
	rc = sync_datastores(ctx);
	CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));

	rc = sr_dp_get_items_subscribe(session, xpath, state_data_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
	CHECK_RET(rc, error, "failed sr_dp_get_items_subscribe: %s", sr_strerror(rc));

	return SR_ERR_OK;

error:
	ERR("%s plugin initialization failed: %s", ctx->yang_model, sr_strerror(rc));
	if (NULL != ctx->sub) {
		sr_unsubscribe(session, ctx->sub);
	}
	if (NULL != ctx) {
		free(ctx);
	}
	return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx) {
	if (NULL == session || NULL == private_ctx) {
		return;
	}
	/* subscription was set as our private context */
	ctx_t *ctx = private_ctx;

	clear_context(ctx);
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void
sigint_handler(__attribute__((unused)) int signum) {
	INF_MSG("Sigint called, exiting...");
	exit_application = 1;
}

int
main() {
	INF_MSG("Plugin application mode initialized");
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_ctx = NULL;
	int rc = SR_ERR_OK;

	/* connect to sysrepo */
	rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &connection);
	CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

	/* start session */
	rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
	CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

	rc = sr_plugin_init_cb(session, &private_ctx);
	CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);  /* or do some more useful work... */
	}

	sr_plugin_cleanup_cb(session, private_ctx);
cleanup:
	if (NULL != session) {
		sr_session_stop(session);
	}
	if (NULL != connection) {
		sr_disconnect(connection);
	}
}
#endif
