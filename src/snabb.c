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

#define BUFSIZE 256

const char *YANG_MODEL = "snabb-softwire-v1";

static int
get_snabb_pid(const char *fmt, void *ptr)
{
	int rc = 0;
	FILE *fp;
	char buf[BUFSIZE];

	if ((fp = popen("exec bash -c 'snabb ps | head -n1 | cut -d \" \" -f1'", "r")) == NULL) {
		ERR_MSG("Error opening pipe!");
		return -1;
	}

	if (fgets(buf, BUFSIZE, fp) != NULL) {
		sscanf(buf, fmt, ptr);
	} else {
		ERR_MSG("Error running 'snabb ps' command.");
	}

	rc = pclose(fp);

	return rc;
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
	INF("%s configuration has changed.", YANG_MODEL);

	return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
	sr_subscription_ctx_t *subscription = NULL;
	int rc = SR_ERR_OK;

	/* get snabb process ID */
	int32_t pid = 0;
	rc = get_snabb_pid("%d", &pid);
	if (0 != rc) {
		goto error;
	}

	rc = sr_module_change_subscribe(session, YANG_MODEL, module_change_cb, NULL,
			0, SR_SUBSCR_DEFAULT, &subscription);
	if (SR_ERR_OK != rc) {
		goto error;
	}

	INF("%s plugin initialized successfully", YANG_MODEL);

	/* set subscription as our private context */
	*private_ctx = subscription;

	return SR_ERR_OK;

error:
	ERR("%s plugin initialization failed: %s\n", YANG_MODEL, sr_strerror(rc));
	sr_unsubscribe(session, subscription);
	return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
	/* subscription was set as our private context */
	sr_unsubscribe(session, private_ctx);

	INF("%s plugin cleanup finished.", YANG_MODEL);
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void
sigint_handler(int signum)
{
	INF_MSG("Sigint called, exiting...");
	exit_application = 1;
}

int
main(int argc, char *argv[])
{
	INF_MSG("Plugin application mode initialized");
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	int rc = SR_ERR_OK;

	/* connect to sysrepo */
	rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &connection);
	if (SR_ERR_OK != rc) {
		ERR("Error by sr_connect: %s\n", sr_strerror(rc));
		goto cleanup;
	}

	/* start session */
	rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
	if (SR_ERR_OK != rc) {
		ERR("Error by sr_session_start: %s\n", sr_strerror(rc));
		goto cleanup;
	}

	void *private_ctx = NULL;
	sr_plugin_init_cb(session, &private_ctx);

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);  /* or do some more useful work... */
	}

cleanup:
	sr_plugin_cleanup_cb(session, private_ctx);
}
#endif
