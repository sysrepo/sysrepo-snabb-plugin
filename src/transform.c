/**
 * @file transofrm.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief A bridge for connecting snabb and sysrepo data plane.
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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/plugins.h>

#include "common.h"
#include "transform.h"

char *concat(const char *s1, const char *s2) {
	char *result = NULL;

	result = malloc(strlen(s1)+strlen(s2)+1);

	strcpy(result, s1);
	strcat(result, s2);

	return result;
}

char *format_message(char *message) {
	char *tmp, *formated = NULL;
	char snum[7];

	int len = strlen(message);
	//TODO error handling
	snprintf(snum, 7, "%d", len);

	tmp = concat(&snum[0], "\n");
	formated = concat(tmp, message);
	free(tmp);

	return formated;
}

void socket_close(ctx_t *ctx) {
	if (-1 != ctx->socket_fd) {
		close(ctx->socket_fd);
	}
}

int socket_connect(ctx_t *ctx) {
	struct sockaddr_un address;
	int  rc;

	INF("connect to snabb socket /run/snabb/%d/config-leader-socket", ctx->pid);

	ctx->socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (ctx->socket_fd < 0) {
		WRN("failed to create UNIX socket: %d", ctx->socket_fd);
		goto error;
	}

	snprintf(ctx->socket_path, UNIX_PATH_MAX, "/run/snabb/%d/config-leader-socket", ctx->pid);

	/* start with a clean address structure */
	memset(&address, 0, sizeof(struct sockaddr_un));

	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, UNIX_PATH_MAX, "/run/snabb/%d/config-leader-socket", ctx->pid);

	rc = connect(ctx->socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un));
	CHECK_RET_MSG(rc, error, "failed connection to snabb socket");

	return SR_ERR_OK;
error:
	socket_close(ctx);
	return SR_ERR_INTERNAL;
}

int socket_send(ctx_t *ctx, char *message) {
	char buffer[SNABB_MESSAGE_MAX];
	int  nbytes;

	char *formated = format_message(message);
	nbytes = snprintf(buffer, SNABB_MESSAGE_MAX, "%s", formated);

	nbytes = write(ctx->socket_fd, buffer, nbytes);
	if ((int) strlen(formated) != (int) nbytes) {
		ERR("Failed to write full messaget o server: written %d, expected %d", (int) nbytes, (int) strlen(formated));
		goto error;
	}
	free(formated);

	nbytes = read(ctx->socket_fd, ch, SNABB_SOCKET_MAX);
	ch[nbytes] = 0;

	printf("MESSAGE FROM SERVER: %s\n", ch);
	ch[0] = 0;

	/* based on the leader.lua file */

	return SR_ERR_OK;
error:
	return SR_ERR_INTERNAL;
}
