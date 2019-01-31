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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/plugins.h>
#include <sysrepo/xpath.h>
#include <libyang/libyang.h>
#include <libyang/tree_data.h>
#include <libyang/tree_schema.h>

#include "common.h"
#include "snabb.h"
#include "libyang.h"
#include "transform.h"

//int socket_send(global_ctx_t *ctx, char *message, sb_command_t command, char **response, sr_notif_event_t event, status_t *status);
//int xpath_to_snabb(global_ctx_t *ctx, action_t *action, char **message);
//int sysrepo_to_snabb(global_ctx_t *ctx, action_t *action);

/* transform xpath to snabb compatible format
 * 1) remove yang model from xpath
 * 2) remove "'" from the key value
 */
char *
sr_xpath_to_snabb(char *xpath) {
    char *node = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};
    int rc = SR_ERR_OK;

    /* snabb xpath is always smaller than sysrepo's xpath */
    char *tmp = strdup(xpath);
    int len = strlen(xpath);

    CHECK_NULL_MSG(tmp, &rc, error, "failed to allocate memory");
    *tmp = '\0'; // init xpath string

    node = sr_xpath_next_node(xpath, &state);
    CHECK_NULL_MSG(node, &rc, error, "failed sr_xpath_next_node");

    while(true) {
        strncat(tmp, "/", len);
        if (NULL != node) {
            strncat(tmp, node, len);
        }

        while(true) {
            char *key, *value;
            /* iterate over key value pairs in xpath */
            key = sr_xpath_next_key_name(NULL, &state);
            if (NULL == key) {
                break;
            }
            strncat(tmp, "[", len);
            strncat(tmp, key, len);
            strncat(tmp, "=", len);
            value = sr_xpath_next_key_value(NULL, &state);
            strncat(tmp, value, len);
            strncat(tmp, "]", len);
        }
        /* iterate over nodes in xpath */
        node = sr_xpath_next_node(NULL, &state);

        if (NULL == node) {
            break;
        }
    }

error:
    sr_xpath_recover(&state);
    if (rc == SR_ERR_OK) {
        return tmp;
    } else {
        free(tmp);
        return NULL;
    }
}

/* transform xpath to snabb compatible format
 * 1) remove yang model from xpath
 * 2) remove "'" from the key value
 * 3) remove key's from the last node for add operation
 */
char *
sr_xpath_to_snabb_no_end_keys(char *xpath) {
    char *node = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};
    int rc = SR_ERR_OK;

    /* snabb xpath is always smaller than sysrepo's xpath */
    char *tmp = strdup(xpath);
    int len = strlen(xpath);

    CHECK_NULL_MSG(tmp, &rc, error, "failed to allocate memory");
    *tmp = '\0'; // init xpath string

    node = sr_xpath_next_node(xpath, &state);
    CHECK_NULL_MSG(node, &rc, error, "failed sr_xpath_next_node");

    while(true) {
        strncat(tmp, "/", len);
        if (NULL != node) {
            strncat(tmp, node, len);
        }

        int current_pos = strlen(tmp);
        while(true) {
            char *key, *value;
            /* iterate over key value pairs in xpath */
            key = sr_xpath_next_key_name(NULL, &state);
            if (NULL == key) {
                break;
            }
            strncat(tmp, "[", len);
            strncat(tmp, key, len);
            strncat(tmp, "=", len);
            value = sr_xpath_next_key_value(NULL, &state);
            strncat(tmp, value, len);
            strncat(tmp, "]", len);
        }
        /* iterate over nodes in xpath */
        node = sr_xpath_next_node(NULL, &state);

        if (NULL == node) {
            /* remove keys if they exists in the last node
               when adding list's in snabb you can't have keys in the xpath */
            if (tmp[strlen(tmp) - 1] == ']') {
                tmp[current_pos] = '\0';
            }
            break;
        }
    }

error:
    sr_xpath_recover(&state);
    if (rc == SR_ERR_OK) {
        return tmp;
    } else {
        free(tmp);
        return NULL;
    }
}


void socket_close(global_ctx_t *ctx) {
    if (-1 != ctx->socket_fd) {
        close(ctx->socket_fd);
    }
}

int socket_send(global_ctx_t *ctx, char *input, char **output, bool fetch, bool ignore_error) {
    int rc = SR_ERR_OK;
    int len = 0;
    int nbytes;
    char *buffer = NULL;

    if (NULL == input) {
        return SR_ERR_INTERNAL;
    }

    /* get input length in char* format */
    char str[30];
    sprintf(str, "%d", (int) strlen(input));

    len = (int) strlen(&str[0]) + 1 + (int) strlen(input) + 1;

    buffer = malloc(sizeof(*buffer) * len);
    CHECK_NULL_MSG(buffer, &rc, error, "failed to allocate memory");

    nbytes = snprintf(buffer, len, "%s\n%s", str, input);

    //TODO add timeout check
    nbytes = write(ctx->socket_fd, buffer, nbytes);
    if ((int) strlen(buffer) != (int) nbytes) {
        if (-1 == nbytes) {
            snabb_socket_reconnect(ctx);
            free(buffer);
            //TODO prevent infinit loop
            return socket_send(ctx, input, output, fetch, ignore_error);
        } else {
            ERR("Failed to write full input to server: written %d, expected %d", (int) nbytes, (int) strlen(buffer));
            rc = SR_ERR_INTERNAL;
            goto error;
        }
    }
    free(buffer);
    buffer = NULL;

    nbytes = read(ctx->socket_fd, ch, SNABB_SOCKET_MAX);
    ch[nbytes] = 0;

    /* count new lines */
    int counter = 0;
    for (int i = 0; i < (int) strlen(ch); i++) {
        if ('\n' == ch[i]) {
            counter++;
        }
    }
    /* if it has 5 new lines that means it has 'status' parameter */
    if (0 == nbytes) {
        goto failed;
    } else if (5 == counter) {
        goto failed;
    } else if (!fetch && 18 != nbytes) {
        goto failed;
    } else if (fetch && 0 == nbytes) {
        goto failed;
    } else {
        INF("Operation:\n%s", input);
        INF("Response:\n%s", ch);
    }

    if (fetch) {
        *output = strdup(ch);
    }

    /* set null terminated string at the beggining */
    ch[0] = '\0';

    return SR_ERR_OK;
failed:
    if (ignore_error) {
        rc = SR_ERR_INTERNAL;
        WRN("Operation faild for:\n%s", input);
        WRN("Respons:\n%s", ch);
    }
error:
    if (NULL != buffer) {
        free(buffer);
    }
    return rc;
}

//int double_message_size(char **message, int *len) {
//    int rc = SR_ERR_OK;
//    char *tmp = NULL;
//
//    *len = *len * 2;
//    tmp = (char *) realloc(*message, (*len));
//    CHECK_NULL_MSG(tmp, &rc, error, "failed to allocate memory");
//
//    *message = tmp;
//
//error:
//    return rc;
//}
//
//int fill_list(sr_node_t *tree, char **message, int *len) {
//    int rc = SR_ERR_OK;
//
//    if (NULL == tree) {
//        return rc;
//    }
//
//    while(true) {
//        if (*len < XPATH_MAX_LEN + (int) strlen(*message)) {
//            rc = double_message_size(message, len);
//            CHECK_RET(rc, cleanup, "failed to double the buffer size: %s", sr_strerror(rc));
//        }
//        if (NULL == tree) {
//            break;
//        } else if (list_or_container(tree->type)) {
//            //TODO check for error
//            strncat(*message, tree->name, *len);
//            strncat(*message, " { ", *len);
//            rc = fill_list(tree->first_child, message, len);
//            CHECK_RET(rc, cleanup, "failed fill_list: %s", sr_strerror(rc));
//            strncat(*message, " } ", *len);
//        } else {
//            //TODO check for error
//            strncat(*message, tree->name, *len);
//            strncat(*message, " ", *len);
//            char *value = sr_val_to_str((sr_val_t *) tree);
//            strncat(*message, value, *len);
//            free(value);
//            strncat(*message, "; ", *len);
//        }
//        tree = tree->next;
//    }
//
//cleanup:
//    return rc;
//}
//
//int
//xpath_to_snabb(global_ctx_t *ctx, action_t *action, char **message) {
//    int rc = SR_ERR_OK;
//    int len = SNABB_MESSAGE_MAX;
//    sr_node_t *trees = NULL;
//
//    *message = malloc(sizeof(**message) * len);
//    CHECK_NULL_MSG(*message, &rc, error, "failed to allocate memory");
//
//    *message[0] = '\0';
//
//    long unsigned int tree_cnt = 0;
//    rc = sr_get_subtrees(ctx->sess, action->xpath, SR_GET_SUBTREE_DEFAULT, &trees, &tree_cnt);
//    if (SR_ERR_NOT_FOUND == rc && SR_EV_ABORT == action->event) {
//        INF("No items found in sysrepo datastore for xpath: %s", action->xpath);
//        return SR_ERR_OK;
//    }
//    CHECK_RET(rc, error, "failed sr_get_subtrees: %s", sr_strerror(rc));
//
//    if (1 == tree_cnt) {
//        if (true == list_or_container(trees[0].type)) {
//            if (SR_LIST_T == trees[0].type) {
//                strncat(*message, " { ", len);
//            }
//            rc = fill_list(trees->first_child, message, &len);
//            CHECK_RET(rc, error, "failed to create snabb configuration data: %s", sr_strerror(rc));
//            if (SR_LIST_T == trees[0].type) {
//                strncat(*message, " } ", len);
//            }
//        } else {
//            char *value = sr_val_to_str((sr_val_t *) &trees[0]);
//            strncat(*message, trees[0].name, len);
//            strncat(*message, " ", len);
//            strncat(*message, value, len);
//            strncat(*message, ";", len);
//            free(value);
//        }
//    } else {
//        for (int i = 0; i < (int) tree_cnt; i++) {
//            rc = fill_list(&trees[i], message, &len);
//            CHECK_RET(rc, error, "failed to create snabb configuration data: %s", sr_strerror(rc));
//        }
//    }
//
//    sr_free_trees(trees, tree_cnt);
//    return rc;
//error:
//    if (NULL != *message) {
//        free(*message);
//    }
//    if (NULL != trees) {
//        sr_free_trees(trees, tree_cnt);
//    }
//    return rc;
//}
//
//int
//sysrepo_to_snabb(global_ctx_t *ctx, action_t *action) {
//    sb_command_t command;
//    char *message = NULL;
//    int  rc = SR_ERR_OK;
//
//    char *tmp = NULL;
//    char **value = &tmp;
//
//    /* translate sysrepo operation to snabb command */
//    switch(action->op) {
//    case SR_OP_MODIFIED:
//        //rc = format_xpath(action);
//        CHECK_RET(rc, error, "failed to format xpath: %s", sr_strerror(rc));
//
//        message = malloc(sizeof(*message) * (SNABB_MESSAGE_MAX + strlen(action->snabb_xpath) + strlen(ctx->yang_model)));
//        CHECK_NULL_MSG(message, &rc, error, "failed to allocate memory");
//
//        snprintf(message, SNABB_MESSAGE_MAX, "set-config {path '%s'; config '%s'; schema %s;}", action->snabb_xpath, action->value, ctx->yang_model);
//        command = SB_SET;
//        break;
//    case SR_OP_CREATED:
//        rc = xpath_to_snabb(ctx, action, value);
//        CHECK_RET(rc, error, "failed xpath_to_snabb: %s", sr_strerror(rc));
//        /* edge case, deleting all of leaf-list entries
//         * check if value is empty string ""
//         * and parent_type is LYS_LEAFLIST
//         */
//#ifdef LEAFLIST
//        if (LYS_LEAFLIST == action->yang_type && 0 == strlen(*value)) {
//            action->yang_type = LYS_UNKNOWN;
//        }
//#endif
//        //rc = format_xpath(action);
//
//        CHECK_RET(rc, error, "failed to format xpath: %s", sr_strerror(rc));
//
//        int len = SNABB_MESSAGE_MAX + (int) strlen(action->snabb_xpath) + strlen(*value) + (int) strlen(ctx->yang_model);
//        message = malloc(sizeof(*message) * len);
//        CHECK_NULL_MSG(message, &rc, error, "failed to allocate memory");
//
//        if (action->type == SR_LIST_T) {
//            snprintf(message, len, "add-config {path '%s'; config '%s'; schema %s;}", action->snabb_xpath, *value, ctx->yang_model);
//        } else {
//            snprintf(message, len, "set-config {path '%s'; config '%s'; schema %s;}", action->snabb_xpath, *value, ctx->yang_model);
//        }
//        free(*value);
//        command = SB_ADD;
//        break;
//    case SR_OP_DELETED:
//        //rc = format_xpath(action);
//        CHECK_RET(rc, error, "failed to format xpath: %s", sr_strerror(rc));
//
//        message = malloc(sizeof(*message) * (SNABB_MESSAGE_MAX + strlen(action->snabb_xpath) + strlen(ctx->yang_model)));
//        CHECK_NULL_MSG(message, &rc, error, "failed to allocate memory");
//
//        snprintf(message, SNABB_MESSAGE_MAX, "remove-config {path '%s'; schema %s;}", action->snabb_xpath, ctx->yang_model);
//        command = SB_REMOVE;
//        break;
//    default:
//        command = SB_SET;
//    }
//
//    /* send to socket */
//    INF_MSG("send to socket");
//    rc = socket_send(ctx, message, command, NULL, action->event, &action->status);
//    CHECK_RET(rc, error, "failed to send message to snabb socket: %s", sr_strerror(rc));
//
//error:
//    if (NULL != message) {
//        free(message);
//    }
//    return rc;
//}

int
snabb_state_data_to_sysrepo(global_ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt) {
    int rc = SR_ERR_OK;
    //TODO calculate size
    char message[SNABB_MESSAGE_MAX] = {0};
    char *response = NULL;
    struct lyd_node *root = NULL;
    int cnt = 0;

    CHECK_RET(rc, error, "failed to format xpath: %s", sr_strerror(rc));
    char *snabb_xpath = sr_xpath_to_snabb(xpath);
    snprintf(message, SNABB_MESSAGE_MAX, "get-state {path '%s'; schema %s;}", snabb_xpath, ctx->yang_model);
    free(snabb_xpath);

    /* send to socket */
    INF_MSG("send to socket");
    rc = socket_send(ctx, message, &response, true, false);
    CHECK_RET(rc, error, "failed to send message to snabb socket: %s", sr_strerror(rc));

    rc = transform_data_to_array(ctx, xpath, response, &root);
    CHECK_RET(rc, error, "failed parse snabb data in libyang: %s", sr_strerror(rc));

    const struct lyd_node *node = NULL, *next = NULL;
    LY_TREE_DFS_BEGIN(root, next, node) {
        if (LYS_LEAF == node->schema->nodetype || LYS_LEAFLIST == node->schema->nodetype) {
            cnt++;
        }
        LY_TREE_DFS_END(root, next, node);
    }

    sr_val_t *v = NULL;
    rc = sr_new_values(cnt, &v);
    CHECK_RET(rc, error, "failed sr_new_values: %s", sr_strerror(rc));

    int i = 0;
    LY_TREE_DFS_BEGIN(root, next, node) {
        if (LYS_LEAF == node->schema->nodetype || LYS_LEAFLIST == node->schema->nodetype) {
            struct lyd_node_leaf_list *leaf = (struct lyd_node_leaf_list *) node;
            char *path = lyd_path(node);
            CHECK_NULL_MSG(path, &rc, error, "failed to allocate memory");

            rc = sr_val_set_xpath(&v[i], path);
            free(path);
            CHECK_RET(rc, error, "failed sr_val_set_xpath: %s", sr_strerror(rc));

            //TODO replace with sr_print_val
            rc = sr_val_set_str_data(&v[i], leaf->schema->flags, leaf->value_str);
            CHECK_RET(rc, error, "failed to set value: %s", sr_strerror(rc));

            i++;
        }
        LY_TREE_DFS_END(root, next, node);
    }

    *values = v;
    *values_cnt = cnt;

error:
    /* free lyd_node */
    if (NULL != root) {
        lyd_free(root);
    }
    if (NULL != response) {
        free(response);
    }
    return rc;
}

int
libyang_data_to_sysrepo(sr_session_ctx_t *session, struct lyd_node *root) {
    const struct lyd_node *node = NULL, *next = NULL;
    char *xpath = NULL;
    int rc = SR_ERR_OK;

    LY_TREE_DFS_BEGIN(root, next, node) {
        if (LYS_LEAF == node->schema->nodetype || LYS_LEAFLIST == node->schema->nodetype) {
            struct lyd_node_leaf_list *leaf = (struct lyd_node_leaf_list *) node;
            /* skip key nodes, sysrepo will show error messages in the logs */
            bool skip = false;
            if (LYS_LIST == node->parent->schema->nodetype) {
                struct lys_node_list *list = (struct lys_node_list *) node->parent->schema;
                for(int i = 0; i < list->keys_size; i++) {
                    if (0 == strncmp(list->keys[i]->name, node->schema->name, strlen(node->schema->name))) {
                        skip = true;
                    }
                }
            }
            if (!skip) {
                xpath = lyd_path(node);
                CHECK_NULL_MSG(xpath, &rc, error, "failed to allocate memory");

                rc = sr_set_item_str(session, xpath, leaf->value_str, SR_EDIT_DEFAULT);
                CHECK_RET(rc, error, "failed sr_set_item_str: %s", sr_strerror(rc));
                free(xpath);
                xpath = NULL;
            }
        }
        LY_TREE_DFS_END(root, next, node);
    }

    INF_MSG("commit the changes");
    rc = sr_commit(session);
    CHECK_RET(rc, error, "failed sr_commit: %s", sr_strerror(rc));

    xpath = NULL;
error:
    if (NULL != xpath) {
        free(xpath);
    }
    return rc;
}

int
snabb_datastore_to_sysrepo(global_ctx_t *ctx) {
    int rc = SR_ERR_OK;
    char message[SNABB_MESSAGE_MAX] = {0};
    char *response = NULL;
    struct lyd_node *node = NULL;

    snprintf(message, SNABB_MESSAGE_MAX, "get-config {path '/'; print-default 'true'; schema %s;}", ctx->yang_model);

    /* send to socket */
    INF_MSG("send to socket");
    rc = socket_send(ctx, message, &response, true, false);
    CHECK_RET(rc, error, "failed to send message to snabb socket: %s", sr_strerror(rc));

    rc = transform_data_to_array(ctx, NULL, response, &node);
    CHECK_RET(rc, error, "failed parse snabb data in libyang: %s", sr_strerror(rc));

    /* copy snabb daat to startup datastore */
    INF_MSG("appply snabb data to sysrepo startup datastore");
    rc = libyang_data_to_sysrepo(ctx->startup_sess, node);
    CHECK_RET(rc, error, "failed to apply libyang data to sysrepo: %s", sr_strerror(rc));

    /* free lyd_node */
    if (NULL != node) {
        lyd_free(node);
    }

error:
    if (NULL != response) {
        free(response);
    }
    return rc;
}

int
sync_datastores(global_ctx_t *ctx) {
    char startup_file[XPATH_MAX_LEN] = {0};
    int rc = SR_ERR_OK;
    struct stat st;

    /* check if the startup datastore is empty
     * by checking the content of the file */
    snprintf(startup_file, XPATH_MAX_LEN, "/etc/sysrepo/data/%s.startup", ctx->yang_model);

    if (stat(startup_file, &st) != 0) {
        ERR("Could not open sysrepo file %s", startup_file);
        return SR_ERR_INTERNAL;
    }

    if (0 == st.st_size) {
        /* copy the snabb datastore to sysrepo */
        INF_MSG("copy snabb data to sysrepo");
        rc = snabb_datastore_to_sysrepo(ctx);
        CHECK_RET(rc, error, "failed to apply snabb data to sysrepo: %s", sr_strerror(rc));
    } else {
        /* copy the sysrepo startup datastore to snabb */
        INF_MSG("copy sysrepo data to snabb");
        //rc = sysrepo_datastore_to_snabb(ctx);
        CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));
    }

error:
    return rc;
}

void
clear_context(global_ctx_t *ctx) {
    sr_unsubscribe(ctx->running_sess, ctx->sub);

    socket_close(ctx);

    ly_ctx_destroy(ctx->libyang_ctx, NULL);

    /* startup datastore */
    sr_session_stop(ctx->startup_sess);
    sr_disconnect(ctx->startup_conn);

    INF("%s plugin cleanup finished.", ctx->yang_model);
    free(ctx);
}

int
load_startup_datastore(global_ctx_t *ctx) {
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect(ctx->yang_model, SR_CONN_DEFAULT, &connection);
    CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_CONFIG_ONLY, &session);
    CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

    ctx->startup_conn = connection;
    ctx->startup_sess = session;

    return rc;
cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }

    return rc;
}

int
snabb_socket_reconnect(global_ctx_t *ctx) {
    int32_t pid = 0;
    struct sockaddr_un address;
    int rc = SR_ERR_OK;
    FILE *fp = NULL;
    int BUFSIZE = 256;
    char buf[BUFSIZE];

    // close existing socket if exists
    if (-1 != ctx->socket_fd) {
        close(ctx->socket_fd);
    }

    // extract pid from the command "snabb ps"
    if ((fp = popen("exec bash -c 'snabb ps | head -n1 | cut -d \" \" -f1'", "r")) == NULL) {
        ERR_MSG("Error opening pipe!");
        return SR_ERR_INTERNAL;
    }

    if (fgets(buf, BUFSIZE, fp) != NULL) {
        sscanf(buf, "%d", &pid);
    } else {
        ERR_MSG("Error running 'snabb ps' command.");
        goto error;
    }
    INF("connect to snabb socket /run/snabb/%d/config-leader-socket", pid);

    ctx->socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (ctx->socket_fd < 0) {
        WRN("failed to create UNIX socket: %d", ctx->socket_fd);
        goto error;
    }

    snprintf(ctx->socket_path, UNIX_PATH_MAX, "/run/snabb/%d/config-leader-socket", pid);

    /* start with a clean address structure */
    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, UNIX_PATH_MAX, "/run/snabb/%d/config-leader-socket", pid);

    rc = connect(ctx->socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un));
    CHECK_RET_MSG(rc, error, "failed connection to snabb socket");

    return SR_ERR_OK;
error:
    if (fp) {
        pclose(fp);
    }
    socket_close(ctx);
    return SR_ERR_INTERNAL;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

bool
is_new_snabb_command(iter_change_t *iter, iter_change_t *prev) {

    /* one snabb command for creating list or containers */
    //print_change(iter->oper, iter->old_val, iter->new_val);
    if (SR_OP_CREATED == iter->oper && iter->new_val->type < SR_BINARY_T) {
        if (SR_OP_CREATED != prev->oper || iter == prev) {
            return true;
        } else {
            if (SR_OP_CREATED == prev->oper &&
                0 != strncmp(prev->new_val->xpath, iter->new_val->xpath, strlen(prev->new_val->xpath))) {
                return true;
            }
        }
    }

    /* one snabb command for deleting list or containers
    lib/yang/path_data.lua:436: Remove only allowed on arrays and tables */
    if (SR_OP_DELETED == iter->oper && iter->old_val->type == SR_LIST_T) {
        if (SR_OP_DELETED != prev->oper) {
            return true;
        } else {
            if (SR_OP_DELETED == prev->oper &&
                0 != strncmp(prev->old_val->xpath, iter->old_val->xpath, strlen(iter->old_val->xpath))) {
                return true;
            }

            if (SR_OP_DELETED == prev->oper) {
                if (strlen(iter->old_val->xpath) < strlen(prev->old_val->xpath) &&
                    0 == strncmp(prev->old_val->xpath, iter->old_val->xpath, strlen(iter->old_val->xpath))) {
                    return true;
                }
                if (strlen(iter->old_val->xpath) > strlen(prev->old_val->xpath) &&
                    0 != strncmp(prev->old_val->xpath, iter->old_val->xpath, strlen(prev->old_val->xpath))) {
                    return true;
                }
            }
        }
    }

    /* one snabb command for changing leaf's */
    if (SR_OP_MODIFIED == iter->oper) {
        return true;
    }

    return false;
}

int
sr_modified_operation(sr_val_t *val) {
    int rc = SR_ERR_OK;

    char *leaf = sr_val_to_str(val);
    char *snabb_xpath = sr_xpath_to_snabb(val->xpath);
    INF("\nmodified %s %s\n", snabb_xpath, leaf);
    free(snabb_xpath);
    if (leaf) free(leaf);

    return rc;
}

int
sr_deleted_operation(sr_val_t *val) {
    int rc = SR_ERR_OK;

    char *snabb_xpath = sr_xpath_to_snabb(val->xpath);
    INF("\ndelete %s\n", snabb_xpath);
    free(snabb_xpath);

    return rc;
}

struct ly_ctx *
parse_yang_model2() {
    const struct lys_module *module = NULL;
    struct ly_ctx *ctx = NULL;

    ctx = ly_ctx_new(NULL, LY_CTX_ALLIMPLEMENTED);
    if (NULL == ctx) {
        goto error;
    }

    module = lys_parse_path(ctx, "/etc/sysrepo/yang/snabb-softwire-v2@2017-04-17.yang", LYS_IN_YANG);
    if (NULL == module) {
        goto error;
    }

error:
    return ctx;
}

void
lyd_to_snabb_json(struct lyd_node *node, char *message, int len) {
    bool add_brackets = false;

    if (*message == '\0') {
        add_brackets = true;
        strncat(message, "{ ", len);
    }

    while (node) {
        if (node->child &&
            (node->schema->flags == LYS_CONTAINER || node->schema->flags == LYS_LIST || node->schema->flags == LYS_CHOICE)) {
            strncat(message, node->schema->name, len);
            strncat(message, " { ", len);
            lyd_to_snabb_json(node->child, message, 1000);
            strncat(message, " } ", len);
        } else {
            strncat(message, node->schema->name, len);
            strncat(message, " ", len);
            struct lyd_node_leaf_list *leaf = (struct lyd_node_leaf_list *) node;
            strncat(message, leaf->value_str, len);
            strncat(message, "; ", len);
        }
        node = node->next;
    }

    if (add_brackets) {
        strncat(message, "}", len);
    }
}

int
sr_created_operation(iter_change_t **p_iter, pthread_rwlock_t *iter_lock, size_t begin, size_t end) {
    iter_change_t *iter = *p_iter;
    int rc = SR_ERR_OK;
    struct lyd_node *root = NULL;
    struct ly_ctx *ctx = parse_yang_model2();
    char *xpath = NULL;

    pthread_rwlock_rdlock(iter_lock);
    sr_val_t *create_val = iter[begin].new_val;
    xpath = iter[begin].new_val->xpath;
    for (size_t i = begin; i < end; ++i) {
        sr_val_t *val = iter[i].new_val;
        char *leaf = sr_val_to_str(val);
        if (root) {
            lyd_new_path(root, ctx, val->xpath, (void *) leaf, 0, 1);
        } else {
            root = lyd_new_path(NULL, ctx, val->xpath, (void *) leaf, 0, 1);
        }
        if (leaf) {
            free(leaf);
        }
    }
    pthread_rwlock_unlock(iter_lock);

    struct ly_set *set = lyd_find_path(root, create_val->xpath);
    CHECK_NULL(set, &rc, cleanup, "failed lyd_find_path with path", create_val->xpath);

    char *data = NULL;
    int len = 1000;
    data = malloc(sizeof(*data) * len);
    *data = '\0';

    lyd_to_snabb_json((*set->set.d)->child, data, len);

    // snabb xpath can't have leafs at the end
    char *snabb_xpath = sr_xpath_to_snabb_no_end_keys(xpath);
    INF("\ncreated %s %s\n", snabb_xpath, data);
    free(snabb_xpath);
    free(data);

cleanup:
    if (set) {
        ly_set_free(set);
    }
    if (root) {
        lyd_free_withsiblings(root);
    }
    if (ctx) {
        ly_ctx_destroy(ctx, NULL);
    }
    return rc;
}

int
xpaths_to_snabb_socket(iter_change_t **p_iter, pthread_rwlock_t *iter_lock, size_t begin, size_t end) {
    iter_change_t *iter = *p_iter;
    sr_change_oper_t oper;
    sr_val_t *tmp_val = NULL;
    int rc = SR_ERR_OK;

    pthread_rwlock_rdlock(iter_lock);
    oper = iter[begin].oper;
    if (SR_OP_DELETED == oper) {
        tmp_val = iter[begin].old_val;
    } else if (SR_OP_MODIFIED == oper) {
        tmp_val = iter[begin].new_val;
    } else {
        tmp_val = iter[begin].new_val;
    }
    pthread_rwlock_unlock(iter_lock);

    if (SR_OP_MODIFIED == oper) {
        rc = sr_modified_operation(tmp_val);
    } else if (SR_OP_DELETED == oper) {
        /* snabb allows remove operations only on arrays and tables, list and leaf-list */
        if (tmp_val->type == SR_LIST_T) {
            rc = sr_deleted_operation(tmp_val);
        }
    } else {
        rc = sr_created_operation(p_iter, iter_lock, begin, end);
    }
    CHECK_RET(rc, cleanup, "failed to run operation: %s", sr_strerror(rc));

cleanup:
    return rc;
}
