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

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/plugins.h>

#include "common.h"
#include "xpath.h"
#include "transform.h"

int socket_send(ctx_t *ctx, char *message, sb_command_t command, char **response, sr_notif_event_t event, status_t *status);
int xpath_to_snabb(ctx_t *ctx, action_t *action, char **message);
int sysrepo_to_snabb(ctx_t *ctx, action_t *action);
void free_all_actions();
void free_action(action_t *action);
int apply_action(ctx_t *ctx, action_t *action);

bool has_aborted() {
    action_t *tmp = NULL;
    LIST_FOREACH(tmp, &head, actions) {
        if (SR_EV_ABORT == tmp->event) {
            return true;
        }
    }

    return false;
}

void socket_close(ctx_t *ctx) {
    if (-1 != ctx->socket_fd) {
        close(ctx->socket_fd);
    }
}

int socket_send(ctx_t *ctx, char *message, sb_command_t command, char **response, sr_notif_event_t event, status_t *status) {
    int rc = SR_ERR_OK;
    int len = 0;
    int nbytes;
    char *buffer = NULL;

    if (NULL == message) {
        return SR_ERR_INTERNAL;
    }

    /* get message length in char* format */
    char str[30];
    sprintf(str, "%d", (int) strlen(message));

    len = (int) strlen(&str[0]) + 1 + (int) strlen(message) + 1;

    buffer = malloc(sizeof(*buffer) * len);
    CHECK_NULL_MSG(buffer, &rc, error, "failed to allocate memory");

    nbytes = snprintf(buffer, len, "%s\n%s", str, message);

    //TODO add timeout check
    if (NULL != status) {
        *status = EXECUTED;
    }
    nbytes = write(ctx->socket_fd, buffer, nbytes);
    if ((int) strlen(buffer) != (int) nbytes) {
        if (-1 == nbytes) {
            snabb_socket_reconnect(ctx);
            free(buffer);
            //TODO prevent infinit loop
            return socket_send(ctx, message, command, response, event, status);
        } else {
            ERR("Failed to write full message to server: written %d, expected %d", (int) nbytes, (int) strlen(buffer));
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
    } else if (SB_SET == command && 18 != nbytes) {
        goto failed;
    } else if (SB_GET == command && 0 == nbytes) {
        goto failed;
    } else {
        INF("Operation:\n%s", message);
        INF("Response:\n%s", ch);
    }

    if (SB_GET == command) {
        *response = strdup(ch);
    }

    /* set null terminated string at the beggining */
    ch[0] = '\0';

    if (NULL != status) {
        *status = APPLIED;
    }
    return SR_ERR_OK;
failed:
    if (SR_EV_ABORT != event) {
        rc = SR_ERR_INTERNAL;
        WRN("Operation faild for:\n%s", message);
        WRN("Respons:\n%s", ch);
    }
error:
    if (NULL != buffer) {
        free(buffer);
    }
    return rc;
}

int double_message_size(char **message, int *len) {
    int rc = SR_ERR_OK;
    char *tmp = NULL;

    *len = *len * 2;
    tmp = (char *) realloc(*message, (*len));
    CHECK_NULL_MSG(tmp, &rc, error, "failed to allocate memory");

    *message = tmp;

error:
    return rc;
}

int fill_list(sr_node_t *tree, char **message, int *len) {
    int rc = SR_ERR_OK;

    if (NULL == tree) {
        return rc;
    }

    while(true) {
        if (*len < XPATH_MAX_LEN + (int) strlen(*message)) {
            rc = double_message_size(message, len);
            CHECK_RET(rc, cleanup, "failed to double the buffer size: %s", sr_strerror(rc));
        }
        if (NULL == tree) {
            break;
        } else if (list_or_container(tree->type)) {
            //TODO check for error
            strncat(*message, tree->name, *len);
            strncat(*message, " { ", *len);
            rc = fill_list(tree->first_child, message, len);
            CHECK_RET(rc, cleanup, "failed fill_list: %s", sr_strerror(rc));
            strncat(*message, " } ", *len);
        } else {
            //TODO check for error
            strncat(*message, tree->name, *len);
            strncat(*message, " ", *len);
            char *value = sr_val_to_str((sr_val_t *) tree);
            strncat(*message, value, *len);
            free(value);
            strncat(*message, "; ", *len);
        }
        tree = tree->next;
    }

cleanup:
    return rc;
}

int
xpath_to_snabb(ctx_t *ctx, action_t *action, char **message) {
    int rc = SR_ERR_OK;
    int len = SNABB_MESSAGE_MAX;
    sr_node_t *trees = NULL;

    *message = malloc(sizeof(**message) * len);
    CHECK_NULL_MSG(*message, &rc, error, "failed to allocate memory");

    *message[0] = '\0';

    long unsigned int tree_cnt = 0;
    rc = sr_get_subtrees(ctx->sess, action->xpath, SR_GET_SUBTREE_DEFAULT, &trees, &tree_cnt);
    if (SR_ERR_NOT_FOUND == rc && SR_EV_ABORT == action->event) {
        INF("No items found in sysrepo datastore for xpath: %s", action->xpath);
        return SR_ERR_OK;
    }
    CHECK_RET(rc, error, "failed sr_get_subtrees: %s", sr_strerror(rc));

    if (1 == tree_cnt) {
        if (true == list_or_container(trees[0].type)) {
            if (SR_LIST_T == trees[0].type) {
                strncat(*message, " { ", len);
            }
            rc = fill_list(trees->first_child, message, &len);
            CHECK_RET(rc, error, "failed to create snabb configuration data: %s", sr_strerror(rc));
            if (SR_LIST_T == trees[0].type) {
                strncat(*message, " } ", len);
            }
        } else {
            char *value = sr_val_to_str((sr_val_t *) &trees[0]);
            strncat(*message, trees[0].name, len);
            strncat(*message, " ", len);
            strncat(*message, value, len);
            strncat(*message, ";", len);
            free(value);
        }
    } else {
        for (int i = 0; i < (int) tree_cnt; i++) {
            rc = fill_list(&trees[i], message, &len);
            CHECK_RET(rc, error, "failed to create snabb configuration data: %s", sr_strerror(rc));
        }
    }

    sr_free_trees(trees, tree_cnt);
    return rc;
error:
    if (NULL != *message) {
        free(*message);
    }
    if (NULL != trees) {
        sr_free_trees(trees, tree_cnt);
    }
    return rc;
}

int
sysrepo_to_snabb(ctx_t *ctx, action_t *action) {
    sb_command_t command;
    char *message = NULL;
    int  rc = SR_ERR_OK;

    char *tmp = NULL;
    char **value = &tmp;

    /* translate sysrepo operation to snabb command */
    switch(action->op) {
    case SR_OP_MODIFIED:
        rc = format_xpath(action);
        CHECK_RET(rc, error, "failed to format xpath: %s", sr_strerror(rc));

        message = malloc(sizeof(*message) * (SNABB_MESSAGE_MAX + strlen(action->snabb_xpath) + strlen(ctx->yang_model)));
        CHECK_NULL_MSG(message, &rc, error, "failed to allocate memory");

        snprintf(message, SNABB_MESSAGE_MAX, "set-config {path '%s'; config '%s'; schema %s;}", action->snabb_xpath, action->value, ctx->yang_model);
        command = SB_SET;
        break;
    case SR_OP_CREATED:
        rc = xpath_to_snabb(ctx, action, value);
        CHECK_RET(rc, error, "failed xpath_to_snabb: %s", sr_strerror(rc));
        /* edge case, deleting all of leaf-list entries
         * check if value is empty string ""
         * and parent_type is LYS_LEAFLIST
         */
#ifdef LEAFLIST
        if (LYS_LEAFLIST == action->yang_type && 0 == strlen(*value)) {
            action->yang_type = LYS_UNKNOWN;
        }
#endif
        rc = format_xpath(action);

        CHECK_RET(rc, error, "failed to format xpath: %s", sr_strerror(rc));

        int len = SNABB_MESSAGE_MAX + (int) strlen(action->snabb_xpath) + strlen(*value) + (int) strlen(ctx->yang_model);
        message = malloc(sizeof(*message) * len);
        CHECK_NULL_MSG(message, &rc, error, "failed to allocate memory");

        if (action->type == SR_LIST_T) {
            snprintf(message, len, "add-config {path '%s'; config '%s'; schema %s;}", action->snabb_xpath, *value, ctx->yang_model);
        } else {
            snprintf(message, len, "set-config {path '%s'; config '%s'; schema %s;}", action->snabb_xpath, *value, ctx->yang_model);
        }
        free(*value);
        command = SB_ADD;
        break;
    case SR_OP_DELETED:
        rc = format_xpath(action);
        CHECK_RET(rc, error, "failed to format xpath: %s", sr_strerror(rc));

        message = malloc(sizeof(*message) * (SNABB_MESSAGE_MAX + strlen(action->snabb_xpath) + strlen(ctx->yang_model)));
        CHECK_NULL_MSG(message, &rc, error, "failed to allocate memory");

        snprintf(message, SNABB_MESSAGE_MAX, "remove-config {path '%s'; schema %s;}", action->snabb_xpath, ctx->yang_model);
        command = SB_REMOVE;
        break;
    default:
        command = SB_SET;
    }

    /* send to socket */
    INF_MSG("send to socket");
    rc = socket_send(ctx, message, command, NULL, action->event, &action->status);
    CHECK_RET(rc, error, "failed to send message to snabb socket: %s", sr_strerror(rc));

error:
    if (NULL != message) {
        free(message);
    }
    return rc;
}

int
add_action(ctx_t *ctx, sr_val_t *val, sr_change_oper_t op, sr_notif_event_t event) {
    int rc = SR_ERR_OK;

    if (SR_OP_MOVED == op) {
        return rc;
    }

    action_t *action = malloc(sizeof(action_t));
    action->xpath = strdup(val->xpath);
    action->snabb_xpath = NULL;
    action->value = NULL;
    action->type = val->type;
    action->event = event;
    action->status = CREATED;

#ifdef LEAFLIST
    rc = get_yang_type(ctx, action);
    CHECK_RET(rc, error, "failed get_parent_type %s", sr_strerror(rc));

    /* leaf-list are handled diferently in snabb */
    if (LYS_LEAFLIST == action->yang_type) {
        op = SR_OP_CREATED;
    }
#endif

    /* in case ABORT check if xpath is already applied to snabb if yes add it to the list */
    if (SR_EV_ABORT == action->event) {
        action_t *tmp = NULL;
        LIST_FOREACH(tmp, &head, actions) {
            if (0 == strncmp(val->xpath, tmp->xpath, strlen(tmp->xpath)) && EXECUTED == tmp->status) {
                goto error;
            }
        }
    }

    if (!list_or_container(val->type) && !leaf_without_value(val->type) && SR_OP_MODIFIED == op) {
        action->value = sr_val_to_str(val);
        if (NULL == action->value) {
            rc = SR_ERR_DATA_MISSING;
            goto error;
        }
    } else if (!list_or_container(val->type) && (SR_OP_CREATED == op || SR_OP_DELETED == op)) {
        /* check if a list/container is already in the list */
        action_t *tmp = NULL;
        LIST_FOREACH(tmp, &head, actions) {
            if (0 == strncmp(val->xpath, tmp->xpath, strlen(tmp->xpath)) && list_or_container(tmp->type) && tmp->event == event) {
                goto error;
            }
        }
        action->value = NULL;
    } else if (list_or_container(val->type) && (SR_OP_CREATED == op || SR_OP_DELETED == op)) {
        action_t *tmp = NULL, *tmp2 = NULL;
        /* check of contaire/group is covered with some other xpathg */
        LIST_FOREACH(tmp, &head, actions) {
            if (0 == strncmp(val->xpath, tmp->xpath, strlen(tmp->xpath)) && list_or_container(tmp->type) && tmp->event == event) {
                goto error;
            }
        }
        /* if a list/container is created/deleted remove previous entries of child nodes */
        tmp = LIST_FIRST(&head);
        while (NULL != tmp) {
            tmp2 = LIST_NEXT(tmp, actions);
            if (0 == strncmp(val->xpath, tmp->xpath, strlen(val->xpath)) && tmp->event == event) {
                LIST_REMOVE(tmp, actions);
                free_action(tmp);
            }
            tmp = tmp2;
        }
    }
    action->op = op;
    LIST_INSERT_HEAD(&head, action, actions);

    return rc;
error:
    free_action(action);
    return rc;
}

void
free_action(action_t *action) {
    if (NULL == action) {
        return;
    }
    if (NULL != action->value) {
        free(action->value);
    }
    if (NULL != action->xpath) {
        free(action->xpath);
    }
    if (NULL != action->snabb_xpath) {
        free(action->snabb_xpath);
    }
    free(action);
    action = NULL;
}

void
free_all_actions() {
    action_t *tmp = NULL;
    while (!LIST_EMPTY(&head)) {
        tmp = LIST_FIRST(&head);
        LIST_REMOVE(tmp, actions);
        free_action(tmp);
    }
}

int
apply_all_actions(ctx_t *ctx) {
    int rc = SR_ERR_OK;
    action_t *tmp = NULL;

    /* if aborted actions exist, apply only failed snabb actions */
    bool aborted = has_aborted();

    /* if the change callback is aborted use the running datastore session */
    if (true == aborted) {
        ctx->sess = ctx->running_sess;
    }

    /* first apply all delete actions */
    LIST_FOREACH(tmp, &head, actions) {
        if (SR_OP_DELETED == tmp->op && ((!aborted) || (aborted && SR_EV_ABORT == tmp->event))) {
            rc = apply_action(ctx, tmp);
            CHECK_RET(rc, cleanup, "failed apply action: %s", sr_strerror(rc));
        }
    }

    /* than apply all add/change actions */
    LIST_FOREACH(tmp, &head, actions) {
        if (SR_OP_DELETED != tmp->op && ((!aborted) || (aborted && SR_EV_ABORT == tmp->event))) {
            rc = apply_action(ctx, tmp);
            CHECK_RET(rc, cleanup, "failed apply action: %s", sr_strerror(rc));
        }
    }

    free_all_actions();
    return rc;

cleanup:
    /* in case aborted action failde free all actions */
    if (true == aborted) {
        free_all_actions();
    }
    return rc;
}

int
apply_action(ctx_t *ctx, action_t *action) {
    int rc = SR_ERR_OK;

    rc = sysrepo_to_snabb(ctx, action);
    CHECK_RET(rc, error, "failed to create snabb message: %s", sr_strerror(rc));

error:
    return rc;
}

int
sysrepo_datastore_to_snabb(ctx_t *ctx) {
    action_t *action = NULL;
    sr_node_t *trees = NULL;
    /* use startup session */
    sr_session_ctx_t *session = ctx->startup_sess;

    int rc = SR_ERR_OK;
    char xpath[XPATH_MAX_LEN] = {0};

    snprintf(xpath, XPATH_MAX_LEN, "/%s:*", ctx->yang_model);

    long unsigned int tree_cnt = 0;
    rc = sr_get_subtrees(session, xpath, SR_GET_SUBTREE_DEFAULT, &trees, &tree_cnt);
    CHECK_RET(rc, error, "failed sr_get_subtrees: %s", sr_strerror(rc));

    for (int i = 0; i < (int) tree_cnt; i++) {
        action = malloc(sizeof(action_t));
        CHECK_NULL_MSG(action, &rc, error, "failed to allocate memory");

        snprintf(xpath, XPATH_MAX_LEN, "/%s:%s", ctx->yang_model, trees[i].name);
        action->value = NULL;
        action->xpath = strdup(xpath);
        action->snabb_xpath = NULL;
        action->op = SR_OP_CREATED;
        action->type = trees[i].type;
        action->event = SR_EV_APPLY;

#ifdef LEAFLIST
        rc = get_yang_type(ctx, action);
        if (SR_ERR_OK != rc) {
            free_action(action);
        }
        CHECK_RET(rc, error, "failed get_parent_type %s", sr_strerror(rc));
#endif

        LIST_INSERT_HEAD(&head, action, actions);
    }

    //action_t *tmp = NULL;
    //LIST_FOREACH(tmp, &head, actions) {
    //    INF("Add liste entry: xpath: %s, value: %s, op: %d", tmp->xpath, tmp->value, tmp->op);
    //}

    ctx->sess = session;
    rc = apply_all_actions(ctx);
    CHECK_RET(rc, error, "failed execute all operations: %s", sr_strerror(rc));

error:
    if (NULL != trees) {
        sr_free_trees(trees, tree_cnt);
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
snabb_datastore_to_sysrepo(ctx_t *ctx) {
    int rc = SR_ERR_OK;
    sb_command_t command;
    char message[SNABB_MESSAGE_MAX] = {0};
    char *response = NULL;
    struct lyd_node *node = NULL;

    snprintf(message, SNABB_MESSAGE_MAX, "get-config {path '/'; print-default 'true'; schema %s;}", ctx->yang_model);
    command = SB_GET;

    INF("%s", message);
    /* send to socket */
    INF_MSG("send to socket");
    status_t status;
    rc = socket_send(ctx, message, command, &response, SR_EV_APPLY, &status);
    CHECK_RET(rc, error, "failed to send message to snabb socket: %s", sr_strerror(rc));

    rc = transform_data_to_array(ctx, NULL, response, &node);
    CHECK_RET(rc, error, "failed parse snabb data in libyang: %s", sr_strerror(rc));

    /* copy snabb daat to startup datastore */
    INF_MSG("appply snabb data to sysrepo startup datastore");
    rc = libyang_data_to_sysrepo(ctx->startup_sess, node);
    CHECK_RET(rc, error, "failed to apply libyang data to sysrepo: %s", sr_strerror(rc));

    ///* copy snabb daat to startup datastore */
    //INF_MSG("appply snabb data to sysrepo running datastore");
    //rc = libyang_data_to_sysrepo(ctx->sess, node);
    //CHECK_RET(rc, error, "failed to apply libyang data to sysrepo: %s", sr_strerror(rc));

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
sync_datastores(ctx_t *ctx) {
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
        rc = sysrepo_datastore_to_snabb(ctx);
        CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));
    }

error:
    return rc;
}

void
clear_context(ctx_t *ctx) {
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
load_startup_datastore(ctx_t *ctx) {
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

static sr_type_t
sr_ly_data_type_to_sr(LY_DATA_TYPE type)
{
    switch(type){
        case LY_TYPE_BINARY:
            return SR_BINARY_T;
        case LY_TYPE_BITS:
            return SR_BITS_T;
        case LY_TYPE_BOOL:
            return SR_BOOL_T;
        case LY_TYPE_DEC64:
            return SR_DECIMAL64_T;
        case LY_TYPE_EMPTY:
            return SR_LEAF_EMPTY_T;
        case LY_TYPE_ENUM:
            return SR_ENUM_T;
        case LY_TYPE_IDENT:
            return SR_IDENTITYREF_T;
        case LY_TYPE_INST:
            return SR_INSTANCEID_T;
        case LY_TYPE_STRING:
            return SR_STRING_T;
        case LY_TYPE_INT8:
            return SR_INT8_T;
        case LY_TYPE_UINT8:
            return SR_UINT8_T;
        case LY_TYPE_INT16:
            return SR_INT16_T;
        case LY_TYPE_UINT16:
            return SR_UINT16_T;
        case LY_TYPE_INT32:
            return SR_INT32_T;
        case LY_TYPE_UINT32:
            return SR_UINT32_T;
        case LY_TYPE_INT64:
            return SR_INT64_T;
        case LY_TYPE_UINT64:
            return SR_UINT64_T;
        default:
            return SR_UNKNOWN_T;
            //LY_LEAF_REF
            //LY_DERIVED
            //LY_TYPE_UNION
        }
}

int
set_value(sr_val_t *value, LY_DATA_TYPE type, lyd_val leaf)
{
    int rc = SR_ERR_OK;
    /* try to build string data first */
    rc = sr_val_set_str_data(value, type, leaf.string);
    if (SR_ERR_OK == rc) {
        return rc;
    }

    value->type = sr_ly_data_type_to_sr(type);

    switch (type) {
    case LY_TYPE_BOOL:
        value->data.bool_val = leaf.bln;
        return SR_ERR_OK;
    case LY_TYPE_DEC64:
        value->data.decimal64_val = (double) leaf.dec64;
        return SR_ERR_OK;
    case LY_TYPE_UNION:
        return SR_ERR_OK;
    case LY_TYPE_INT8:
        value->data.int8_val = leaf.int8;
        return SR_ERR_OK;
    case LY_TYPE_UINT8:
        value->data.uint8_val = leaf.uint8;
        return SR_ERR_OK;
    case LY_TYPE_INT16:
        value->data.int16_val = leaf.int16;
        return SR_ERR_OK;
    case LY_TYPE_UINT16:
        value->data.uint16_val = leaf.uint16;
        return SR_ERR_OK;
    case LY_TYPE_INT32:
        value->data.int32_val = leaf.int32;
        return SR_ERR_OK;
    case LY_TYPE_UINT32:
        value->data.uint32_val = leaf.uint32;
        return SR_ERR_OK;
    case LY_TYPE_INT64:
        value->data.int64_val = leaf.int64;
        return SR_ERR_OK;
    case LY_TYPE_UINT64:
        value->data.uint64_val = leaf.uint64;
        return SR_ERR_OK;
    default:
        return SR_ERR_INTERNAL;
    }
}

int
snabb_state_data_to_sysrepo(ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt) {
    int rc = SR_ERR_OK;
    sb_command_t command;
    char message[SNABB_MESSAGE_MAX] = {0};
    char *response = NULL;
    struct lyd_node *root = NULL;
    action_t *action = NULL;
    int cnt = 0;

    action = malloc(sizeof(action_t));
    CHECK_NULL_MSG(action, &rc, error, "failed to allocate memory");

    action->xpath = strdup(xpath);
    action->snabb_xpath = NULL;
    action->value = NULL;
    action->event = SR_EV_APPLY;

    rc = format_xpath(action);
    CHECK_RET(rc, error, "failed to format xpath: %s", sr_strerror(rc));

    snprintf(message, SNABB_MESSAGE_MAX, "get-state {path '%s'; schema %s;}", action->snabb_xpath, ctx->yang_model);
    free_action(action);
    action = NULL;
    command = SB_GET;

    INF("%s", message);
    /* send to socket */
    INF_MSG("send to socket");
    rc = socket_send(ctx, message, command, &response, SR_EV_APPLY, NULL);
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
            struct lys_node_leaf *lys_leaf = (struct lys_node_leaf *) node->schema;
            char *path = lyd_path(node);
            CHECK_NULL_MSG(path, &rc, error, "failed to allocate memory");

            rc = sr_val_set_xpath(&v[i], path);
            free(path);
            CHECK_RET(rc, error, "failed sr_val_set_xpath: %s", sr_strerror(rc));

            set_value(&v[i], lys_leaf->type.base, leaf->value);
            CHECK_RET(rc, error, "failed to set value: %s", sr_strerror(rc));

            i++;
        }
        LY_TREE_DFS_END(root, next, node);
    }

    *values = v;
    *values_cnt = cnt;

error:
    /* free lyd_node */
    if (NULL != action) {
        free_action(action);
    }
    if (NULL != root) {
        lyd_free(root);
    }
    if (NULL != response) {
        free(response);
    }
    return rc;
}

int
snabb_socket_reconnect(ctx_t *ctx) {
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
