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
 *    http://www.apache.org/licenses/LICENSE-2.0
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
#include <pthread.h>

#include "common.h"
#include "snabb.h"
#include "transform.h"
#include "libyang.h"
#include "config.h"
#include "cfg.h"
#include "thpool.h"

const char *YANG_MODEL = YANG;

static int
parse_config(sr_session_ctx_t *session, const char *module_name, global_ctx_t *ctx, sr_notif_event_t event) {
    sr_change_iter_t *it = NULL;
    iter_change_t *iter_change = NULL;
    iter_change_t **p_iter_change = NULL;
    size_t iter_cnt = 0;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    iter_change = NULL;
    char xpath[XPATH_MAX_LEN] = {0,};
    pthread_rwlock_t iter_lock;

    /* create threads */
	threadpool thpool = thpool_init(THREADS);

    rc = pthread_rwlock_init(&iter_lock, NULL);
    if (0 != rc) {
        ERR_MSG("failed to create rwlock");
        goto error;
    }

    // initalize the array
    pthread_rwlock_wrlock(&iter_lock);
    size_t iter_change_size = 10;
    iter_cnt = 0;
    iter_change = calloc(iter_change_size, sizeof(*iter_change));
    if (iter_change) {
        p_iter_change = &iter_change;
    }
    pthread_rwlock_unlock(&iter_lock);
    CHECK_NULL_MSG(iter_change, &rc, error, "failed to allocate memory");

    snprintf(xpath, XPATH_MAX_LEN, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, xpath , &it);
    if (SR_ERR_OK != rc) {
        ERR("Get changes iter failed for xpath %s", xpath);
        goto error;
    }

    size_t prev = 0;
    INF_MSG("start iterating over the changes");
    while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {
        iter_change[iter_cnt].old_val = old_value;
        iter_change[iter_cnt].new_val = new_value;
        iter_change[iter_cnt].oper = oper;

        if (is_new_snabb_command(&iter_change[iter_cnt], &iter_change[prev])) {
            if (iter_cnt) {
                INF("cahnge prev %zd current %zd", prev, iter_cnt);
                //thpool_add_work(thpool, (void *) xpaths_to_snabb_socket(ctx, p_iter_change, &iter_lock, prev, iter_cnt), NULL);
                thread_job_t *job = (thread_job_t *) malloc(sizeof(thread_job_t));
                CHECK_NULL_MSG(job, &rc, error, "failed to allocate memory");
                job->ctx = ctx;
                job->p_iter = p_iter_change;
                job->iter_lock = &iter_lock;
                job->begin = prev;
                job->end = iter_cnt;
                thpool_add_work(thpool, xpaths_to_snabb_socket, job);
                //TODO check error
            }
            prev = iter_cnt;
        }

        ++iter_cnt;

        /* lock the mutex and resize the array if needed */
        if (iter_cnt >= iter_change_size) {
            pthread_rwlock_wrlock(&iter_lock);
            iter_change_size *= 4;
            iter_change = realloc(iter_change, sizeof(*iter_change) * iter_change_size);
            p_iter_change = &iter_change;
            pthread_rwlock_unlock(&iter_lock);
            CHECK_NULL_MSG(iter_change, &rc, error, "failed to allocate memory");
        }
    }
    //thpool_add_work(thpool, (void *) xpaths_to_snabb_socket, ctx, p_iter_change, &iter_lock, prev, iter_cnt);
    thread_job_t *job = (thread_job_t *) malloc(sizeof(thread_job_t));
    CHECK_NULL_MSG(job, &rc, error, "failed to allocate memory");
    job->ctx = ctx;
    job->p_iter = p_iter_change;
    job->iter_lock = &iter_lock;
    job->begin = prev;
    job->end = iter_cnt;
    thpool_add_work(thpool, xpaths_to_snabb_socket, job);
    //TODO check error

error:
    thpool_wait(thpool);
    thpool_destroy(thpool);

    if (NULL != it) {
        sr_free_change_iter(it);
    }
    if (iter_change) {
        for(size_t i = 0; i < iter_cnt; ++i) {
            sr_free_val(iter_change[i].old_val);
            sr_free_val(iter_change[i].new_val);
        }
        free(iter_change);
        iter_change = NULL;
    }
    pthread_rwlock_destroy(&iter_lock);
    return rc;
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
    int rc = SR_ERR_OK;
    global_ctx_t *ctx = private_ctx;
    INF("%s configuration has changed.", ctx->yang_model);

    ctx->sess = session;

    if (SR_EV_APPLY == event) {
        if (false == ctx->cfg->sync_startup) {
            return SR_ERR_OK;
        }
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

    rc = parse_config(session, module_name, ctx, event);
    CHECK_RET(rc, error, "failed to apply sysrepo changes to snabb: %s", sr_strerror(rc));

error:
    return rc;
}

static int
#if defined(SYSREPO_LESS_0_7_5)
state_data_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
#elif defined(SYSREPO_LESS_0_7_7)
state_data_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, void *private_ctx)
#else
state_data_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
#endif
{
    int rc = SR_ERR_OK;

    global_ctx_t *ctx = private_ctx;
    rc = snabb_state_data_to_sysrepo(ctx, (char *) xpath, values, values_cnt);
    CHECK_RET(rc, error, "failed to load state data: %s", sr_strerror(rc));

error:
    return rc;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx) {
    int rc = SR_ERR_OK;
    char xpath[XPATH_MAX_LEN] = {0};
    global_ctx_t *ctx = NULL;

    ctx = malloc(sizeof *ctx);
    CHECK_NULL_MSG(ctx, &rc, error, "failed malloc global context");

    ctx->cfg = NULL;
    ctx->yang_model = YANG_MODEL;
    ctx->libyang_ctx = NULL;
    ctx->sub = NULL;
    ctx->sess = session;
    ctx->socket_fd = -1;

    /* get snabb socket */
    rc = snabb_socket_reconnect(ctx);
    CHECK_RET_MSG(rc, error, "failed to get socket from snabb");

    /* set subscription as our private context */
    *private_ctx = ctx;

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

    rc = sr_module_change_subscribe(ctx->sess, ctx->yang_model, module_change_cb, ctx, 0, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, error, "failed sr_module_change_subscribe: %s", sr_strerror(rc));

    if (0 != strcmp("ietf-softwire-br", ctx->yang_model)) {
        snprintf(xpath, XPATH_MAX_LEN, "/%s:softwire-state", ctx->yang_model);
        rc = sr_dp_get_items_subscribe(ctx->sess, xpath, state_data_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
        CHECK_RET(rc, error, "failed sr_dp_get_items_subscribe: %s", sr_strerror(rc));
    }

    /* load config file */
    ctx->cfg = init_cfg_file();
    CHECK_NULL_MSG(ctx->cfg, &rc, error, "failed to parse cfg config file");

    rc = pthread_rwlock_init(&ctx->snabb_lock, NULL);
    if (0 != rc) {
        ERR_MSG("failed to create snabb rwlock");
        goto error;
    }

    INF("%s plugin initialized successfully", ctx->yang_model);

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
    /* subscription was set as our private context */
    global_ctx_t *ctx = private_ctx;

    /* clean snabb related context */
    if (ctx) {
        clear_context(ctx);
    }

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

cleanup:
    sr_plugin_cleanup_cb(session, private_ctx);

    sr_session_stop(session);
    sr_disconnect(connection);
}
#endif
