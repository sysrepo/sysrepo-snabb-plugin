/**
 * @file snabb.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for snabb.c.
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

#ifndef SNABB_H
#define SNABB_H

#include <pthread.h>
#include <sysrepo.h>

typedef struct iter_change_s {
    sr_val_t *old_val; // data passed from sysrepo
    sr_val_t *new_val; // data passed from sysrepo
    sr_change_oper_t oper; // data passed from sysrepo
    bool create_snabb; //use this iteration for creating a snabb command
} iter_change_t;

#endif /* SNABB_H */
