/**
 * @file xpath.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for libyang.c.
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

#ifndef LIBYANG_H
#define LIBYANG_H

#include "snabb.h"

bool list_or_container(sr_val_type_t);
//int transform_data_to_array(global_ctx_t *, char *, char *, struct lyd_node **);
int transform_snabb_data_to_tree(global_ctx_t *, char *, char *, struct lyd_node **, bool);
int parse_yang_model(global_ctx_t *);

#endif /* LIBYANG_H */
