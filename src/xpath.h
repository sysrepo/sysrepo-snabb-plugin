/**
 * @file xpath.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for xpath.c.
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

#ifndef XPATH_H
#define XPATH_H

#include "transform.h"

bool leaf_without_value(sr_type_t type);
bool list_or_container(sr_type_t type);
int format_xpath(action_t *action);
int transform_data_to_array(ctx_t *ctx, char *xpath, char *data, struct lyd_node **node);
int get_yang_type(ctx_t *ctx, action_t *action);

#endif /* XPATH_H */
