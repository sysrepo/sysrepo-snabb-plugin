#include <stdio.h>
#include <string.h>

#include <sysrepo.h>
#include <libyang/libyang.h>
#include <libyang/tree_data.h>
#include <libyang/tree_schema.h>

const char *changes[18] = {
"/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']", NULL,
"/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']/ipv4", "1.79.150.15",
"/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']/psid", "0",
"/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']/b4-ipv6", "127:22:33:44:55:66:77:128",
"/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']/br-address", "8:9:a:b:c:d:e:f",
"/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']/port-set (container)",
"/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']/port-set/psid-length", "4",
"/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']/port-set/reserved-ports-bit-count", "0",
"/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']/padding", "0"
};

struct ly_ctx *
parse_yang_model() {
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

    while (node && node->schema) {
        if (node->schema->flags == LYS_CONTAINER || node->schema->flags == LYS_LIST) {
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

int main() {
    struct lyd_node *node = NULL;
    struct lyd_node *root = NULL;
    struct ly_ctx *ctx = parse_yang_model();

    for (int i = 0; i < 9; i = i + 2) {
        if (root) {
            node = lyd_new_path(root, ctx, changes[i], (void *) changes[i + 1], 0, 1);
        } else {
            root = lyd_new_path(NULL, ctx, changes[i], (void *) changes[i + 1], 0, 1);
        }
    }

    struct ly_set *set = lyd_find_path(root, "/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']");

    char *data = NULL;
    lyd_print_mem(&data, *(set->set.d), LYD_JSON, 0);

    printf("DATA:\n%s\n", data);
    free(data);

    data = NULL;
    data = malloc(sizeof(*data) * 1000);
    *data = '\0';

    lyd_to_snabb_json((*set->set.d)->child, data, 1000);

    printf("DATA:\n%s\n", data);
    free(data);

    ly_set_free(set);
    lyd_free_withsiblings(root);
    ly_ctx_destroy(ctx, NULL);
    return 0;
}
