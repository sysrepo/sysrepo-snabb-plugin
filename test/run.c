#include <stdio.h>
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


int main() {
    struct lyd_node *node = NULL;
    struct ly_ctx *ctx = parse_yang_model();

    for (int i = 0; i < 9; i = i + 2) {
        node = lyd_new_path(node, ctx, changes[i], (void *) changes[i + 1], 0, 1);
    }

    while (true) {
        if (NULL == node->parent) break;
        node = node->parent;
    }

    struct ly_set *set = lyd_find_path(node, "/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='1.79.150.15'][psid='0']");

    char *data = NULL;
    lyd_print_mem(&data, *(set->set.d), LYD_JSON, 0);

    printf("DATA:\n%s\n", data);
    free(data);

    return 0;
}
