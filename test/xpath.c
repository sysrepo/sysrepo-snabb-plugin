#include <stdio.h>
#include <string.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

char *
sr_xpath_to_snabb(char *xpath) {
    char *node = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};

    /* snabb xpath is always smaller than sysrepo's xpath */
    char *tmp = strdup(xpath);
    int len = strlen(xpath);

    if (!tmp) {
        free(tmp);
        tmp = NULL;
        goto error;
    }
    *tmp = '\0'; // init xpath string

    node = sr_xpath_next_node(xpath, &state);
    if (NULL == node) {
        free(tmp);
        tmp = NULL;
        goto error;
    }

    while(true) {
        strncat(tmp, "/", len);
        if (NULL != node) {
            strncat(tmp, node, len);
        }

        while(true) {
            char *key, *value;
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
        node = sr_xpath_next_node(NULL, &state);

        if (NULL == node) {
            break;
        }
    }

error:
    sr_xpath_recover(&state);
    return tmp;
}


int main() {
    char *xpath = strdup("/snabb-softwire-v2:softwire-config/binding-table/softwire[ipv4='178.79.150.2'][psid='7850']");

    char *snabb = sr_xpath_to_snabb(xpath);

    printf("PRINT XPATH orig, snabb\n%s\n%s\n", xpath, snabb);

    free(xpath);
    free(snabb);
}
