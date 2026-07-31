#include "gui.h"
#include <fcntl.h>

#define CONFIG_DIR "/etc/proxybridge"
#define CONFIG_PATH "/etc/proxybridge/config.ini"

// save config
void save_config() {
    struct stat st = {0};
    if (stat(CONFIG_DIR, &st) == -1) {
        if (mkdir(CONFIG_DIR, 0700) != 0) {
            perror("failed to create config dir");
            return;
        }
    } else if (chmod(CONFIG_DIR, 0700) != 0) {
        perror("failed to tighten config dir permissions");
    }

    int cfg_fd = open(CONFIG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (cfg_fd < 0) {
        printf("failed to save config to %s\n", CONFIG_PATH);
        return;
    }
    FILE *f = fdopen(cfg_fd, "w");
    if (!f) {
        close(cfg_fd);
        printf("failed to save config to %s\n", CONFIG_PATH);
        return;
    }

    // settings section
    fprintf(f, "[SETTINGS]\n");
    fprintf(f, "ip=%s\n", g_proxy_ip);
    fprintf(f, "port=%d\n", g_proxy_port);
    fprintf(f, "type=%d\n", g_proxy_type);
    fprintf(f, "user=%s\n", g_proxy_user);
    fprintf(f, "pass=%s\n", g_proxy_pass);
    fprintf(f, "logging=%d\n", g_chk_logging);
    fprintf(f, "dns=%d\n", g_chk_dns);

    // rules section
    fprintf(f, "[RULES]\n");
    for (GList *l = g_rules_list; l != NULL; l = l->next) {
        RuleData *rule = (RuleData *)l->data;
        // format: id|protocol|action|enabled|procname|hosts|ports
        fprintf(f, "%u|%d|%d|%d|%s|%s|%s\n",
            rule->id,
            rule->protocol,
            rule->action,
            rule->enabled,
            rule->process_name ? rule->process_name : "",
            rule->target_hosts ? rule->target_hosts : "",
            rule->target_ports ? rule->target_ports : ""
        );
    }

    fclose(f);
}

// load settings from file
void load_config() {
    chmod(CONFIG_PATH, 0600); // tighten legacy world-readable installs
    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) return;

    char line[2048];
    int section = 0; // 0=none, 1=settings, 2=rules

    while (fgets(line, sizeof(line), f)) {
        // trim newline
        line[strcspn(line, "\r\n")] = 0;

        if (strlen(line) == 0 || line[0] == '#') continue;

        if (strcmp(line, "[SETTINGS]") == 0) { section = 1; continue; }
        if (strcmp(line, "[RULES]") == 0) { section = 2; continue; }

        if (section == 1) {
            char *val = strchr(line, '=');
            if (!val) continue;
            *val = 0; val++;

            if (strcmp(line, "ip") == 0) strncpy(g_proxy_ip, val, sizeof(g_proxy_ip) - 1);
            else if (strcmp(line, "port") == 0) g_proxy_port = atoi(val);
            else if (strcmp(line, "type") == 0) g_proxy_type = atoi(val);
            else if (strcmp(line, "user") == 0) strncpy(g_proxy_user, val, sizeof(g_proxy_user) - 1);
            else if (strcmp(line, "pass") == 0) strncpy(g_proxy_pass, val, sizeof(g_proxy_pass) - 1);
            else if (strcmp(line, "logging") == 0) g_chk_logging = atoi(val);
            else if (strcmp(line, "dns") == 0) g_chk_dns = atoi(val);
        }
        else if (section == 2) {
            // parse rule line
            RuleData *rule = g_malloc0(sizeof(RuleData));
            char *p = line;
            char *token;
            int idx = 0;

            while ((token = strsep(&p, "|")) != NULL) {
                switch(idx) {
                    case 0: rule->id = atoi(token); break;
                    case 1: rule->protocol = atoi(token); break;
                    case 2: rule->action = atoi(token); break;
                    case 3: rule->enabled = atoi(token); break;
                    case 4: rule->process_name = g_strdup(token); break;
                    case 5: rule->target_hosts = g_strdup(token); break;
                    case 6: rule->target_ports = g_strdup(token); break;
                }
                idx++;
            }

            if (idx >= 4) {
               g_rules_list = g_list_append(g_rules_list, rule);
            } else {
               g_free(rule);
            }
        }
    }
    fclose(f);
}