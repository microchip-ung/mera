// Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/time.h>

#include "main.h"
#include "trace.h"
#include "cli.h"

static mscc_appl_trace_module_t *trace_module_list;

static mscc_appl_trace_module_t trace_module = {
    .name = "rte"
};

#define TRACE_GROUP_CNT LAN9662_TRACE_GROUP_CNT

static mscc_appl_trace_group_t trace_groups[TRACE_GROUP_CNT] = {
    {
        .name = "default",
        .level = LAN9662_TRACE_LEVEL_ERROR
    },
    {
        .name = "ib",
        .level = LAN9662_TRACE_LEVEL_ERROR
    },
    {
        .name = "ob",
        .level = LAN9662_TRACE_LEVEL_ERROR
    },
};

static void printf_trace_head(const char *mname,
                              const char *gname,
                              const lan9662_trace_level_t level,
                              const char *file,
                              const int line,
                              const char *function,
                              const char *lcont)
{
    struct timeval tv;
    int            h, m, s;
    const char     *p, *base_name = file;

    for (p = file; *p != 0; p++) {
        if (*p == '/' || *p == '\\') {
            base_name = (p + 1);
        }
    }

    (void)gettimeofday(&tv, NULL);
    h = (tv.tv_sec / 3600 % 24);
    m = (tv.tv_sec / 60 % 60);
    s = (tv.tv_sec % 60);
    printf("%u:%02u:%02u:%05lu %s/%s/%s %s(%u) %s%s",
           h, m, s, tv.tv_usec,
           mname,
           gname,
           level == LAN9662_TRACE_LEVEL_ERROR ? "error" :
           level == LAN9662_TRACE_LEVEL_INFO ? "info" :
           level == LAN9662_TRACE_LEVEL_DEBUG ? "debug" :
           level == LAN9662_TRACE_LEVEL_NOISE ? "noise" : "?",
           base_name, line, function, lcont);
}

static void lan9662_printf_trace_head(const lan9662_trace_group_t group,
                                      const lan9662_trace_level_t level,
                                      const char *file,
                                      const int line,
                                      const char *function,
                                      const char *lcont)
{
    printf_trace_head(trace_module.name,
                      group < TRACE_GROUP_CNT ? trace_groups[group].name : "?",
                      level,
                      file,
                      line,
                      function,
                      lcont);
}

void lan9662_callout_trace_printf(const lan9662_trace_group_t group,
                                  const lan9662_trace_level_t level,
                                  const char *file,
                                  const int line,
                                  const char *function,
                                  const char *format,
                                  ...)
{
    va_list args;

    lan9662_printf_trace_head(group, level, file, line, function, ": ");
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

void mscc_appl_trace_printf(const char *mname,
                            const char *gname,
                            const lan9662_trace_level_t level,
                            const char *file,
                            const int line,
                            const char *function,
                            const char *format,
                            ...)
{
    va_list args;

    va_start(args, format);
    mscc_appl_trace_vprintf(mname, gname, level, file, line, function, format, args);
    va_end(args);
}

void mscc_appl_trace_vprintf(const char *mname,
                             const char *gname,
                             const lan9662_trace_level_t level,
                             const char *file,
                             const int line,
                             const char *function,
                             const char *format,
                             va_list args)
{
    printf_trace_head(mname, gname, level, file, line, function, ": ");
    vprintf(format, args);
    printf("\n");
    fflush(stdout);
}

static void trace_hex(const unsigned char *byte_p, int byte_cnt)
{
    int i, j;

    for (i = 0; i < byte_cnt; i++) {
        j = (i == (byte_cnt - 1) ? 15 : (i % 16));
        if (j == 0) {
            printf("%04x: ", i);
        }
        printf("%02x%s", byte_p[i], j == 15 ? "\n" : (j & 3) == 3 ? "-" : " ");
        if (j == 15) {
            fflush(stdout);
        }
    }
}

void mscc_appl_trace_hex(const char *mname,
                         const char *gname,
                         const lan9662_trace_level_t level,
                         const char *file,
                         const int line,
                         const char *function,
                         const unsigned char *byte_p,
                         const int byte_cnt)
{
    char buf[32];

    sprintf(buf, ": hex dump, %u bytes\n", byte_cnt);
    printf_trace_head(mname, gname, level, file, line, function, buf);
    trace_hex(byte_p, byte_cnt);
}

void lan9662_callout_trace_hex_dump(const lan9662_trace_group_t group,
                                    const lan9662_trace_level_t level,
                                    const char               *file,
                                    const int                line,
                                    const char               *function,
                                    const unsigned char      *byte_p,
                                    const int                byte_cnt)
{
    lan9662_printf_trace_head(group, level, file, line, function, "\n");
    trace_hex(byte_p, byte_cnt);
}

/* ================================================================= *
 *  CLI
 * ================================================================= */

#define TRACE_NAME_MAX 64

typedef struct {
    char                  module_name[TRACE_NAME_MAX];
    char                  group_name[TRACE_NAME_MAX];
    lan9662_trace_level_t level;
    lan9662_debug_group_t group;
    int                   clear;
    int                   full;
} trace_cli_req_t;

static void trace_control(char *module_name, char *group_name, lan9662_trace_level_t level, int set)
{
    mscc_appl_trace_module_t *module;
    mscc_appl_trace_group_t  *group;
    lan9662_trace_conf_t     conf;
    int                      first = 1;
    int                      i;

    for (module = trace_module_list; module != NULL; module = module->next) {
        if (strlen(module_name) != 0 && strstr(module->name, module_name) != module->name) {
            continue;
        }

        for (group = module->group_list; group != NULL; group = group->next) {
            if (strlen(group_name) != 0 && strstr(group->name, group_name) != group->name) {
                continue;
            }
            if (set) {
                group->level = level;
            } else {
                if (first) {
                    cli_table_header("Module   Group       Level");
                    first = 0;
                }
                level = group->level;
                cli_printf("%-9s%-12s%s\n",
                           module->name,
                           group->name,
                           level == LAN9662_TRACE_LEVEL_NONE ? "off" :
                           level == LAN9662_TRACE_LEVEL_ERROR ? "error" :
                           level == LAN9662_TRACE_LEVEL_INFO ? "info" :
                           level == LAN9662_TRACE_LEVEL_DEBUG ? "debug" :
                           level == LAN9662_TRACE_LEVEL_NOISE ? "noise" : "?");
            }
        }
    }
    if (set) {
        // Update API trace configuration
        for (i = 0; i < TRACE_GROUP_CNT; i++) {
            if (lan9662_trace_conf_get(i, &conf) == 0) {
                conf.level = trace_groups[i].level;
                lan9662_trace_conf_set(i, &conf);
            }
        }
    }
}

static void cli_cmd_debug_trace(cli_req_t *req)
{
    trace_cli_req_t *mreq = req->module_req;

    trace_control(mreq->module_name, mreq->group_name, mreq->level, req->set);
}

static const char *const cli_api_group_table[LAN9662_DEBUG_GROUP_CNT] = {
    [LAN9662_DEBUG_GROUP_ALL] = "all",
    [LAN9662_DEBUG_GROUP_GEN] = "gen",
    [LAN9662_DEBUG_GROUP_IB]  = "ib",
    [LAN9662_DEBUG_GROUP_OB]  = "ob",
};

static void cli_cmd_debug_api(cli_req_t *req)
{
    lan9662_debug_info_t info;
    int                  group;
    trace_cli_req_t      *mreq = req->module_req;

    if (mreq->group == LAN9662_DEBUG_GROUP_CNT) {
        cli_printf("Legal groups are:\n\n");
        for (group = 0; group < LAN9662_DEBUG_GROUP_CNT; group++) {
            cli_printf("%s\n", cli_api_group_table[group]);
        }
    } else if (lan9662_debug_info_get(&info) == 0) {
        info.group = mreq->group;
        info.full = mreq->full;
        info.clear = mreq->clear;
        lan9662_debug_info_print(NULL, cli_printf, &info);
    }
}

static cli_cmd_t cli_cmd_table[] = {
    {
        "Debug Trace [<module>] [<group>] [off|error|info|debug|noise]",
        "Set or show the trace level for group",
        cli_cmd_debug_trace
    },
    {
        "Debug API [<group>] [full] [clear]",
        "Show API debug information",
        cli_cmd_debug_api
    },
};

static int cli_parm_wildcard(cli_req_t *req)
{
    return (strcmp(req->cmd, "*") == 0);
}

static int cli_parm_trace_module(cli_req_t *req)
{
    mscc_appl_trace_module_t *module;
    trace_cli_req_t          *mreq = req->module_req;

    if (cli_parm_wildcard(req)) {
        // Wildcard module accepted
        return 0;
    }

    for (module = trace_module_list; module != NULL; module = module->next) {
        if (strstr(module->name, req->cmd) == module->name) {
            // At least one module matches
            strcpy(mreq->module_name, req->cmd);
            return 0;
        }
    }
    return 1;
}

static int cli_parm_trace_group(cli_req_t *req)
{
    mscc_appl_trace_module_t *module;
    mscc_appl_trace_group_t  *group;
    trace_cli_req_t          *mreq = req->module_req;

    if (cli_parm_wildcard(req)) {
        // Wildcard group accepted
        return 0;
    }

    for (module = trace_module_list; module != NULL; module = module->next) {
        if (strlen(mreq->module_name) != 0 && strstr(module->name, mreq->module_name) != module->name) {
            continue;
        }
        for (group = module->group_list; group != NULL; group = group->next) {
            if (strstr(group->name, req->cmd) == group->name) {
                // At least one group matches
                strcpy(mreq->group_name, req->cmd);
                return 0;
            }
        }
    }
    return 1;
}

static int cli_parm_keyword(cli_req_t *req)
{
    const char      *found;
    trace_cli_req_t *mreq = req->module_req;

    if ((found = cli_parse_find(req->cmd, req->stx)) == NULL)
        return 1;

    if (!strncmp(found, "clear", 5))
        mreq->clear = 1;
    else if (!strncmp(found, "debug", 5))
        mreq->level = LAN9662_TRACE_LEVEL_DEBUG;
    else if (!strncmp(found, "error", 5))
        mreq->level = LAN9662_TRACE_LEVEL_ERROR;
    else if (!strncmp(found, "full", 4))
        mreq->full = 1;
    else if (!strncmp(found, "info", 4))
        mreq->level = LAN9662_TRACE_LEVEL_INFO;
    else if (!strncmp(found, "noise", 5))
        mreq->level = LAN9662_TRACE_LEVEL_NOISE;
    else if (!strncmp(found, "off", 3))
        mreq->level = LAN9662_TRACE_LEVEL_NONE;
    else
        cli_printf("no match:%s\n",found);

    return 0;
}

static int cli_parm_api_group(cli_req_t *req)
{
    int             error = 1;
    const char      *txt = "show";
    int             group;
    trace_cli_req_t *mreq = req->module_req;

    /* Accept 'show' keyword to display groups */
    if (strstr(txt, req->cmd) == txt) {
        mreq->group = LAN9662_DEBUG_GROUP_CNT;
        return 0;
    }

    for (group = 0; group < LAN9662_DEBUG_GROUP_CNT; group++) {
        txt = cli_api_group_table[group];
        if (txt != NULL && strstr(txt, req->cmd) == txt) {
            /* Found matching group */
            error = 0;
            mreq->group = group;
            break;
        }
    }
    return error;
}

static cli_parm_t cli_parm_table[] = {
    {
        "<module>",
        "Trace module, default: All modules",
        CLI_PARM_FLAG_NONE,
        cli_parm_trace_module
    },
    {
        "<group>",
        "Trace group name, default: All groups",
        CLI_PARM_FLAG_NONE,
        cli_parm_trace_group,
        cli_cmd_debug_trace
    },
    {
        "off|error|info|debug|noise",
        "off     : No trace\n"
        "error   : Error trace level\n"
        "info    : Information trace level\n"
        "debug   : Debug trace level\n"
        "noise   : Noise trace level\n"
        "(default: Show trace level)",
        CLI_PARM_FLAG_NO_TXT | CLI_PARM_FLAG_SET,
        cli_parm_keyword
    },
    {
        "<group>",
        "API Function Group or 'show' to list groups (default: All groups)",
        CLI_PARM_FLAG_NONE,
        cli_parm_api_group
    },
    {
        "clear",
        "Clear sticky bits",
        CLI_PARM_FLAG_NONE,
        cli_parm_keyword
    },
    {
        "full",
        "Show full information",
        CLI_PARM_FLAG_NONE,
        cli_parm_keyword
    },
};

static void trace_cli_init(void)
{
    int i;

    /* Register commands */
    for (i = 0; i < sizeof(cli_cmd_table)/sizeof(cli_cmd_t); i++) {
        mscc_appl_cli_cmd_reg(&cli_cmd_table[i]);
    }

    /* Register parameters */
    for (i = 0; i < sizeof(cli_parm_table)/sizeof(cli_parm_t); i++) {
        mscc_appl_cli_parm_reg(&cli_parm_table[i]);
    }
}

static void trace_module_register(mscc_appl_trace_module_t *module)
{
    mscc_appl_trace_module_t *cur, *prev = NULL;
    int                      cmp;

    // Build sorted list of modules
    for (cur = trace_module_list; cur != NULL; prev = cur, cur = cur->next) {
        cmp = strcmp(cur->name, module->name);
        if (cmp == 0) {
            fprintf(stderr, "duplicate trace module: %s\n", cur->name);
            return;
        } else if (cmp > 0) {
            // Found greater name
            break;
        }
    }
    if (prev == NULL) {
        // Insert first
        module->next = trace_module_list;
        trace_module_list = module;
    } else {
        // Insert after previous entry
        module->next = prev->next;
        prev->next = module;
    }
}

void mscc_appl_trace_register(mscc_appl_trace_module_t *module,
                              mscc_appl_trace_group_t *group_table,
                              uint32_t group_count)
{
    mscc_appl_trace_group_t *group, *cur, *prev;
    int                     i, cmp;

    /* Build sorted list of groups */
    module->group_list = NULL;
    for (i = 0; i < group_count; i++) {
        group = &group_table[i];
        for (cur = module->group_list, prev = NULL; cur != NULL; prev = cur, cur = cur->next) {
            cmp = strcmp(cur->name, group->name);
            if (cmp == 0) {
                fprintf(stderr, "duplicate trace group: %s for module: %s\n", cur->name, module->name);
                return;
            } else if (cmp > 0) {
                // Found greater name
                break;
            }
        }
        if (prev == NULL) {
            // Insert first
            group->next = module->group_list;
            module->group_list = group;
        } else {
            // Insert after previous entry
            group->next = prev->next;
            prev->next = group;
        }
    }
    trace_module_register(module);
}

static int trace_option(char *parm)
{
    char                  *module_name, *group_name, *level_name, c;
    lan9662_trace_level_t level;

    module_name = strtok(parm, ":");
    group_name = strtok(NULL, ":");
    level_name = strtok(NULL, ":");

    if (module_name == NULL || group_name == NULL || level_name == NULL) {
        fprintf(stderr, "please specify <module>:<group>:<level>\n");
        return -1;
    }
    if (*module_name == '*') {
        *module_name = 0;
    }
    if (*group_name == '*') {
        *group_name = 0;
    }
    c = (level_name != NULL && strlen(level_name) ? level_name[0] : 'z');
    level = (c == 'o' ? LAN9662_TRACE_LEVEL_NONE :
             c == 'e' ? LAN9662_TRACE_LEVEL_ERROR :
             c == 'i' ? LAN9662_TRACE_LEVEL_INFO :
             c == 'd' ? LAN9662_TRACE_LEVEL_DEBUG :
             c == 'n' ? LAN9662_TRACE_LEVEL_NOISE : LAN9662_TRACE_LEVEL_CNT);
    if (level == LAN9662_TRACE_LEVEL_CNT) {
        fprintf(stderr, "illegal trace level\n");
        return -1;
    }
    trace_control(module_name, group_name, level, 1);
    return 0;
}

static mscc_appl_opt_t trace_opt = {
    "t:",
    "<module>:<group>:<level>",
    "Set trace level for <module> and <group>, use '*' for wildcard" ,
    trace_option
};

void mscc_appl_trace_init(mscc_appl_init_t *init)
{
    switch (init->cmd) {
    case MSCC_INIT_CMD_REG:
        // Register RTE API trace
        mscc_appl_trace_register(&trace_module, trace_groups, TRACE_GROUP_CNT);

        // Register startup options
        mscc_appl_opt_reg(&trace_opt);
        break;

    case MSCC_INIT_CMD_INIT:
        trace_cli_init();
        break;

    default:
        break;
    }
}
