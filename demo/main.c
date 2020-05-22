// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "main.h"
#include "trace.h"

static mscc_appl_trace_module_t trace_module = {
    .name = "main"
};

enum {
    TRACE_GROUP_DEFAULT,
    TRACE_GROUP_CNT
};

static mscc_appl_trace_group_t trace_groups[TRACE_GROUP_CNT] = {
    {
        .name = "default",
        .level = LAN9662_TRACE_LEVEL_ERROR
    },
};

/* ================================================================= *
 *  Option parsing
 * ================================================================= */

static mscc_appl_opt_t *main_opt_list;

void mscc_appl_opt_reg(mscc_appl_opt_t *opt)
{
    mscc_appl_opt_t *cur, *prev = NULL;
    int             cmp;

    for (cur = main_opt_list; cur != NULL; prev = cur, cur = cur->next) {
        cmp = strncmp(cur->option, opt->option, 1);
        if (cmp == 0) {
            fprintf(stderr, "duplicate option: %s\n", cur->option);
            return;
        } else if (cmp > 0) {
            // Found greater option
            break;
        }
    }
    if (prev == NULL) {
        // Insert first
        opt->next = main_opt_list;
        main_opt_list = opt;
    } else {
        // Insert after previous entry
        opt->next = prev->next;
        prev->next = opt;
    }
}

static void main_parse_options(int argc, char **argv)
{
    mscc_appl_opt_t *opt;
    char            buf[256], *p = buf;
    int             option;

    // Build option string
    for (opt = main_opt_list; opt != NULL; opt = opt->next) {
        p += sprintf(p, "%s", opt->option);
    }

    while ((option = getopt(argc, argv, buf)) != -1) {
        // Call registered option function
        for (opt = main_opt_list; opt != NULL; opt = opt->next) {
            if (opt->option[0] == option && opt->func(optarg) != 0) {
                exit(0);
            }
        }
    }
}

static int help_option(char *parm)
{
    mscc_appl_opt_t *opt;
    int             i, len, max_len = 0;

    printf("mesa_demo options:\n\n");
    for (i = 0; i < 2; i++) {
        for (opt = main_opt_list; opt != NULL; opt = opt->next) {
            if (i) {
                printf("-%c %-*s : %s\n", opt->option[0], max_len, opt->parm ? opt->parm : "", opt->descr);
            } else if (opt->parm && (len = strlen(opt->parm)) > max_len) {
                max_len = len;
            }
        }
    }
    return -1;
}

static mscc_appl_opt_t main_opt = {
    "h",
    NULL,
    "Show this help text",
    help_option
};

static int run_in_foreground = 0;
static int option_foreground(char *parm)
{
    run_in_foreground = 1;
    return 0;
}

static mscc_appl_opt_t main_opt_foreground = {
    "f",
    NULL,
    "Run in foreground",
    option_foreground
};


static void main_init(mscc_appl_init_t *init)
{
    switch (init->cmd) {
    case MSCC_INIT_CMD_REG:
        mscc_appl_trace_register(&trace_module, trace_groups, TRACE_GROUP_CNT);
        mscc_appl_opt_reg(&main_opt);
        mscc_appl_opt_reg(&main_opt_foreground);
        break;

    case MSCC_INIT_CMD_INIT:
        //main_cli_init();
        break;

    default:
        break;
    }

}

static void init_modules(mscc_appl_init_t *init)
{
    main_init(init);
    mscc_appl_cli_init(init);
    mscc_appl_trace_init(init);
    mscc_appl_uio_init(init);
}

typedef struct {
    int                fd;
    fd_read_callback_t cb;
    void               *ref;
} fd_read_reg_t;

#define FD_REG_MAX 32
fd_read_reg_t fd_reg_table[FD_REG_MAX];

int fd_read_register(int fd, fd_read_callback_t cb, void *ref)
{
    int           i, free = -1;
    fd_read_reg_t *reg;

    if (fd <= 0) {
        T_E("illegal fd: %d", fd);
        return -1;
    }

    for (i = 0; i < FD_REG_MAX; i++) {
        reg = &fd_reg_table[i];
        if (reg->fd == fd) {
            if (cb == NULL) {
                // Deregistration
                reg->fd = 0;
            } else {
                // Re-registration
                reg->cb = cb;
                reg->ref = ref;
            }
            return 0;
        } else if (cb != NULL && reg->fd == 0 && free < 0) {
            // First free entry found
            free = i;
        }
    }
    if (free < 0) {
        return -1;
    }
    // New registration
    reg = &fd_reg_table[free];
    reg->fd = fd;
    reg->cb = cb;
    reg->ref = ref;
    return 0;
}

int main(int argc, char **argv)
{
    mscc_appl_init_t        init;
    struct lan9662_rte_inst *inst;
    lan9662_rte_cb_t        cb = {};
    struct timeval          tv;
    int                     i, fd, fd_max, poll_cnt = 0;
    fd_set                  rfds;
    fd_read_reg_t           *reg;

    // Register trace
    init.cmd = MSCC_INIT_CMD_REG;
    init_modules(&init);

    // Parse options
    main_parse_options(argc, argv);

    if (!run_in_foreground && daemon(0, 1) < 0) {
        T_E("daemon failed");
        return 1;
    }

    if (uio_init() < 0) {
        T_E("uio_init() failed");
        return 1;
    }
    cb.reg_rd = uio_reg_read;
    cb.reg_wr = uio_reg_write;

    if ((inst = lan9662_rte_create(&cb)) == NULL) {
        T_E("rte_create() failed");
        return 1;
    }

    // Initialize modules
    init.cmd = MSCC_INIT_CMD_INIT;
    init_modules(&init);

    // Poll modules
    while (1) {
        FD_ZERO(&rfds);
        fd_max = 0;
        for (i = 0; i < FD_REG_MAX; i++) {
            fd = fd_reg_table[i].fd;
            if (fd > 0) {
                FD_SET(fd, &rfds);
                if (fd > fd_max) {
                    fd_max = fd;
                }
            }
        }
        tv.tv_sec = 0;
        tv.tv_usec = 10000;
        if (select(fd_max + 1, &rfds, NULL, NULL, &tv) < 0) {
            T_E("select() failed");
        } else {
            for (i = 0; i < FD_REG_MAX; i++) {
                reg = &fd_reg_table[i];
                if (reg->fd > 0 && FD_ISSET(reg->fd, &rfds)) {
                    reg->cb(reg->fd, reg->ref);
                }
            }
        }
        init.cmd = MSCC_INIT_CMD_POLL_FAST;
        init_modules(&init);
        poll_cnt++;
        if (poll_cnt >= 100) {
            poll_cnt = 0;
            init.cmd = MSCC_INIT_CMD_POLL;
            init_modules(&init);
        }
    }
    return 0;
}
