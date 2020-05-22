// Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT


#ifndef _MSCC_APPL_CLI_H_
#define _MSCC_APPL_CLI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "main.h"

/* Initialize CLI */
void mscc_appl_cli_init(mscc_appl_init_t *init);

/* CLI request block */
typedef struct {
    /* Parameter parser input */
    const char *cmd;
    const char *stx;
    const char *cmd_org;
    int   parm_parsed;
    uint32_t cmd_flags;

    int set;

    // Keywords
    int enable;
    int disable;


    // Module specific parser data
    uint8_t module_data[10240];
    void    *module_req;
} cli_req_t;

#define CLI_CMD_FLAG_NONE      0x00000000
#define CLI_CMD_FLAG_ALL_PORTS 0x00000001

/* CLI command entry */
typedef struct cli_cmd_t {
    const char         *syntax;    /* Syntax string */
    const char         *descr;     /* Description string */
    void (* func)(cli_req_t *req); /* Command function */
    uint32_t           flags;      /* Optional command flags */
    int (* func2)(int argc, const char **argv); /* Command function */

    /* Internal fields */
    struct cli_cmd_t *next;       /* Next in registration list */
    struct cli_cmd_t *match_next; /* Next in match list */
} cli_cmd_t;

void mscc_appl_cli_cmd_reg(cli_cmd_t *cmd);

#define CLI_PARM_FLAG_NONE   0x00000000 /* No flags */
#define CLI_PARM_FLAG_NO_TXT 0x00000001 /* Suppress identification text */
#define CLI_PARM_FLAG_SET    0x00000002 /* Set operation parameter */

/* CLI parameter entry */
typedef struct cli_parm_t {
    const char            *txt;    /* Identification text */
    const char            *help;   /* Help text */
    const uint32_t        flags;   /* Miscellaneous flags */
    int  (* parse_func)(cli_req_t *req); /* Parser function */
    void (* cmd_func)(cli_req_t *req);   /* Optional command function */

    /* Internal fields */
    struct cli_parm_t     *next;   /* Next in registration list */
    int                   done;    /* Temporary flag */
} cli_parm_t;

void mscc_appl_cli_parm_reg(cli_parm_t *parm);

void cli_table_header(const char *txt);
int cli_parm_u8(cli_req_t *req, uint8_t *val, uint32_t min, uint32_t max);
int cli_parm_u16(cli_req_t *req, uint16_t *val, uint32_t min, uint32_t max);
int cli_parm_u32(cli_req_t *req, uint32_t *val, uint32_t min, uint32_t max);
const char *cli_parse_find(const char *cmd, const char *stx);
int cli_printf(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* _MSCC_APPL_CLI_H_ */
