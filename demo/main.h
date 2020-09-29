// Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT


#ifndef _MSCC_APPL_MAIN_H_
#define _MSCC_APPL_MAIN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "microchip/ethernet/rte/api.h"

typedef enum {
    MSCC_INIT_CMD_REG,       // Register trace and startup options
    MSCC_INIT_CMD_INIT,      // Initialize module
    MSCC_INIT_CMD_INIT_WARM, // Initialize module after warm start
    MSCC_INIT_CMD_POLL,      // Poll module every second
    MSCC_INIT_CMD_POLL_FAST  // Poll module fast
} mscc_appl_init_cmd_t;

// Startup option
typedef struct mscc_appl_opt_t {
    char *option; // Option character, e.g "t:"
    char *parm;   // Option parameter, e.g. "<module>:<group>:<level>
    char *descr;  // Description
    int (* func)(char *parm); // Command function

    // Internal fields
    struct mscc_appl_opt_t *next;       /* Next in registration list */
} mscc_appl_opt_t;

void mscc_appl_opt_reg(mscc_appl_opt_t *opt);

typedef struct {
    mscc_appl_init_cmd_t cmd;
} mscc_appl_init_t;

// Module init functions
void mscc_appl_debug_init(mscc_appl_init_t *init);
void mscc_appl_trace_init(mscc_appl_init_t *init);
void mscc_appl_cli_init(mscc_appl_init_t *init);
void mscc_appl_json_rpc_init(mscc_appl_init_t *init);
void mscc_appl_uio_init(mscc_appl_init_t *init);

int uio_init(void);
int uio_reg_read(struct mera_inst *inst,
                 const uintptr_t  addr,
                 uint32_t         *data);
int uio_reg_write(struct mera_inst *inst,
                  const uintptr_t  addr,
                  const uint32_t   data);
    
// File descriptor read activity callback registration
typedef void (*fd_read_callback_t)(int fd, void *ref);
int fd_read_register(int fd, fd_read_callback_t callback, void *ref);

#ifdef __cplusplus
}
#endif

#endif /* _MSCC_APPL_MAIN_H_ */
