// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#ifndef _LAN9662_RTE_RTE_H_
#define _LAN9662_RTE_RTE_H_

#include <stdint.h>

// Private type.
struct lan9662_rte_inst;

typedef int (*lan9662_rte_reg_rd_t)(struct lan9662_rte_inst *inst,
                                    const uintptr_t         *addr,
                                    uint32_t                *data);

typedef int (*lan9662_rte_reg_wr_t)(struct lan9662_rte_inst *inst,
                                    const uintptr_t         *addr,
                                    const uint32_t          *data);

typedef struct {
    lan9662_rte_reg_rd_t reg_rd;
    lan9662_rte_reg_wr_t reg_wr;
} lan9662_rte_cb_t;

struct lan9662_rte_inst *lan9662_rte_create(const lan9662_rte_cb_t *cb);

void lan9662_rte_destroy(struct lan9662_rte_inst *inst);

int lan9662_rte_test(struct lan9662_rte_inst *inst);

#endif // _LAN9662_RTE_RTE_H_
