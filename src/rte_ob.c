// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#define LAN9662_TRACE_GROUP LAN9662_TRACE_GROUP_OB
#include "rte_private.h"

int lan9662_ob_init(struct lan9662_rte_inst *inst)
{
    T_I("enter");
    return 0;
}

int lan9662_ob_debug_print(struct lan9662_rte_inst *inst,
                           const lan9662_debug_printf_t pr,
                           const lan9662_debug_info_t   *const info)
{
    lan9662_debug_print_reg_header(pr, "RTE Outbound");
    lan9662_debug_reg(inst, pr, REG_ADDR(RTE_OUTB_CFG), "OUTB_CFG");
    pr("\n");
    return 0;
}
