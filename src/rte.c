// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#include "rte_private.h"

static struct lan9662_rte_inst *lan9662_default_inst;

struct lan9662_rte_inst *lan9662_inst_get(struct lan9662_rte_inst *inst)
{
    return (inst ? inst : lan9662_default_inst);
}

/* ================================================================= *
 *  Trace
 * ================================================================= */

lan9662_trace_conf_t lan9662_trace_conf[LAN9662_TRACE_GROUP_CNT] =
{
    [LAN9662_TRACE_GROUP_DEFAULT] = {
        .level = LAN9662_TRACE_LEVEL_ERROR
    },
    [LAN9662_TRACE_GROUP_IB] = {
        .level = LAN9662_TRACE_LEVEL_ERROR
    },
    [LAN9662_TRACE_GROUP_OB] = {
        .level = LAN9662_TRACE_LEVEL_ERROR
    },
};

/* Get trace configuration */
int lan9662_trace_conf_get(const lan9662_trace_group_t group,
                           lan9662_trace_conf_t *const conf)
{
    if (group >= LAN9662_TRACE_GROUP_CNT) {
        T_E("illegal group: %d", group);
        return -1;
    }
    *conf = lan9662_trace_conf[group];
    return 0;
}

/* Set trace configuration */
int lan9662_trace_conf_set(const lan9662_trace_group_t group,
                           const lan9662_trace_conf_t *const conf)
{
    if (group >= LAN9662_TRACE_GROUP_CNT) {
        T_E("illegal group: %d", group);
        return -1;
    }
    lan9662_trace_conf[group] = *conf;
    return 0;
}

/* ================================================================= *
 *  Register access
 * ================================================================= */
void lan9662_reg_error(const char *file, int line) {
    printf("\n\nFATAL ERROR at %s:%d> Index exceeds replication!\n\n", file, line);
    lan9662_callout_trace_printf(LAN9662_TRACE_GROUP_DEFAULT,
                                 LAN9662_TRACE_LEVEL_ERROR, file, line, file,
                                 "Index exceeds replication!");
}

/* Read target register using current CPU interface */
int lan9662_rd(struct lan9662_rte_inst *inst, uint32_t addr, uint32_t *value)
{
    return inst->cb.reg_rd(inst, addr, value);
}

/* Write target register using current CPU interface */
int lan9662_wr(struct lan9662_rte_inst *inst, uint32_t addr, uint32_t value)
{
    return inst->cb.reg_wr(inst, addr, value);
}

/* Read-modify-write target register using current CPU interface */
int lan9662_wrm(struct lan9662_rte_inst *inst, uint32_t addr, uint32_t value, uint32_t mask)
{
    int      rc;
    uint32_t val;

    if ((rc = lan9662_rd(inst, addr, &val)) == 0) {
        val = ((val & ~mask) | (value & mask));
        rc = lan9662_wr(inst, addr, val);
    }
    return rc;
}

/* ================================================================= *
 *  Initialization
 * ================================================================= */

static int lan9662_gen_init(struct lan9662_rte_inst *inst)
{
    uint32_t val, diff;

    T_I("enter");
    REG_RD(GCB_BUILDID, &val);
    if (val > LAN966X_BUILD_ID) {
        diff = (val - LAN966X_BUILD_ID);
    } else {
        diff = (LAN966X_BUILD_ID - val);
    }
    if (diff > 1000) {
        T_E("unexpected build id. Got: %08x, expected %08x, diff: %u", val, LAN966X_BUILD_ID, diff);
        return -1;
    }
    T_I("build id: 0x%08x", val);
    return 0;
}

static int lan9662_rte_init(struct lan9662_rte_inst *inst)
{
    T_I("enter");
    LAN9662_RC(lan9662_gen_init(inst));
    LAN9662_RC(lan9662_ib_init(inst));
    LAN9662_RC(lan9662_ob_init(inst));
    return 0;
}

struct lan9662_rte_inst *lan9662_rte_create(const lan9662_rte_cb_t *cb)
{
    struct lan9662_rte_inst *inst = calloc(1, sizeof(struct lan9662_rte_inst));

    T_I("enter");
    if (inst) {
        inst->cb = *cb;
        if (lan9662_rte_init(inst)) {
            free(inst);
            inst = NULL;
        } else {
            lan9662_default_inst = inst;
        }
    }
    return inst;
}

void lan9662_rte_destroy(struct lan9662_rte_inst *inst)
{
    T_I("enter");
    inst = lan9662_inst_get(inst);
    free(inst);
}

int lan9662_rte_gen_conf_get(struct lan9662_rte_inst *inst,
                             lan9662_rte_gen_conf_t  *const conf)
{
    T_I("enter");
    inst = lan9662_inst_get(inst);
    *conf = inst->gen.conf;
    return 0;
}

int lan9662_rte_gen_conf_set(struct lan9662_rte_inst      *inst,
                             const lan9662_rte_gen_conf_t *const conf)
{
    T_I("enter");
    inst = lan9662_inst_get(inst);
    inst->gen.conf = *conf;
    return 0;
}

/* ================================================================= *
 *  Debug print
 * ================================================================= */

int lan9662_debug_info_get(lan9662_debug_info_t *const info)
{
    memset(info, 0, sizeof(*info));
    return 0;
}

void lan9662_debug_print_reg_header(const lan9662_debug_printf_t pr, const char *name)
{
    pr("%-20s  31    24.23    16.15     8.7      0  Hex         Decimal\n", name);
}

static void lan9662_debug_print_reg(const lan9662_debug_printf_t pr, const char *name, uint32_t value)
{
    uint32_t i;

    pr("%-20s: ", name);
    for (i = 0; i < 32; i++) {
        pr("%s%u", i == 0 || (i % 8) ? "" : ".", value & (1 << (31 - i)) ? 1 : 0);
    }
    pr("  0x%08x  %u\n", value, value);
}

void lan9662_debug_reg(struct lan9662_rte_inst *inst,
                       const lan9662_debug_printf_t pr, uint32_t addr, const char *name)
{
    uint32_t value;

    if (lan9662_rd(inst, addr, &value) == 0) {
        lan9662_debug_print_reg(pr, name, value);
    }
}

void lan9662_debug_reg_inst(struct lan9662_rte_inst *inst,
                            const lan9662_debug_printf_t pr,
                            uint32_t addr, uint32_t i, const char *name)
{
    char buf[64];

    sprintf(buf, "%s_%u", name, i);
    lan9662_debug_reg(inst, pr, addr, buf);
}

static int lan9662_gen_debug_print(struct lan9662_rte_inst *inst,
                                   const lan9662_debug_printf_t pr,
                                   const lan9662_debug_info_t   *const info)
{
    lan9662_debug_print_reg_header(pr, "RTE General");
    lan9662_debug_reg(inst, pr, REG_ADDR(RTE_RTE_CFG), "RTE_CFG");
    lan9662_debug_reg(inst, pr, REG_ADDR(RTE_RUT), "RUT");
    pr("\n");

    return 0;
}

int lan9662_debug_info_print(struct lan9662_rte_inst *inst,
                             const lan9662_debug_printf_t pr,
                             const lan9662_debug_info_t   *const info)
{
    int all = (info->group == LAN9662_DEBUG_GROUP_ALL);

    inst = lan9662_inst_get(inst);
    if (all || info->group == LAN9662_DEBUG_GROUP_GEN) {
        lan9662_gen_debug_print(inst, pr, info);
    }
    if (all || info->group == LAN9662_DEBUG_GROUP_IB) {
        lan9662_ib_debug_print(inst, pr, info);
    }
    if (all || info->group == LAN9662_DEBUG_GROUP_OB) {
        lan9662_ob_debug_print(inst, pr, info);
    }
    return 0;
}
