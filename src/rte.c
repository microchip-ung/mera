// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#include "rte_private.h"

static struct mera_inst *mera_default_inst;

struct mera_inst *mera_inst_get(struct mera_inst *inst)
{
    return (inst ? inst : mera_default_inst);
}

/* ================================================================= *
 *  Trace
 * ================================================================= */

mera_trace_conf_t mera_trace_conf[MERA_TRACE_GROUP_CNT] =
{
    [MERA_TRACE_GROUP_DEFAULT] = {
        .level = MERA_TRACE_LEVEL_ERROR
    },
    [MERA_TRACE_GROUP_IB] = {
        .level = MERA_TRACE_LEVEL_ERROR
    },
    [MERA_TRACE_GROUP_OB] = {
        .level = MERA_TRACE_LEVEL_ERROR
    },
};

/* Get trace configuration */
int mera_trace_conf_get(const mera_trace_group_t group,
                        mera_trace_conf_t *const conf)
{
    if (group >= MERA_TRACE_GROUP_CNT) {
        T_E("illegal group: %d", group);
        return -1;
    }
    *conf = mera_trace_conf[group];
    return 0;
}

/* Set trace configuration */
int mera_trace_conf_set(const mera_trace_group_t group,
                        const mera_trace_conf_t *const conf)
{
    if (group >= MERA_TRACE_GROUP_CNT) {
        T_E("illegal group: %d", group);
        return -1;
    }
    mera_trace_conf[group] = *conf;
    return 0;
}

/* ================================================================= *
 *  Register access
 * ================================================================= */
void mera_reg_error(const char *file, int line)
{
    printf("\n\nFATAL ERROR at %s:%d> Index exceeds replication!\n\n", file, line);
    mera_callout_trace_printf(MERA_TRACE_GROUP_DEFAULT,
                              MERA_TRACE_LEVEL_ERROR, file, line, file,
                              "Index exceeds replication!");
}

/* Read target register using current CPU interface */
int mera_rd(struct mera_inst *inst, uint32_t addr, uint32_t *value)
{
    return inst->cb.reg_rd(inst, addr, value);
}

/* Write target register using current CPU interface */
int mera_wr(struct mera_inst *inst, uint32_t addr, uint32_t value)
{
    return inst->cb.reg_wr(inst, addr, value);
}

/* Read-modify-write target register using current CPU interface */
int mera_wrm(struct mera_inst *inst, uint32_t addr, uint32_t value, uint32_t mask)
{
    int      rc;
    uint32_t val;

    if ((rc = mera_rd(inst, addr, &val)) == 0) {
        val = ((val & ~mask) | (value & mask));
        rc = mera_wr(inst, addr, val);
    }
    return rc;
}

/* ================================================================= *
 *  Initialization
 * ================================================================= */

static int mera_gen_init(struct mera_inst *inst)
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

static int mera_init(struct mera_inst *inst)
{
    T_I("enter");
    MERA_RC(mera_gen_init(inst));
    MERA_RC(mera_ib_init(inst));
    MERA_RC(mera_ob_init(inst));
    return 0;
}

struct mera_inst *mera_create(const mera_cb_t *cb)
{
    struct mera_inst *inst = calloc(1, sizeof(struct mera_inst));

    T_I("enter");
    if (inst) {
        inst->cb = *cb;
        if (mera_init(inst)) {
            free(inst);
            inst = NULL;
        } else {
            mera_default_inst = inst;
        }
    }
    return inst;
}

void mera_destroy(struct mera_inst *inst)
{
    T_I("enter");
    inst = mera_inst_get(inst);
    free(inst);
}

int mera_gen_conf_get(struct mera_inst *inst,
                      mera_gen_conf_t  *const conf)
{
    T_I("enter");
    inst = mera_inst_get(inst);
    *conf = inst->gen.conf;
    return 0;
}

int mera_gen_conf_set(struct mera_inst      *inst,
                      const mera_gen_conf_t *const conf)
{
    mera_gen_t *gen;

    T_I("enter");
    inst = mera_inst_get(inst);
    gen = &inst->gen;
    switch (conf->intf) {
    case MERA_IO_INTF_QSPI:
        gen->rai_base = 0x40000000;
        break;
    case MERA_IO_INTF_PI:
        gen->rai_base = 0x48000000;
        break;
    case MERA_IO_INTF_SRAM:
        // Use 128/3 = 42 kB for 3-buffer system
        gen->rai_base = 0x00100000;
        gen->rai_offset = RTE_BUF3_SIZE;
        break;
    case MERA_IO_INTF_PCIE:
        gen->rai_base = 0x10000000;
        break;
    default:
        T_E("unknown I/O");
        return -1;
    }
    gen->conf = *conf;
    REG_WR(RTE_RTE_CFG, RTE_RTE_CFG_RTE_ENA(conf->enable ? 1 : 0));
    REG_WR(RTE_SC_LEN, RTE_SC_LEN_SC_LEN(20000000)); // 20.000.000 x 50 nsec = 1 sec
    REG_WR(RTE_SC_RESET, RTE_SC_RESET_SC_RESET_TIME_NS(1));
    return 0;
}

int mera_poll(struct mera_inst *inst)
{
    T_I("enter");
    inst = mera_inst_get(inst);
    MERA_RC(mera_ib_poll(inst));
    MERA_RC(mera_ob_poll(inst));
    return 0;
}

void mera_cnt_16_update(uint16_t value, mera_counter_t *counter, int clear)
{
    uint64_t add = 0;

    if (clear) {
        // Clear counter
        counter->value = 0;
    } else {
        // Accumulate counter
        if (value < counter->prev) {
            add = (1ULL << 16); /* Wrapped */
        }
        counter->value += (value + add - counter->prev);
    }
    counter->prev = value;
}

/* ================================================================= *
 *  Debug print
 * ================================================================= */

int mera_debug_info_get(mera_debug_info_t *const info)
{
    memset(info, 0, sizeof(*info));
    return 0;
}

void mera_debug_print_reg_header(const mera_debug_printf_t pr, const char *name)
{
    pr("%-20s  31    24.23    16.15     8.7      0  Hex         Decimal\n", name);
}

void mera_debug_print_reg_mask(const mera_debug_printf_t pr, const char *name, uint32_t value, uint32_t mask)
{
    uint32_t i, m, v = value;

    if (mask == 0xffffffff) {
        pr("%-20s", name);
    } else {
        pr(":%-19s", name);
        for (i = 0; i < 32; i++) {
            if ((1 << i) & mask) {
                v = (v << i);
                break;
            }
        }
    }
    pr(": ");
    for (i = 0; i < 32; i++) {
        m = (1 << (31 - i));
        pr("%s%s", i == 0 || (i % 8) ? "" : ".", (mask & m) == 0 ? " " : v & m ? "1" : "0");
    }
    pr("  0x%08x  %u\n", value, value);
}

void mera_debug_print_reg(const mera_debug_printf_t pr, const char *name, uint32_t value)
{
    mera_debug_print_reg_mask(pr, name, value, 0xffffffff);
}

void mera_debug_reg(struct mera_inst *inst,
                    const mera_debug_printf_t pr, uint32_t addr, const char *name)
{
    uint32_t value;

    if (mera_rd(inst, addr, &value) == 0) {
        mera_debug_print_reg(pr, name, value);
    }
}

void mera_debug_reg_inst(struct mera_inst *inst,
                            const mera_debug_printf_t pr,
                            uint32_t addr, uint32_t i, const char *name)
{
    char buf[64];

    sprintf(buf, "%s_%u", name, i);
    mera_debug_reg(inst, pr, addr, buf);
}

static int mera_gen_debug_print(struct mera_inst *inst,
                                const mera_debug_printf_t pr,
                                const mera_debug_info_t   *const info)
{
    mera_gen_t      *gen = &inst->gen;
    mera_gen_conf_t *conf = &gen->conf;
    uint32_t        value;

    mera_debug_print_header(pr, "RTE General State");
    pr("RTE State : %s\n", conf->enable ? "Enabled" : "Disabled");
    pr("RTE I/O   : %s\n",
       conf->intf == MERA_IO_INTF_QSPI ? "QSPI" :
       conf->intf == MERA_IO_INTF_PI ? "PI" :
       conf->intf == MERA_IO_INTF_SRAM ? "SRAM" :
       conf->intf == MERA_IO_INTF_PCIE ? "PCIe" : "?");
    pr("RAI Base  : 0x%08x\n", gen->rai_base);
    pr("RAI Offset: 0x%08x\n", gen->rai_offset);
    pr("\n");

    mera_debug_print_header(pr, "RTE General Registers");
    mera_debug_print_reg_header(pr, "RTE General");
    DBG_REG(REG_ADDR(RTE_RTE_CFG), "RTE_CFG");
    DBG_REG(REG_ADDR(RTE_RUT), "RUT");
    DBG_REG(REG_ADDR(RTE_SC_LEN), "SC_LEN");
    REG_RD(RTE_SC_TIME, &value);
    DBG_PR_REG("SC_TIME", value);
    DBG_PR_REG_M("SC_RUT_CNT", RTE_SC_TIME_SC_RUT_CNT, value);
    DBG_PR_REG_M("SC_IDX", RTE_SC_TIME_SC_IDX, value);
    value = (RTE_SC_TIME_SC_IDX_X(value) * (RTE_SC_TIME_SC_RUT_CNT_M + 1) + RTE_SC_TIME_SC_RUT_CNT_X(value));
    DBG_PR_REG(":SC_IDX:SC_RUT_CNT", value);
    pr("\n");

    return 0;
}

void mera_debug_print_header(const mera_debug_printf_t pr,
                             const char *header)
{
    int i, len = strlen(header);

    pr("%s\n", header);
    for (i = 0; i < len; i++) {
        pr("=");
    }
    pr("\n\n");
}

int mera_debug_info_print(struct mera_inst *inst,
                          const mera_debug_printf_t pr,
                          const mera_debug_info_t   *const info)
{
    int all = (info->group == MERA_DEBUG_GROUP_ALL);

    inst = mera_inst_get(inst);
    if (all || info->group == MERA_DEBUG_GROUP_GEN) {
        mera_gen_debug_print(inst, pr, info);
    }
    if (all || info->group == MERA_DEBUG_GROUP_IB) {
        mera_ib_debug_print(inst, pr, info);
    }
    if (all || info->group == MERA_DEBUG_GROUP_OB) {
        mera_ob_debug_print(inst, pr, info);
    }
    return 0;
}
