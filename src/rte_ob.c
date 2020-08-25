// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#define MERA_TRACE_GROUP MERA_TRACE_GROUP_OB
#include "rte_private.h"

// Profinet DataStatus value/mask
#define RTE_OB_PN_DS_MASK 0xb7
#define RTE_OB_PN_DS_VAL  0x35

int mera_ob_init(struct mera_inst *inst)
{
    uint32_t i;

    T_I("enter");

    REG_WR(RTE_OUTB_RTP_STATE, 0xffffffff);
    REG_WR(RTE_OUTB_CFG, RTE_OUTB_CFG_OUTB_PORT(4));

    // Data/transfer status checks
    REG_WR(RTE_OUTB_PN_PDU_MISC,
           RTE_OUTB_PN_PDU_MISC_PN_DATA_STATUS_MASK(RTE_OB_PN_DS_MASK) |
           RTE_OUTB_PN_PDU_MISC_PN_DATA_STATUS_VALID_CHK_ENA(0) |
           RTE_OUTB_PN_PDU_MISC_PN_TRANSFER_STATUS_CHK_ENA(1));

    // OPC PDU checks
    REG_WR(RTE_OUTB_OPC_PDU_FLAGS,
           RTE_OUTB_OPC_PDU_FLAGS_OPC_EXT_FLAGS1_VAL(0x01) |
           RTE_OUTB_OPC_PDU_FLAGS_OPC_EXT_FLAGS1_MASK(0xff) |
           RTE_OUTB_OPC_PDU_FLAGS_OPC_GRP_FLAGS_VAL(0x0f) |
           RTE_OUTB_OPC_PDU_FLAGS_OPC_GRP_FLAGS_MASK(0xff));
    REG_WR(RTE_OUTB_OPC_PDU_MISC,
           RTE_OUTB_OPC_PDU_MISC_OPC_FLAGS_VAL(0xb) |
           RTE_OUTB_OPC_PDU_MISC_OPC_FLAGS_MASK(0xf) |
           RTE_OUTB_OPC_PDU_MISC_OPC_VER(1) |
           RTE_OUTB_OPC_PDU_MISC_OPC_GRP_VER_CHK_ENA(1) |
           RTE_OUTB_OPC_PDU_MISC_OPC_NETWORK_MSG_NUM(1));

    // Profinet DataStatus default
    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        inst->ob.rtp_tbl[i].conf.pn_ds = RTE_OB_PN_DS_VAL;
    }

    return 0;
}

int mera_rtp_check(const mera_rtp_id_t rtp_id)
{
    if (rtp_id == 0 || rtp_id > MERA_RTP_CNT) {
        T_E("illegal rtp_id: %u", rtp_id);
        return -1;
    }
    return 0;
}

int mera_ob_rtp_conf_get(struct mera_inst    *inst,
                         const mera_rtp_id_t rtp_id,
                         mera_ob_rtp_conf_t  *const conf)
{
    T_I("enter");
    MERA_RC(mera_rtp_check(rtp_id));
    inst = mera_inst_get(inst);
    *conf = inst->ob.rtp_tbl[rtp_id].conf;
    return 0;
}

int mera_ob_rtp_conf_set(struct mera_inst         *inst,
                         const mera_rtp_id_t      rtp_id,
                         const mera_ob_rtp_conf_t *const conf)
{
    uint32_t type = (conf->type == MERA_RTP_TYPE_OPC_UA ? 1 : 0);
    uint32_t ena = (conf->type == MERA_RTP_TYPE_DISABLED ? 0 : 1);

    T_I("enter");
    MERA_RC(mera_rtp_check(rtp_id));
    inst = mera_inst_get(inst);
    inst->ob.rtp_tbl[rtp_id].conf = *conf;
    REG_WR(RTE_OUTB_RTP_MISC(rtp_id),
           RTE_OUTB_RTP_MISC_RTP_GRP_ID(0) |
           RTE_OUTB_RTP_MISC_PDU_TYPE(type) |
           RTE_OUTB_RTP_MISC_RTP_ENA(ena) |
           RTE_OUTB_RTP_MISC_RTP_GRP_STATE_STOPPED_MODE(1) |
           RTE_OUTB_RTP_MISC_DG_DATA_CP_ENA(1) |
           RTE_OUTB_RTP_MISC_WR_ACTION_ADDR(0));

    // PDU length check
    REG_WR(RTE_OUTB_RTP_PDU_CHKS(rtp_id),
           RTE_OUTB_RTP_PDU_CHKS_PDU_LEN(conf->length) |
           RTE_OUTB_RTP_PDU_CHKS_PN_CC_INIT(1) |
           RTE_OUTB_RTP_PDU_CHKS_PN_CC_STORED(0));

    REG_WR(RTE_OUTB_RTP_PN_MISC(rtp_id),
           RTE_OUTB_RTP_PN_MISC_PN_DATA_STATUS_VAL(conf->pn_ds) |
           RTE_OUTB_RTP_PN_MISC_PN_DATA_STATUS_MISMATCH_VAL(0) |
           RTE_OUTB_RTP_PN_MISC_PN_CC_CHK_ENA(1) |
           RTE_OUTB_RTP_PN_MISC_PN_CC_MISMATCH_FRM_FWD_ENA(0) |
           RTE_OUTB_RTP_PN_MISC_PN_DATA_STATUS_MISMATCH_DROP_ENA(1));

    REG_WR(RTE_OUTB_RTP_OPC_GRP_VER(rtp_id), conf->opc_grp_ver);
    return 0;
}

int mera_ob_dg_init(mera_ob_dg_conf_t *const conf)
{
    memset(conf, 0, sizeof(*conf));
    return 0;
}

int mera_ob_dg_add(struct mera_inst        *inst,
                   const mera_rtp_id_t     rtp_id,
                   const mera_ob_dg_conf_t *conf)
{
    mera_ob_t           *ob;
    mera_ob_dg_entry_t  *dg, *prev;
    mera_ob_rtp_entry_t *rtp;
    uint16_t            i, addr, new = 0, prev_addr, found = 0, cnt;

    T_I("enter");
    MERA_RC(mera_rtp_check(rtp_id));
    inst = mera_inst_get(inst);

    if (conf->length == 0) {
        T_E("length must be non-zero");
        return -1;
    }

    cnt = ((conf->length + 3) / 4);
    ob = &inst->ob;
    if ((ob->dg_addr + cnt) > RTE_OB_DG_SEC_SIZE) {
        T_E("DG memory is full");
        return -1;
    }

    // Find free DG entry
    for (addr = 1; addr < RTE_OB_DG_CNT; addr++) {
        if (ob->dg_tbl[addr].rtp_id == 0) {
            new = addr;
            break;
        }
    }
    if (new == 0) {
        T_E("no more DG entries");
        return -1;
    }

    // Insert sorted by increasing PDU offset
    rtp = &ob->rtp_tbl[rtp_id];
    for (addr = rtp->addr, prev = NULL; addr != 0; ) {
        dg = &ob->dg_tbl[addr];
        if (dg->conf.dg_id == conf->dg_id) {
            // Same ID found
            T_E("rtp_id %u already has id %u", rtp_id, conf->dg_id);
            return -1;
        } else if (dg->conf.pdu_offset == conf->pdu_offset) {
            // Same PDU offset found
            T_E("rtp_id %u already has PDU offset %u", rtp_id, conf->pdu_offset);
            return -1;
        } else if (dg->conf.pdu_offset > conf->pdu_offset) {
            // Greater PDU offset found
            found = 1;
        } else if (!found) {
            // Smaller PDU offset found
            prev = dg;
        }
        addr = dg->addr;
    }

    dg = &ob->dg_tbl[new];
    dg->conf = *conf;
    dg->rtp_id = rtp_id;
    dg->dg_addr = ob->dg_addr;
    ob->dg_addr += cnt;
    if (prev == NULL) {
        // Insert first
        dg->addr = rtp->addr;
        rtp->addr = new;
    } else {
        // Insert after previous
        dg->addr = prev->addr;
        prev->addr = new;
    }

    // Write list to hardware
    for (i = 0, addr = rtp->addr, prev_addr = addr; addr != 0; i++) {
        if (i < 3) {
            REG_WR(RTE_OUTB_DG_ADDR(rtp_id, i), RTE_OUTB_DG_ADDR_DG_ADDR(addr));
        } else {
            REG_WR(RTE_OUTB_DG_MISC(prev_addr),
                   RTE_OUTB_DG_MISC_DG_BASE_PDU_POS(0) |
                   RTE_OUTB_DG_MISC_DG_ADDR(addr));
            prev_addr = ob->dg_tbl[prev_addr].addr;
        }
        dg = &ob->dg_tbl[addr];
        REG_WR(RTE_OUTB_DG_DATA_OFFSET_PDU_POS(addr),
               RTE_OUTB_DG_DATA_OFFSET_PDU_POS_DG_DATA_OFFSET_PDU_POS(dg->conf.pdu_offset));
        REG_WR(RTE_OUTB_DG_DATA_SECTION_ADDR(addr),
               RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_SECTION_ADDR(dg->dg_addr) |
               RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_LEN(dg->conf.length));
        REG_WR(RTE_OUTB_PN_IOPS(addr),
               RTE_OUTB_PN_IOPS_PN_IOPS_VAL(0) |
               RTE_OUTB_PN_IOPS_PN_IOPS_OFFSET_PDU_POS(dg->conf.pdu_offset) |
               RTE_OUTB_PN_IOPS_PN_IOPS_CHK_ENA(0) | // TBD: Enabling IOPS check seems to prevent DG copy
               RTE_OUTB_PN_IOPS_PN_IOPS_MISMATCH_SKIP_ENA(1));
        addr = dg->addr;
    }
    return 0;
}

static int mera_wal_check(const mera_ob_wal_id_t wal_id)
{
    if (wal_id >= MERA_OB_WAL_CNT) {
        T_E("illegal wal_id: %u", wal_id);
        return -1;
    }
    return 0;
}

int mera_ob_wal_conf_get(struct mera_inst       *inst,
                         const mera_ob_wal_id_t wal_id,
                         mera_ob_wal_conf_t     *const conf)
{
    MERA_RC(mera_wal_check(wal_id));
    inst = mera_inst_get(inst);
    *conf = inst->ob.wal_tbl[wal_id].conf;
    return 0;
}

int mera_ob_wal_conf_set(struct mera_inst         *inst,
                         const mera_ob_wal_id_t   wal_id,
                         const mera_ob_wal_conf_t *const conf)
{
    uint32_t value;

    MERA_RC(mera_wal_check(wal_id));
    inst = mera_inst_get(inst);
    inst->ob.wal_tbl[wal_id].conf = *conf;
    REG_RD(RTE_SC_TIME, &value);
    value = (conf->time ? 0 : RTE_SC_TIME_SC_RUT_CNT_X(value));
    REG_WR(RTE_OUTB_WR_TIMER_CFG1(wal_id), RTE_OUTB_WR_TIMER_CFG1_FIRST_RUT_CNT(value));
    REG_WR(RTE_OUTB_WR_TIMER_CFG2(wal_id),
           RTE_OUTB_WR_TIMER_CFG2_DELTA_RUT_CNT(MERA_RUT_TIME(conf->time)));
    REG_WR(RTE_OUTB_TIMER_CMD,
           RTE_OUTB_TIMER_CMD_TIMER_CMD(2) |
           RTE_OUTB_TIMER_CMD_TIMER_RSLT(0) |
           RTE_OUTB_TIMER_CMD_TIMER_TYPE(1) |
           RTE_OUTB_TIMER_CMD_TIMER_IDX(wal_id));
    return 0;
}

int mera_ob_wa_init(mera_ob_wa_conf_t *const conf)
{
    memset(conf, 0, sizeof(*conf));
    return 0;
}

int mera_ob_wa_add(struct mera_inst        *inst,
                   const mera_ob_wal_id_t  wal_id,
                   const mera_ob_wa_conf_t *const conf)
{
    mera_gen_t          *gen;
    mera_ob_t           *ob;
    mera_ob_wal_entry_t *wal;
    mera_ob_wa_entry_t  *wa;
    mera_ob_dg_entry_t  *dg = NULL;
    mera_ob_rtp_entry_t *rtp;
    uint16_t            i, addr, found = 0;

    MERA_RC(mera_wal_check(wal_id));
    inst = mera_inst_get(inst);
    gen = &inst->gen;
    ob = &inst->ob;
    wal = &ob->wal_tbl[wal_id];

    if (conf->internal) {
        // Internal transfer
    } else {
        // DG transfer
        MERA_RC(mera_rtp_check(conf->rtp_id));
        addr = ob->rtp_tbl[conf->rtp_id].addr;
        while (addr != 0) {
            dg = &ob->dg_tbl[addr];
            if (dg->conf.dg_id == conf->dg_id) {
                found = 1;
                break;
            }
            addr = dg->addr;
        }
        if (found == 0) {
            T_E("DG ID %u not found", conf->dg_id);
            return -1;
        }
    }

    // Find free WA entry
    for (addr = 1, found = 0; addr < RTE_OB_WA_CNT; addr++) {
        wa = &ob->wa_tbl[addr];
        if (wa->used == 0) {
            // Insert first in list
            wa->addr = wal->addr;
            wal->addr = addr;
            wa->used = 1;
            wa->conf = *conf;
            found = 1;
            break;
        }
    }
    if (!found) {
        T_E("no more WA entries");
        return -1;
    }

    // Update WA entry
    REG_WR(RTE_WR_ACTION_DG_DATA(addr),
           RTE_WR_ACTION_DG_DATA_DG_DATA_SECTION_ADDR(dg ? dg->dg_addr : 0) |
           RTE_WR_ACTION_DG_DATA_DG_DATA_LEN(dg ? dg->conf.length : conf->length) |
           RTE_WR_ACTION_DG_DATA_DG_DATA_LATEST_INVLD_MODE(0));
    // Write mode is NONE(0)/REQ_REL(3)/REQ(1)
    REG_WR(RTE_WR_ACTION_MISC(addr),
           RTE_WR_ACTION_MISC_OUTB_RTP_ID(dg ? conf->rtp_id : 0) |
           RTE_WR_ACTION_MISC_WR_ACTION_ADDR(wa->addr) |
           RTE_WR_ACTION_MISC_BUF3_WR_MODE(gen->rai_offset == 0 ? 0 : wa->addr == 0 ? 3 : 1) |
           RTE_WR_ACTION_MISC_HW_WR_DIS_MODE(0) |
           RTE_WR_ACTION_MISC_INTERN_ENA(dg ? 0 : 1) |
           RTE_WR_ACTION_MISC_TRANSFER_PROTECT_ENA(0) |
           RTE_WR_ACTION_MISC_RTP_STOPPED_MODE(0));
    REG_WR(RTE_WR_RAI_ADDR(addr), gen->rai_base + conf->wr_addr);
    REG_WR(RTE_WR_ACTION_RTP_GRP(addr),
           RTE_WR_ACTION_RTP_GRP_RTP_GRP_ID(0) |
           RTE_WR_ACTION_RTP_GRP_RTP_GRP_STOPPED_MODE(0));
    REG_WR(RTE_RD_RAI_ADDR(addr), dg ? 0 : (gen->rai_base + conf->rd_addr));
    REG_WR(RTE_OFFSET_RAI_ADDR(addr), RTE_OFFSET_RAI_ADDR_OFFSET_RAI_ADDR(gen->rai_offset));
    REG_WR(RTE_BUF3_ADDR(addr), RTE_BUF3_ADDR_BUF3_ADDR(addr));

    addr = wa->addr;
    if (gen->rai_offset != 0 && addr != 0) {
        // Write mode for next entry is NONE(0)/REL(2)
        wa = &ob->wa_tbl[addr];
        REG_WRM(RTE_WR_ACTION_MISC(addr),
                RTE_WR_ACTION_MISC_BUF3_WR_MODE(wa->addr == 0 ? 2 : 0),
                RTE_WR_ACTION_MISC_BUF3_WR_MODE_M);
    }

    // Update WAL
    REG_WR(RTE_OUTB_WR_ACTION_ADDR(wal_id), RTE_OUTB_WR_ACTION_ADDR_WR_ACTION_ADDR(wal->addr));

    // Update RTP WAL reference
    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        rtp = &ob->rtp_tbl[i];
        if (rtp->conf.wal_enable && rtp->conf.wal_id == wal_id) {
            REG_WRM(RTE_OUTB_RTP_MISC(i),
                    RTE_OUTB_RTP_MISC_WR_ACTION_ADDR(wal->addr),
                    RTE_OUTB_RTP_MISC_WR_ACTION_ADDR_M);
        }
    }
    return 0;
}

int mera_ob_flush(struct mera_inst *inst)
{
    mera_ob_t           *ob;
    mera_ob_dg_entry_t  *dg;
    mera_ob_rtp_entry_t *rtp;
    uint16_t            i, j, addr, prev_addr;

    T_I("enter");
    inst = mera_inst_get(inst);
    ob = &inst->ob;

    // Clear lists in state and hardware
    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        rtp = &ob->rtp_tbl[i];
        for (j = 0, addr = rtp->addr, prev_addr = addr; addr != 0; j++) {
            if (j < 3) {
                REG_WR(RTE_OUTB_DG_ADDR(i, j), RTE_OUTB_DG_ADDR_DG_ADDR(0));
            } else {
                REG_WR(RTE_OUTB_DG_MISC(prev_addr), RTE_OUTB_DG_MISC_DG_ADDR(0));
                prev_addr = ob->dg_tbl[prev_addr].addr;
            }
            REG_WR(RTE_OUTB_DG_DATA_SECTION_ADDR(addr),
                   RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_SECTION_ADDR(0) |
                   RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_LEN(0));
            dg = &ob->dg_tbl[addr];
            addr = dg->addr;
            memset(dg, 0, sizeof(*dg));
            dg->addr = addr; // Restore address used as prev_addr
        }
        memset(rtp, 0, sizeof(*rtp));
        REG_WR(RTE_OUTB_RTP_MISC(i), 0);
    }
    ob->dg_addr = 0;
    return 0;
}

static int mera_ob_rtp_counters_update(struct mera_inst       *inst,
                                       const mera_rtp_id_t    rtp_id,
                                       mera_ob_rtp_counters_t *const counters,
                                       int                    clear)
{
    mera_ob_rtp_entry_t *rtp;
    uint32_t            value;

    T_I("enter");
    inst = mera_inst_get(inst);
    MERA_RC(mera_rtp_check(rtp_id));
    rtp = &inst->ob.rtp_tbl[rtp_id];
    if (rtp->conf.type != MERA_RTP_TYPE_DISABLED) {
        REG_RD(RTE_OUTB_PDU_RECV_CNT(rtp_id), &value);
        mera_cnt_16_update(RTE_OUTB_PDU_RECV_CNT_PDU_RECV_CNT0_X(value), &rtp->rx_0, clear);
        mera_cnt_16_update(RTE_OUTB_PDU_RECV_CNT_PDU_RECV_CNT1_X(value), &rtp->rx_1, clear);
    }
    if (counters != NULL) {
        counters->rx_0 = rtp->rx_0.value;
        counters->rx_1 = rtp->rx_1.value;
    }
    return 0;
}

int mera_ob_rtp_counters_get(struct mera_inst       *inst,
                             const mera_rtp_id_t    rtp_id,
                             mera_ob_rtp_counters_t *const counters)
{
    return mera_ob_rtp_counters_update(inst, rtp_id, counters, 0);
}

int mera_ob_rtp_counters_clr(struct mera_inst    *inst,
                             const mera_rtp_id_t rtp_id)
{
    return mera_ob_rtp_counters_update(inst, rtp_id, NULL, 1);
}

int mera_ob_poll(struct mera_inst *inst)
{
    mera_ob_t *ob = &inst->ob;
    uint32_t  i;

    T_I("enter");
    for (i = 0; i < RTE_POLL_CNT; i++) {
        ob->rtp_id++;
        if (ob->rtp_id >= RTE_IB_RTP_CNT) {
            ob->rtp_id = 1;
        }
        MERA_RC(mera_ob_rtp_counters_update(inst, ob->rtp_id, NULL, 0));
    }
    return 0;
}

static int mera_ob_debug_dg_data(struct mera_inst *inst,
                                 const mera_debug_printf_t pr,
                                 uint32_t addr,
                                 uint32_t sec)
{
    uint32_t i, n, value, base, cnt;

    REG_RD(RTE_OUTB_DG_DATA_SECTION_ADDR(addr), &value);
    base = RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_SECTION_ADDR_X(value);
    cnt = ((RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_LEN_X(value) + 3) / 4);
    for (i = 0; i < cnt; i++) {
        addr = (base + i);
        if (sec < 3) {
            addr += (sec * RTE_OB_DG_SEC_SIZE);
            REG_WR(RTE_OUTB_DG_DATA_ADDR, addr);
            REG_RD(RTE_OUTB_DG_DATA, &value);
        } else {
            REG_WR(RTE_OUTB_LAST_VLD_DG_DATA_ADDR, addr);
            REG_RD(RTE_OUTB_LAST_VLD_DG_DATA, &value);
        }
        n = (i % 8);
        if (n == 0) {
            pr("%04x: ", addr);
        }
        pr("%08x%s", value, i == (cnt - 1) ? "\n\n" : n == 7 ? "\n" : "-");
    }
    return 0;
}

int mera_ob_debug_print(struct mera_inst *inst,
                        const mera_debug_printf_t pr,
                        const mera_debug_info_t   *const info)
{
    mera_ob_t              *ob = &inst->ob;
    mera_ob_rtp_entry_t    *rtp;
    mera_ob_rtp_counters_t cnt;
    mera_ob_dg_entry_t     *dg;
    mera_ob_wal_entry_t    *wal;
    mera_ob_wa_entry_t     *wa;
    const char             *txt;
    uint32_t               value, len, pos, idx, i, j, addr = ob->dg_addr;
    mera_bool_t            internal;
    char                   buf[32];
    struct {
        uint32_t cnt;
        uint32_t addr[3];
    } addr_table;

    mera_debug_print_header(pr, "RTE Outbound State");
    pr("Next RTP ID: %u\n", ob->rtp_id);
    pr("DG Addr    : %u (%u bytes used)\n\n", addr, addr * 4);

    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        rtp = &ob->rtp_tbl[i];
        addr = rtp->addr;
        switch (rtp->conf.type) {
        case MERA_RTP_TYPE_PN:
            txt = "Profinet";
            break;
        case MERA_RTP_TYPE_OPC_UA:
            txt = "OPC-UA";
            break;
        default:
            if (addr == 0 && !info->full) {
                continue;
            }
            txt = "Disabled";
            break;
        }
        pr("RTP ID: %u\n", i);
        pr("Type  : %s\n", txt);
        pr("WAL ID: ");
        if (rtp->conf.wal_enable) {
            pr("%u", rtp->conf.wal_id);
        } else {
            pr("-");
        }
        pr("\n");
        if (mera_ob_rtp_counters_update(inst, i, &cnt, 0) == 0) {
            pr("Rx 0  : %" PRIu64 "\n", cnt.rx_0);
            pr("Rx 1  : %" PRIu64 "\n", cnt.rx_1);
        }
        for ( ; addr != 0; addr = dg->addr) {
            dg = &ob->dg_tbl[addr];
            if (addr == rtp->addr) {
                pr("\n  Addr  DG ID  PDU   DG_Addr  Length\n");
            }
            pr("  %-6u%-7u%-6u%-9u%u\n",
               addr, dg->conf.dg_id, dg->conf.pdu_offset, dg->dg_addr, dg->conf.length);
        }
        pr("\n");
    }

    for (i = 0; i < MERA_OB_WAL_CNT; i++) {
        wal = &ob->wal_tbl[i];
        addr = wal->addr;
        if (addr == 0 && !info->full) {
            continue;
        }
        pr("WAL ID: %u\n", i);
        pr("Time  : %u.%03u usec\n", wal->conf.time / 1000, wal->conf.time % 1000);
        for ( ; addr != 0; addr = wa->addr) {
            wa = &ob->wa_tbl[addr];
            if (addr == wal->addr) {
                pr("\n  Addr  RTP  DG   RD Addr     Length  WR Addr\n");
            }
            pr("  %-6u", addr);
            internal = wa->conf.internal;
            sprintf(buf, "%u", wa->conf.rtp_id);
            pr("%-5s", internal ? "-" : buf);
            sprintf(buf, "%u", wa->conf.dg_id);
            pr("%-5s", internal ? "-" : buf);
            sprintf(buf, "0x%08x", wa->conf.rd_addr);
            pr("%-12s", internal ? buf : "-");
            sprintf(buf, "%u", wa->conf.length);
            pr("%-8s", internal ? buf : "-");
            pr("0x%08x\n", wa->conf.wr_addr);
        }
        pr("\n");
    }

    mera_debug_print_header(pr, "RTE Outbound Registers");
    mera_debug_print_reg_header(pr, "RTE Outbound");
    DBG_REG(REG_ADDR(RTE_OUTB_CFG), "OUTB_CFG");
    DBG_REG(REG_ADDR(RTE_OUTB_RTP_STATE), "OUTB_RTP_STATE");
    REG_RD(RTE_OUTB_PN_PDU_MISC, &value);
    DBG_PR_REG("PN_PDU_MISC", value);
    DBG_PR_REG_M("STATUS_MASK", RTE_OUTB_PN_PDU_MISC_PN_DATA_STATUS_MASK, value);
    DBG_PR_REG_M("VALID_CHK_ENA", RTE_OUTB_PN_PDU_MISC_PN_DATA_STATUS_VALID_CHK_ENA, value);
    DBG_PR_REG_M("TRANSFER_CHK_ENA", RTE_OUTB_PN_PDU_MISC_PN_TRANSFER_STATUS_CHK_ENA, value);
    REG_RD(RTE_OUTB_OPC_PDU_FLAGS, &value);
    DBG_PR_REG("OPC_PDU_FLAGS", value);
    DBG_PR_REG_M("EXT_FLAGS1_VAL", RTE_OUTB_OPC_PDU_FLAGS_OPC_EXT_FLAGS1_VAL, value);
    DBG_PR_REG_M("EXT_FLAGS1_MASK", RTE_OUTB_OPC_PDU_FLAGS_OPC_EXT_FLAGS1_MASK, value);
    DBG_PR_REG_M("GRP_FLAGS_VAL", RTE_OUTB_OPC_PDU_FLAGS_OPC_GRP_FLAGS_VAL, value);
    DBG_PR_REG_M("GRP_FLAGS_MASK", RTE_OUTB_OPC_PDU_FLAGS_OPC_GRP_FLAGS_MASK, value);
    REG_RD(RTE_OUTB_OPC_PDU_MISC, &value);
    DBG_PR_REG("OPC_PDU_MISC", value);
    DBG_PR_REG_M("FLAGS_VAL", RTE_OUTB_OPC_PDU_MISC_OPC_FLAGS_VAL, value);
    DBG_PR_REG_M("FLAGS_MASK", RTE_OUTB_OPC_PDU_MISC_OPC_FLAGS_MASK, value);
    DBG_PR_REG_M("VER", RTE_OUTB_OPC_PDU_MISC_OPC_VER, value);
    DBG_PR_REG_M("GRP_VER_CHK_ENA", RTE_OUTB_OPC_PDU_MISC_OPC_GRP_VER_CHK_ENA, value);
    DBG_PR_REG_M("NMSG_NUM", RTE_OUTB_OPC_PDU_MISC_OPC_NETWORK_MSG_NUM, value);
    DBG_REG(REG_ADDR(RTE_OUTB_STICKY_BITS), "STICKY_BITS");
    DBG_REG(REG_ADDR(RTE_OUTB_BUS_ERROR), "BUS_ERROR");
    pr("\n");

    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        REG_RD(RTE_OUTB_RTP_MISC(i), &value);
        if (RTE_OUTB_RTP_MISC_RTP_ENA_X(value) == 0 && !info->full) {
            continue;
        }
        sprintf(buf, "OUTB_RTP_TBL_%u", i);
        mera_debug_print_reg_header(pr, buf);
        REG_RD(RTE_OUTB_RTP_MISC(i), &value);
        DBG_PR_REG("MISC", value);
        DBG_PR_REG_M("GRP_ID", RTE_OUTB_RTP_MISC_RTP_GRP_ID, value);
        DBG_PR_REG_M("PDU_TYPE", RTE_OUTB_RTP_MISC_PDU_TYPE, value);
        DBG_PR_REG_M("RTP_ENA", RTE_OUTB_RTP_MISC_RTP_ENA, value);
        DBG_PR_REG_M("STOPPED_MODE", RTE_OUTB_RTP_MISC_RTP_GRP_STATE_STOPPED_MODE, value);
        DBG_PR_REG_M("DATA_CP_ENA", RTE_OUTB_RTP_MISC_DG_DATA_CP_ENA, value);
        DBG_PR_REG_M("WR_ACTION_ADDR", RTE_OUTB_RTP_MISC_WR_ACTION_ADDR, value);
        DBG_PR_REG_M("DBG_ENA", RTE_OUTB_RTP_MISC_RTP_DBG_ENA, value);
        REG_RD(RTE_OUTB_RTP_PDU_CHKS(i), &value);
        DBG_PR_REG("PDU_CHKS", value);
        DBG_PR_REG_M("PDU_LEN", RTE_OUTB_RTP_PDU_CHKS_PDU_LEN, value);
        DBG_PR_REG_M("PN_CC_INIT", RTE_OUTB_RTP_PDU_CHKS_PN_CC_INIT, value);
        DBG_PR_REG_M("PN_CC_STORED", RTE_OUTB_RTP_PDU_CHKS_PN_CC_STORED, value);
        REG_RD(RTE_OUTB_RTP_PN_MISC(i), &value);
        DBG_PR_REG("PN_MISC", value);
        DBG_PR_REG_M("DATA_STATUS_VAL", RTE_OUTB_RTP_PN_MISC_PN_DATA_STATUS_VAL, value);
        DBG_PR_REG_M("DATA_STATUS_MM", RTE_OUTB_RTP_PN_MISC_PN_DATA_STATUS_MISMATCH_VAL, value);
        DBG_PR_REG_M("CC_CHK_ENA", RTE_OUTB_RTP_PN_MISC_PN_CC_CHK_ENA, value);
        DBG_PR_REG_M("MM_FRM_FWD_ENA", RTE_OUTB_RTP_PN_MISC_PN_CC_MISMATCH_FRM_FWD_ENA, value);
        DBG_PR_REG_M("MM_DROP_ENA", RTE_OUTB_RTP_PN_MISC_PN_DATA_STATUS_MISMATCH_DROP_ENA, value);
        DBG_REG(REG_ADDR(RTE_OUTB_RTP_OPC_GRP_VER(i)), "OPC_GRP_VER");
        REG_RD(RTE_OUTB_PDU_RECV_CNT(i), &value);
        DBG_PR_REG("PDU_RECV_CNT", value);
        DBG_PR_REG_M("CNT0", RTE_OUTB_PDU_RECV_CNT_PDU_RECV_CNT0, value);
        DBG_PR_REG_M("CNT1", RTE_OUTB_PDU_RECV_CNT_PDU_RECV_CNT1, value);
        DBG_REG(REG_ADDR(RTE_OUTB_RTP_STICKY_BITS(i)), "STICKY_BITS");

        // Show DG data
        memset(&addr_table, 0, sizeof(addr_table));
        for (j = 0; j < 3; j++) {
            DBG_REG_I(REG_ADDR(RTE_OUTB_DG_ADDR(i, j)), j, "DG_ADDR");
            REG_RD(RTE_OUTB_DG_ADDR(i, j), &value);
            if ((addr = RTE_OUTB_DG_ADDR_DG_ADDR_X(value)) != 0) {
                addr_table.addr[addr_table.cnt++] = addr;
            }
        }
        pr("\n");
        while (addr_table.cnt != 0) {
            addr = addr_table.addr[0];
            addr_table.addr[0] = addr_table.addr[1];
            addr_table.addr[1] = addr_table.addr[2];
            addr_table.cnt--;
            REG_RD(RTE_OUTB_DG_DATA_OFFSET_PDU_POS(addr), &value);
            pos = RTE_OUTB_DG_DATA_OFFSET_PDU_POS_DG_DATA_OFFSET_PDU_POS_X(value);
            REG_WR(RTE_OUTB_DG_DATA_RTP_CTRL_ACC, RTE_OUTB_DG_DATA_RTP_CTRL_ACC_DG_DATA_RTP_CTRL_ADDR(i));
            REG_RD(RTE_OUTB_DG_DATA_RTP_CTRL, &value);
            idx = RTE_OUTB_DG_DATA_RTP_CTRL_LATEST_IDX_X(value);
            pr("Addr %u, PDU Offset %u, Section %u:\n", addr, pos, idx);
            MERA_RC(mera_ob_debug_dg_data(inst, pr, addr, idx));
            REG_RD(RTE_OUTB_DG_MISC(addr), &value);
            if ((addr = RTE_OUTB_DG_MISC_DG_ADDR_X(value)) != 0) {
                addr_table.addr[addr_table.cnt++] = addr;
            }
        }
    }

    for (i = 1; i < RTE_OB_DG_CNT; i++) {
        REG_RD(RTE_OUTB_DG_DATA_SECTION_ADDR(i), &value);
        len = RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_LEN_X(value);
        if (len == 0 && !info->full) {
            continue;
        }

        j = ob->dg_tbl[i].rtp_id;
        sprintf(buf, "OUTB_DG_TBL_%u_%u", i, j);
        mera_debug_print_reg_header(pr, buf);
        REG_RD(RTE_OUTB_DG_MISC(i), &value);
        DBG_PR_REG("MISC", value);
        DBG_PR_REG_M("BASE_PDU_POS", RTE_OUTB_DG_MISC_DG_BASE_PDU_POS, value);
        DBG_PR_REG_M("DG_ADDR", RTE_OUTB_DG_MISC_DG_ADDR, value);
        DBG_PR_REG_M("DBG_ENA", RTE_OUTB_DG_MISC_DG_DBG_ENA, value);
        DBG_REG(REG_ADDR(RTE_OUTB_DG_DATA_OFFSET_PDU_POS(i)), "PDU_POS");
        REG_RD(RTE_OUTB_DG_DATA_SECTION_ADDR(i), &value);
        DBG_PR_REG("DATA_SECTION_ADDR", value);
        DBG_PR_REG_M("DATA_SECTION_ADDR", RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_SECTION_ADDR, value);
        DBG_PR_REG_M("DATA_LEN", RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_LEN, value);
        REG_RD(RTE_OUTB_PN_IOPS(i), &value);
        DBG_PR_REG("PN_IOPS", value);
        DBG_PR_REG_M("VAL", RTE_OUTB_PN_IOPS_PN_IOPS_VAL, value);
        DBG_PR_REG_M("OFFSET_PDU_POS", RTE_OUTB_PN_IOPS_PN_IOPS_OFFSET_PDU_POS, value);
        DBG_PR_REG_M("CHK_ENA", RTE_OUTB_PN_IOPS_PN_IOPS_CHK_ENA, value);
        DBG_PR_REG_M("MISMATCH_SKIP_ENA", RTE_OUTB_PN_IOPS_PN_IOPS_MISMATCH_SKIP_ENA, value);
        DBG_REG(REG_ADDR(RTE_OUTB_OPC_DATA_SET_FLAGS1_VAL(i)), "OPC_FLAGS1_VAL");
        REG_RD(RTE_OUTB_OPC_DATA_SET_FLAGS1_MISC(i), &value);
        DBG_PR_REG("OPC_FLAGS1_MISC", value);
        DBG_PR_REG_M("OFFSET_PDU_POS",
                     RTE_OUTB_OPC_DATA_SET_FLAGS1_MISC_OPC_DATA_SET_FLAGS1_OFFSET_PDU_POS, value);
        DBG_PR_REG_M("MISMATCH_SKIP_ENA",
                     RTE_OUTB_OPC_DATA_SET_FLAGS1_MISC_OPC_DATA_SET_FLAGS1_MISMATCH_SKIP_ENA, value);
        DBG_PR_REG_M("CHK_ENA",
                     RTE_OUTB_OPC_DATA_SET_FLAGS1_MISC_OPC_DATA_SET_FLAGS1_CHK_ENA, value);
        DBG_REG(REG_ADDR(RTE_OUTB_OPC_SEQ_NUM(i)), "OPC_SEQ_NUM");
        DBG_REG(REG_ADDR(RTE_OUTB_OPC_STATUS_CODE_VAL(i)), "OPC_STATUS_CODE_VAL");
        REG_RD(RTE_OUTB_OPC_STATUS_CODE_MISC(i), &value);
        DBG_PR_REG("OPC_STATUS_CODE_MISC", value);
        DBG_PR_REG_M("CODE_CHK_ENA",
                     RTE_OUTB_OPC_STATUS_CODE_MISC_OPC_STATUS_CODE_CHK_ENA, value);
        DBG_PR_REG_M("MISMATCH_SKIP_ENA",
                     RTE_OUTB_OPC_STATUS_CODE_MISC_OPC_STATUS_CODE_MISMATCH_SKIP_ENA, value);
        DBG_PR_REG_M("FAIL_SEVERITY_VAL",
                     RTE_OUTB_OPC_STATUS_CODE_MISC_OPC_FAIL_SEVERITY_VAL, value);
        DBG_REG(REG_ADDR(RTE_OUTB_DG_STICKY_BITS(i)), "STICKY_BITS");
        DBG_REG(REG_ADDR(RTE_OUTB_PN_STATUS(i)), "PN_STATUS");
        DBG_REG(REG_ADDR(RTE_OUTB_OPC_STATUS(i)), "OPC_STATUS");
        DBG_REG(REG_ADDR(RTE_OUTB_OPC_STATUS2(i)), "OPC_STATUS2");
        pr("\n");

        // Read latest index for RTP
        REG_WR(RTE_OUTB_DG_DATA_RTP_CTRL_ACC, RTE_OUTB_DG_DATA_RTP_CTRL_ACC_DG_DATA_RTP_CTRL_ADDR(j));
        REG_RD(RTE_OUTB_DG_DATA_RTP_CTRL, &value);
        idx = RTE_OUTB_DG_DATA_RTP_CTRL_LATEST_IDX_X(value);
        for (j = 0; j < 4; j++) {
            pr("Section %u (%s):\n",
               j,
               j == 2 ? "Default" : j == 3 ? "Last Good" :  j == idx ? "New" : "Old");
            MERA_RC(mera_ob_debug_dg_data(inst, pr, i, j));
        }
    }

    for (i = 0; i < MERA_OB_WAL_CNT; i++) {
        REG_RD(RTE_OUTB_WR_ACTION_ADDR(i), &value);
        addr = RTE_OUTB_WR_ACTION_ADDR_WR_ACTION_ADDR_X(value);
        if (addr == 0 && !info->full) {
            continue;
        }
        sprintf(buf, "OUTB_WR_TIMER_TBL_%u", i);
        mera_debug_print_reg_header(pr, buf);
        DBG_REG(REG_ADDR(RTE_OUTB_WR_TIMER_CFG1(i)), "FIRST_RUT_CNT");
        DBG_REG(REG_ADDR(RTE_OUTB_WR_TIMER_CFG2(i)), "DELTA_RUT_CNT");
        DBG_PR_REG("WR_ACTION_ADDR", value);
        pr("\n");

        while (addr != 0) {
            j = addr;
            sprintf(buf, "OUTB_WR_ACTION_TBL_%u", j);
            mera_debug_print_reg_header(pr, buf);
            REG_RD(RTE_WR_ACTION_MISC(j), &value);
            addr = RTE_WR_ACTION_MISC_WR_ACTION_ADDR_X(value);
            DBG_PR_REG("WR_ACTION_MISC", value);
            DBG_PR_REG_M("OUTB_RTP_ID", RTE_WR_ACTION_MISC_OUTB_RTP_ID, value);
            DBG_PR_REG_M("WR_ACTION_ADDR", RTE_WR_ACTION_MISC_WR_ACTION_ADDR, value);
            DBG_PR_REG_M("BUF3_WR_MODE", RTE_WR_ACTION_MISC_BUF3_WR_MODE, value);
            DBG_PR_REG_M("HW_WR_DIS_MODE", RTE_WR_ACTION_MISC_HW_WR_DIS_MODE, value);
            DBG_PR_REG_M("INTERN_ENA", RTE_WR_ACTION_MISC_INTERN_ENA, value);
            DBG_PR_REG_M("TRNSFR_PROTECT_ENA", RTE_WR_ACTION_MISC_TRANSFER_PROTECT_ENA, value);
            REG_RD(RTE_WR_ACTION_DG_DATA(j), &value);
            DBG_PR_REG("WR_ACTION_DG_DATA", value);
            DBG_PR_REG_M("SECTION_ADDR", RTE_WR_ACTION_DG_DATA_DG_DATA_SECTION_ADDR, value);
            DBG_PR_REG_M("DATA_LEN", RTE_WR_ACTION_DG_DATA_DG_DATA_LEN, value);
            DBG_PR_REG_M("LATEST_INVLD_MODE", RTE_WR_ACTION_DG_DATA_DG_DATA_LATEST_INVLD_MODE, value);
            DBG_REG(REG_ADDR(RTE_WR_RAI_ADDR(j)), "WR_RAI_ADDR");
            DBG_REG(REG_ADDR(RTE_RD_RAI_ADDR(j)), "RD_RAI_ADDR");
            DBG_REG(REG_ADDR(RTE_OFFSET_RAI_ADDR(j)), "OFFSET_RAI_ADDR");
            DBG_REG(REG_ADDR(RTE_BUF3_ADDR(j)), "BUF3_ADDR");
            REG_RD(RTE_WR_ACTION_RTP_GRP(j), &value);
            DBG_PR_REG("RTP_GRP", value);
            pr("\n");
        }
    }

    return 0;
}
