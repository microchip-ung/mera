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
    inst = mera_inst_get(inst);
    MERA_RC(mera_rtp_check(rtp_id));
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
    inst = mera_inst_get(inst);
    MERA_RC(mera_rtp_check(rtp_id));
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

int mera_ob_rtp_pdu2dg_init(mera_ob_rtp_pdu2dg_conf_t *const conf)
{
    memset(conf, 0, sizeof(*conf));
    return 0;
}

int mera_ob_rtp_pdu2dg_add(struct mera_inst                *inst,
                           const mera_rtp_id_t             rtp_id,
                           const mera_ob_rtp_pdu2dg_conf_t *conf)
{
    mera_ob_t           *ob;
    mera_ob_dg_entry_t  *dg, *prev;
    mera_ob_rtp_entry_t *rtp;
    uint16_t            i, addr, new = 0, prev_addr, found = 0, cnt;

    T_I("enter");
    inst = mera_inst_get(inst);
    MERA_RC(mera_rtp_check(rtp_id));

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
        if (dg->conf.id == conf->id) {
            // Same ID found
            T_E("rtp_id %u already has id %u", rtp_id, conf->id);
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
        addr = dg->addr;
    }
    return 0;
}

int mera_ob_rtp_pdu2dg_clr(struct mera_inst    *inst,
                           const mera_rtp_id_t rtp_id)
{
    mera_ob_t           *ob;
    mera_ob_dg_entry_t  *dg;
    mera_ob_rtp_entry_t *rtp;
    uint16_t            i, addr, prev_addr;

    T_I("enter");
    inst = mera_inst_get(inst);
    MERA_RC(mera_rtp_check(rtp_id));

    // Clear list in state and hardware
    ob = &inst->ob;
    rtp = &ob->rtp_tbl[rtp_id];
    for (i = 0, addr = rtp->addr, prev_addr = addr; addr != 0; i++) {
        if (i < 3) {
            REG_WR(RTE_OUTB_DG_ADDR(rtp_id, i), RTE_OUTB_DG_ADDR_DG_ADDR(0));
        } else {
            REG_WR(RTE_OUTB_DG_MISC(prev_addr), RTE_OUTB_DG_MISC_DG_ADDR(0));
            prev_addr = ob->dg_tbl[prev_addr].addr;
        }
        dg = &ob->dg_tbl[addr];
        dg->rtp_id = 0;
        addr = dg->addr;
    }
    rtp->addr = 0;
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
        if (counters != NULL) {
            counters->rx_0 = rtp->rx_0.value;
            counters->rx_1 = rtp->rx_1.value;
        }
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
    mera_ob_t           *ob = &inst->ob;
    mera_ob_rtp_entry_t *rtp;
    mera_ob_dg_entry_t  *dg;
    const char          *txt;
    uint32_t            value, len, pos, idx, i, j, addr = ob->dg_addr;
    char                buf[32];
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
        while (addr != 0) {
            dg = &ob->dg_tbl[addr];
            if (addr == rtp->addr) {
                pr("\n  ID    Addr  PDU   DG_Addr  Length\n");
            }
            pr("  %-6u%-6u%-6u%-9u%u\n",
               dg->conf.id, addr, dg->conf.pdu_offset, dg->dg_addr, dg->conf.length);
            addr = dg->addr;
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
        DBG_PR_REG("DATA_SECTION_ADDR", value);
        DBG_PR_REG_M("DATA_SECTION_ADDR", RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_SECTION_ADDR, value);
        DBG_PR_REG_M("DATA_LEN", RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_LEN, value);
        REG_RD(RTE_OUTB_PN_IOPS(i), &value);
        DBG_PR_REG("PN_IOPS", value);
        DBG_PR_REG(":VAL", RTE_OUTB_PN_IOPS_PN_IOPS_VAL_X(value));
        DBG_PR_REG(":OFFSET_PDU_POS", RTE_OUTB_PN_IOPS_PN_IOPS_OFFSET_PDU_POS_X(value));
        DBG_PR_REG(":CHK_ENA", RTE_OUTB_PN_IOPS_PN_IOPS_CHK_ENA_X(value));
        DBG_PR_REG(":MISMATCH_SKIP_ENA", RTE_OUTB_PN_IOPS_PN_IOPS_MISMATCH_SKIP_ENA_X(value));
        DBG_REG(REG_ADDR(RTE_OUTB_OPC_DATA_SET_FLAGS1_VAL(i)), "OPC_FLAGS1_VAL");
        REG_RD(RTE_OUTB_OPC_DATA_SET_FLAGS1_MISC(i), &value);
        DBG_PR_REG("OPC_FLAGS1_MISC", value);
        DBG_PR_REG(":OFFSET_PDU_POS",
                   RTE_OUTB_OPC_DATA_SET_FLAGS1_MISC_OPC_DATA_SET_FLAGS1_OFFSET_PDU_POS_X(value));
        DBG_PR_REG(":MISMATCH_SKIP_ENA",
                   RTE_OUTB_OPC_DATA_SET_FLAGS1_MISC_OPC_DATA_SET_FLAGS1_MISMATCH_SKIP_ENA_X(value));
        DBG_PR_REG(":CHK_ENA",
                   RTE_OUTB_OPC_DATA_SET_FLAGS1_MISC_OPC_DATA_SET_FLAGS1_CHK_ENA_X(value));
        DBG_REG(REG_ADDR(RTE_OUTB_OPC_SEQ_NUM(i)), "OPC_SEQ_NUM");
        DBG_REG(REG_ADDR(RTE_OUTB_OPC_STATUS_CODE_VAL(i)), "OPC_STATUS_CODE_VAL");
        REG_RD(RTE_OUTB_OPC_STATUS_CODE_MISC(i), &value);
        DBG_PR_REG("OPC_STATUS_CODE_MISC", value);
        DBG_PR_REG(":CODE_CHK_ENA",
                   RTE_OUTB_OPC_STATUS_CODE_MISC_OPC_STATUS_CODE_CHK_ENA_X(value));
        DBG_PR_REG(":MISMATCH_SKIP_ENA",
                   RTE_OUTB_OPC_STATUS_CODE_MISC_OPC_STATUS_CODE_MISMATCH_SKIP_ENA_X(value));
        DBG_PR_REG(":FAIL_SEVERITY_VAL",
                   RTE_OUTB_OPC_STATUS_CODE_MISC_OPC_FAIL_SEVERITY_VAL_X(value));
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
    return 0;
}
