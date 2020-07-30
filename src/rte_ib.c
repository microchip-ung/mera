// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#define MERA_TRACE_GROUP MERA_TRACE_GROUP_IB
#include "rte_private.h"

int mera_ib_init(struct mera_inst *inst)
{
    T_I("enter");
    return 0;
}

int mera_ib_rtp_conf_get(struct mera_inst    *inst,
                         const mera_rtp_id_t rtp_id,
                         mera_ib_rtp_conf_t  *const conf)
{
    T_I("enter");
    inst = mera_inst_get(inst);
    MERA_RC(mera_rtp_check(rtp_id));
    *conf = inst->ib.rtp_tbl[rtp_id].conf;
    return 0;
}

#define IFH_LEN 28

int mera_ib_rtp_conf_set(struct mera_inst         *inst,
                         const mera_rtp_id_t      rtp_id,
                         const mera_ib_rtp_conf_t *const conf)
{
    mera_ib_t           *ib;
    mera_ib_rtp_entry_t *rtp;
    uint32_t            type = (conf->type == MERA_RTP_TYPE_OPC_UA ? 1 : 0);
    uint32_t            ena = (conf->type == MERA_RTP_TYPE_DISABLED ? 0 : 1);
    uint32_t            len = (conf->length < 60 ? 60 : conf->length);
    uint32_t            inj = (conf->mode == MERA_RTP_IB_MODE_INJ ? 1 : 0);
    uint32_t            i, j, k, m, addr, value, len_old, cnt, chg;

    T_I("enter");
    inst = mera_inst_get(inst);
    ib = &inst->ib;
    MERA_RC(mera_rtp_check(rtp_id));

    // Check frame length
    if (len > MERA_FRAME_DATA_CNT) {
        T_E("illegal length: %u", len);
        return -1;
    }
    len += (IFH_LEN + 4);
    REG_RD(RTE_INB_RTP_FRM_PORT(rtp_id), &value);
    len_old = RTE_INB_RTP_FRM_PORT_FRM_LEN_X(value);
    if (len_old != 0 && len_old != len) {
        T_E("length can not be changed");
        return -1;
    }

    rtp = &ib->rtp_tbl[rtp_id];
    rtp->conf = *conf;
    REG_WR(RTE_INB_RTP_FRM_PORT(rtp_id),
           RTE_INB_RTP_FRM_PORT_FRM_LEN(len) |
           RTE_INB_RTP_FRM_PORT_PORT_NUM(conf->port));
    REG_WR(RTE_INB_RTP_MISC(rtp_id),
           RTE_INB_RTP_MISC_RTP_ENA(ena) |
           RTE_INB_RTP_MISC_RTP_CAT(0) |
           RTE_INB_RTP_MISC_PDU_TYPE(type) |
           RTE_INB_RTP_MISC_LAST_FRM_UPD_CNT(0) |
           RTE_INB_RTP_MISC_OTF_TIMER_RESTART_ENA(0) |
           RTE_INB_RTP_MISC_RTP_GRP_ID(0));
    cnt = ((len + 31) / 32);
    if (len_old == 0) {
        // Allocate new frame data address
        addr = ib->frm_data_addr;
        rtp->frm_data_addr = addr;
        ib->frm_data_addr += cnt;
        REG_WR(RTE_INB_RTP_ADDRS(rtp_id),
               RTE_INB_RTP_ADDRS_FRM_DATA_ADDR(addr) |
               RTE_INB_RTP_ADDRS_REDUN_ADDR(0));
    } else {
        // Reuse existing frame data address
        REG_RD(RTE_INB_RTP_ADDRS(rtp_id), &value);
        addr = RTE_INB_RTP_ADDRS_FRM_DATA_ADDR_X(value);
    }

    // If conf->time is zero, it is a one-shot and we set FIRST to delay the frame.
    // The delayed one-shot frame is a test feature.
    REG_RD(RTE_SC_TIME, &value);
    value = (conf->time ? 0 : RTE_SC_TIME_SC_RUT_CNT_X(value));
    REG_WR(RTE_INB_RTP_TIMER_CFG1(rtp_id), RTE_INB_RTP_TIMER_CFG1_FIRST_RUT_CNT(value));
    REG_WR(RTE_INB_RTP_TIMER_CFG2(rtp_id),
           RTE_INB_RTP_TIMER_CFG2_DELTA_RUT_CNT(MERA_RUT_TIME(conf->time)));
    REG_WR(RTE_INB_TIMER_CMD,
           RTE_INB_TIMER_CMD_TIMER_CMD(ena && inj ? 2 : 1) |
           RTE_INB_TIMER_CMD_TIMER_RSLT(0) |
           RTE_INB_TIMER_CMD_TIMER_TYPE(0) |
           RTE_INB_TIMER_CMD_TIMER_IDX(rtp_id));

    // Frame data
    for (i = 0; i < cnt; i++, addr++) {
        REG_WR(RTE_INB_FRM_DATA_CHG_ADDR, addr);
        REG_WR(RTE_INB_FRM_DATA_ADDR, RTE_INB_FRM_DATA_ADDR_FRM_DATA_ADDR(addr));
        REG_WR(RTE_INB_FRM_DATA_WR_MASK, 0xffffffff);
        chg = 0;
        for (j = 0; j < 8; j++) {
            value = 0;
            k = (i * 32 + j * 4);
            if (k >= IFH_LEN) {
                k -= IFH_LEN;
                for (m = 0; m < 4; m++, k++) {
                    value <<= 8;
                    if (k < conf->length) {
                        value += conf->data[k];
                        if (inj || conf->update[k]) {
                             chg |= (1 << (j * 4 + m));
                        }
                    }
                }
            }
            REG_WR(RTE_INB_FRM_DATA(0, j), value);
        }
        REG_WR(RTE_INB_FRM_DATA_CHG_BYTE, chg);
    }

    return 0;
}

static int mera_ral_check(const mera_ib_ral_id_t ral_id)
{
    if (ral_id >= MERA_IB_RAL_CNT) {
        T_E("illegal ral_id: %u", ral_id);
        return -1;
    }
    return 0;
}

int mera_ib_ral_conf_get(struct mera_inst       *inst,
                         const mera_ib_ral_id_t ral_id,
                         mera_ib_ral_conf_t     *const conf)
{
    MERA_RC(mera_ral_check(ral_id));
    inst = mera_inst_get(inst);
    *conf = inst->ib.ral_tbl[ral_id].conf;
    return 0;
}

int mera_ib_ral_conf_set(struct mera_inst         *inst,
                         const mera_ib_ral_id_t   ral_id,
                         const mera_ib_ral_conf_t *const conf)
{
    uint32_t value;

    MERA_RC(mera_ral_check(ral_id));
    inst = mera_inst_get(inst);
    inst->ib.ral_tbl[ral_id].conf = *conf;
    REG_RD(RTE_SC_TIME, &value);
    value = (conf->time ? 0 : RTE_SC_TIME_SC_RUT_CNT_X(value));
    REG_WR(RTE_INB_RD_TIMER_CFG1(ral_id), RTE_INB_RD_TIMER_CFG1_FIRST_RUT_CNT(value));
    REG_WR(RTE_INB_RD_TIMER_CFG2(ral_id),
           RTE_INB_RD_TIMER_CFG2_DELTA_RUT_CNT(MERA_RUT_TIME(conf->time)));
    REG_WR(RTE_INB_TIMER_CMD,
           RTE_INB_TIMER_CMD_TIMER_CMD(2) |
           RTE_INB_TIMER_CMD_TIMER_RSLT(0) |
           RTE_INB_TIMER_CMD_TIMER_TYPE(1) |
           RTE_INB_TIMER_CMD_TIMER_IDX(ral_id));
    return 0;
}

int mera_ib_ra_init(mera_ib_ra_conf_t *const conf)
{
    memset(conf, 0, sizeof(*conf));
    return 0;
}

int mera_ib_ra_add(struct mera_inst        *inst,
                   const mera_ib_ral_id_t  ral_id,
                   const mera_ib_ra_conf_t *const conf)
{
    mera_ib_t           *ib;
    mera_ib_ral_entry_t *ral;
    mera_ib_ra_entry_t  *ra;
    uint16_t            addr, found = 0;

    MERA_RC(mera_ral_check(ral_id));
    inst = mera_inst_get(inst);
    ib = &inst->ib;
    ral = &ib->ral_tbl[ral_id];

    // Find free RA entry
    for (addr = 1, found = 0; addr < RTE_IB_RA_CNT; addr++) {
        ra = &ib->ra_tbl[addr];
        if (ra->used == 0) {
            // Insert first in list
            ra->addr = ral->addr;
            ral->addr = addr;
            ra->used = 1;
            ra->conf = *conf;
            found = 1;
            break;
        }
    }
    if (!found) {
        T_E("no more RA entries");
        return -1;
    }

    // Update RA entry
    REG_WR(RTE_INB_BASE_RAI_ADDR(addr), conf->rd_addr);
    REG_WR(RTE_INB_RD_ACTION_MISC(addr),
           RTE_INB_RD_ACTION_MISC_DG_DATA_LEN(conf->length) |
           RTE_INB_RD_ACTION_MISC_RD_MAGIC_ENA(0) |
           RTE_INB_RD_ACTION_MISC_STATE_STICKY_ENA(0) |
           RTE_INB_RD_ACTION_MISC_INTERN_ENA(0) |
           RTE_INB_RD_ACTION_MISC_RD_CNT(0));
    REG_WR(RTE_INB_RD_ACTION_ADDRS(addr),
           RTE_INB_RD_ACTION_ADDRS_FRM_DATA_CP_ADDR(0) |
           RTE_INB_RD_ACTION_ADDRS_RD_ACTION_ADDR(ra->addr));

    // Update RAL
    REG_WR(RTE_INB_RD_ACTION_ADDR(ral_id), RTE_INB_RD_ACTION_ADDR_RD_ACTION_ADDR(addr));

    return 0;
}

int mera_ib_dg_init(mera_ib_dg_conf_t *const conf)
{
    memset(conf, 0, sizeof(*conf));
    return 0;
}

int mera_ib_dg_add(struct mera_inst        *inst,
                   const mera_ib_ral_id_t  ral_id,
                   const mera_ib_ra_id_t   ra_id,
                   const mera_ib_dg_conf_t *const conf)
{
    mera_ib_t           *ib;
    mera_ib_rtp_entry_t *rtp;
    mera_ib_ra_entry_t  *ra;
    mera_ib_dg_entry_t  *dg;
    uint16_t            addr, ra_addr = 0, found = 0;
    uint32_t            frm_addr;

    inst = mera_inst_get(inst);
    ib = &inst->ib;
    MERA_RC(mera_ral_check(ral_id));
    MERA_RC(mera_rtp_check(conf->rtp_id));
    rtp = &ib->rtp_tbl[conf->rtp_id];
    if (rtp->conf.type == MERA_RTP_TYPE_DISABLED) {
        T_E("rtp_id %u is disabled", conf->rtp_id);
        return -1;
    }

    // Find RA
    ra_addr = ib->ral_tbl[ral_id].addr;
    while (ra_addr != 0) {
        ra = &ib->ra_tbl[ra_addr];
        if (ra->conf.ra_id == ra_id) {
            break;
        }
        ra_addr = ra->addr;
    }
    if (ra_addr == 0) {
        T_E("RA ID %u not found in RAL %u", ra_id, ral_id);
        return -1;
    }
    if (ra->dg_cnt >= 4) {
        T_E("RA ID %u in RAL %u has full DG list", ra_id, ral_id);
        return -1;
    }

    // Find free DG entry
    for (addr = 1; addr < RTE_IB_DG_CNT; addr++) {
        dg = &ib->dg_tbl[addr];
        if (dg->conf.rtp_id == 0) {
            // Insert first in list
            dg->addr = ra->dg_addr;
            ra->dg_addr = addr;
            ra->dg_cnt++;
            dg->conf = *conf;
            found = 1;
            break;
        }
    }
    if (found == 0) {
        T_E("no more DG entries");
        return -1;
    }

    // Update DG
    REG_WR(RTE_INB_FRM_DATA_CP_ADDRS(addr),
           RTE_INB_FRM_DATA_CP_ADDRS_FRM_DATA_CP_ADDR(dg->addr) |
           RTE_INB_FRM_DATA_CP_ADDRS_FRM_DATA_CTRL_ADDR(0));
    frm_addr = (rtp->frm_data_addr * 32 + IFH_LEN + 14 + conf->pdu_offset);
    REG_WR(RTE_INB_FRM_DATA_BYTE_ADDR1(addr),
           RTE_INB_FRM_DATA_BYTE_ADDR1_DG_FRM_DATA_BYTE_ADDR(frm_addr) |
           RTE_INB_FRM_DATA_BYTE_ADDR1_DG_VLD_FRM_DATA_BYTE_ADDR(frm_addr));
    REG_WR(RTE_INB_FRM_DATA_BYTE_ADDR2(addr),
           RTE_INB_FRM_DATA_BYTE_ADDR2_DG_STATUS_FRM_DATA_BYTE_ADDR(frm_addr));
    REG_WR(RTE_INB_FRM_DATA_CP_MISC(addr),
           RTE_INB_FRM_DATA_CP_MISC_DG_VLD_CLR_MODE(0) |
           RTE_INB_FRM_DATA_CP_MISC_DG_VLD_SET_MODE(0) |
           RTE_INB_FRM_DATA_CP_MISC_DG_VLD_ERR_MODE(0) |
           RTE_INB_FRM_DATA_CP_MISC_DG_STATUS_CLR_MODE(0) |
           RTE_INB_FRM_DATA_CP_MISC_DG_STATUS_SET_MODE(0) |
           RTE_INB_FRM_DATA_CP_MISC_DG_STATUS_ERR_MODE(0) |
           RTE_INB_FRM_DATA_CP_MISC_SOF(0) |
           RTE_INB_FRM_DATA_CP_MISC_EOF(0) |
           RTE_INB_FRM_DATA_CP_MISC_LAST_FRM_TX_CNT(0) |
           RTE_INB_FRM_DATA_CP_MISC_STATE_STICKY_ENA(0));

    // Update RA
    REG_WR(RTE_INB_RD_ACTION_ADDRS(ra_addr),
           RTE_INB_RD_ACTION_ADDRS_FRM_DATA_CP_ADDR(addr) |
           RTE_INB_RD_ACTION_ADDRS_RD_ACTION_ADDR(ra->addr));

    return 0;
}

int mera_ib_flush(struct mera_inst *inst)
{
    mera_ib_t           *ib;
    mera_ib_rtp_entry_t *rtp;
    uint32_t            i;

    inst = mera_inst_get(inst);
    ib = &inst->ib;
    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        rtp = &ib->rtp_tbl[i];
        REG_WR(RTE_INB_RTP_FRM_PORT(i), 0);
        REG_WR(RTE_INB_RTP_MISC(i),0);
        memset(rtp, 0, sizeof(*rtp));
    }
    ib->frm_data_addr = 0;
    return 0;
}

static int mera_ib_rtp_counters_update(struct mera_inst       *inst,
                                       const mera_rtp_id_t    rtp_id,
                                       mera_ib_rtp_counters_t *const counters,
                                       int                    clear)
{
    mera_ib_rtp_entry_t *rtp;
    uint32_t            value;

    rtp = &inst->ib.rtp_tbl[rtp_id];
    if (rtp->conf.type != MERA_RTP_TYPE_DISABLED) {
        REG_RD(RTE_INB_RTP_CNT(rtp_id), &value);
        mera_cnt_16_update(RTE_INB_RTP_CNT_FRM_OTF_CNT_X(value), &rtp->tx_otf, clear);
        mera_cnt_16_update(RTE_INB_RTP_CNT_FRM_INJ_CNT_X(value), &rtp->tx_inj, clear);
    }
    if (counters != NULL) {
        counters->tx_otf = rtp->tx_otf.value;
        counters->tx_inj = rtp->tx_inj.value;
    }
    return 0;
}

int mera_ib_rtp_counters_get(struct mera_inst       *inst,
                             const mera_rtp_id_t    rtp_id,
                             mera_ib_rtp_counters_t *const counters)
{
    T_I("enter");
    inst = mera_inst_get(inst);
    MERA_RC(mera_rtp_check(rtp_id));
    return mera_ib_rtp_counters_update(inst, rtp_id, counters, 0);
}

int mera_ib_rtp_counters_clr(struct mera_inst    *inst,
                             const mera_rtp_id_t rtp_id)
{
    T_I("enter");
    inst = mera_inst_get(inst);
    MERA_RC(mera_rtp_check(rtp_id));
    return mera_ib_rtp_counters_update(inst, rtp_id, NULL, 1);
}

int mera_ib_poll(struct mera_inst *inst)
{
    mera_ib_t *ib = &inst->ib;
    uint32_t  i;

    T_I("enter");
    for (i = 0; i < RTE_POLL_CNT; i++) {
        ib->rtp_id++;
        if (ib->rtp_id >= RTE_IB_RTP_CNT) {
            ib->rtp_id = 1;
        }
        MERA_RC(mera_ib_rtp_counters_update(inst, ib->rtp_id, NULL, 0));
    }
    return 0;
}

int mera_ib_debug_print(struct mera_inst *inst,
                        const mera_debug_printf_t pr,
                        const mera_debug_info_t   *const info)
{
    mera_ib_t              *ib = &inst->ib;
    mera_ib_rtp_entry_t    *rtp;
    mera_ib_rtp_counters_t cnt;
    mera_ib_ral_entry_t    *ral;
    mera_ib_ra_entry_t     *ra;
    mera_ib_dg_entry_t     *dg;
    const char             *txt;
    uint32_t               i, j, k, m, value, chg, base, addr, len;
    char                   buf[32];

    mera_debug_print_header(pr, "RTE Inbound State");
    pr("Next RTP ID    : %u\n", ib->rtp_id);
    addr = ib->frm_data_addr;
    pr("Frame Data Addr: %u (%u bytes used)\n\n", addr, addr * 32);

    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        rtp = &ib->rtp_tbl[i];
        switch (rtp->conf.type) {
        case MERA_RTP_TYPE_PN:
            txt = "Profinet";
            break;
        case MERA_RTP_TYPE_OPC_UA:
            txt = "OPC-UA";
            break;
        default:
            if (!info->full) {
                continue;
            }
            txt = "Disabled";
            break;
        }
        pr("RTP ID: %u\n", i);
        pr("Type  : %s\n", txt);
        pr("Mode  : %s\n", rtp->conf.mode == MERA_RTP_IB_MODE_INJ ? "INJ" : "OTF");
        pr("Time  : %u.%03u usec\n", rtp->conf.time / 1000, rtp->conf.time % 1000);
        len = rtp->conf.length;
        pr("Length: %u\n", len);
        if (mera_ib_rtp_counters_update(inst, i, &cnt, 0) == 0) {
            pr("Tx Inj: %" PRIu64 "\n", cnt.tx_inj);
            pr("Tx Otf: %" PRIu64 "\n", cnt.tx_otf);
        }
        pr("\n");

        for (j = 0; j < len; j++) {
            k = (j % 32);
            if (k == 0) {
                pr("%04x: ", j);
            }
            pr("%02x%s", rtp->conf.data[j],
               j == (len - 1) || k == 31 ? "\n" : (j % 4) == 3 ? "-" : "");
        }
        if (len) {
            pr("\n");
        }
    }

    for (i = 0; i < MERA_IB_RAL_CNT; i++) {
        ral = &ib->ral_tbl[i];
        addr = ral->addr;
        if (addr == 0 && !info->full) {
            continue;
        }
        pr("RAL ID: %u\n", i);
        pr("Time  : %u.%03u usec\n", ral->conf.time / 1000, ral->conf.time % 1000);
        for ( ; addr != 0; addr = ra->addr) {
            ra = &ib->ra_tbl[addr];
            if (addr == ral->addr) {
                pr("\n  Addr  RA ID  RD Addr     Length  DG_CNT\n");
            }
            pr("  %-6u%-7u0x%08x  %-8u%u\n", addr, ra->conf.ra_id, ra->conf.rd_addr, ra->conf.length, ra->dg_cnt);
            for (addr = ra->dg_addr; addr != 0; addr = dg->addr) {
                dg = &ib->dg_tbl[addr];
                if (addr == ra->dg_addr) {
                    pr("\n    Addr  RTP  PDU\n");
                }
                pr("    %-6u%-5u%u\n", addr, dg->conf.rtp_id, dg->conf.pdu_offset);
            }
        }
        pr("\n");
    }

    mera_debug_print_header(pr, "RTE Inbound Registers");
    mera_debug_print_reg_header(pr, "RTE Inbound");
    DBG_REG(REG_ADDR(RTE_INB_CFG), "RTE_INB_CFG");
    DBG_REG(REG_ADDR(RTE_INB_STICKY_BITS), "RTE_INB_STICKY_BITS");
    pr("\n");

    for (i = 1; i < RTE_IB_RTP_CNT; i++) {
        REG_RD(RTE_INB_RTP_MISC(i), &value);
        if (RTE_INB_RTP_MISC_RTP_ENA_X(value) == 0 && !info->full) {
            continue;
        }
        sprintf(buf, "INB_RTP_TBL_%u", i);
        mera_debug_print_reg_header(pr, buf);
        REG_RD(RTE_INB_RTP_MISC(i), &value);
        DBG_PR_REG("MISC", value);
        DBG_PR_REG_M("RTP_ENA", RTE_INB_RTP_MISC_RTP_ENA, value);
        DBG_PR_REG_M("CAT", RTE_INB_RTP_MISC_RTP_CAT, value);
        DBG_PR_REG_M("PDU_TYPE", RTE_INB_RTP_MISC_PDU_TYPE, value);
        DBG_PR_REG_M("UPD_CNT", RTE_INB_RTP_MISC_LAST_FRM_UPD_CNT, value);
        DBG_PR_REG_M("OTF_RESTART_ENA", RTE_INB_RTP_MISC_LAST_FRM_UPD_CNT, value);
        DBG_PR_REG_M("DBG_ENA", RTE_INB_RTP_MISC_RTP_DBG_ENA, value);
        DBG_PR_REG_M("GRP_ID", RTE_INB_RTP_MISC_RTP_GRP_ID, value);
        REG_RD(RTE_INB_RTP_FRM_PORT(i), &value);
        len = RTE_INB_RTP_FRM_PORT_FRM_LEN_X(value);
        DBG_PR_REG("FRM_PORT", value);
        DBG_PR_REG_M("FRM_LEN", RTE_INB_RTP_FRM_PORT_FRM_LEN, value);
        DBG_PR_REG_M("PORT_NUM", RTE_INB_RTP_FRM_PORT_PORT_NUM, value);
        REG_RD(RTE_INB_RTP_ADDRS(i), &value);
        base = RTE_INB_RTP_ADDRS_FRM_DATA_ADDR_X(value);
        DBG_PR_REG("ADDRS", value);
        DBG_PR_REG(":FRM_DATA_ADDR", base);
        DBG_PR_REG(":REDUN_ADDR", RTE_INB_RTP_ADDRS_REDUN_ADDR_X(value));
        DBG_REG(REG_ADDR(RTE_INB_RTP_TIMER_CFG1(i)), "TIMER_CFG1:FIRST");
        DBG_REG(REG_ADDR(RTE_INB_RTP_TIMER_CFG2(i)), "TIMER_CFG2:DELTA");
        REG_RD(RTE_INB_RTP_CNT(i), &value);
        DBG_PR_REG("CNT", value);
        DBG_PR_REG_M("OTF_CNT", RTE_INB_RTP_CNT_FRM_OTF_CNT, value);
        DBG_PR_REG_M("INJ_CNT", RTE_INB_RTP_CNT_FRM_INJ_CNT, value);
        DBG_REG(REG_ADDR(RTE_INB_RTP_STICKY_BITS(i)), "STICKY_BITS");
        pr("\n");

        if (len) {
            pr("IFH:  223  192-191  160-159  128-127   96-95    64-63    32-31     0\n");
        }
        for (j = 0; j < len; j += 32) {
            addr = (base + j / 32);
            REG_WR(RTE_INB_FRM_DATA_ADDR, RTE_INB_FRM_DATA_ADDR_FRM_DATA_ADDR(addr));
            REG_WR(RTE_INB_FRM_DATA_CHG_ADDR, addr);
            REG_RD(RTE_INB_FRM_DATA_CHG_BYTE, &chg);
            pr("%04x: ", addr);
            for (k = 0; k < 8; k++) {
                REG_RD(RTE_INB_FRM_DATA(0, k), &value);
                for (m = 0; m < 4; m++) {
                    if (chg & (1 << (m + k * 4))) {
                        pr("%02x", (value >> (24 - m * 8)) & 0xff);
                    } else {
                        pr("xx");
                    }
                }
                pr(k == 7 ? "\n" : "-");
            }
        }
        if (len) {
            pr("\n");
        }
    }

    for (i = 0; i < MERA_IB_RAL_CNT; i++) {
        REG_RD(RTE_INB_RD_ACTION_ADDR(i), &value);
        addr = RTE_INB_RD_ACTION_ADDR_RD_ACTION_ADDR_X(value);
        if (addr == 0 && !info->full) {
            continue;
        }
        sprintf(buf, "INB_RD_TIMER_TBL_%u", i);
        mera_debug_print_reg_header(pr, buf);
        DBG_REG(REG_ADDR(RTE_INB_RD_TIMER_CFG1(i)), "FIRST_RUT_CNT");
        DBG_REG(REG_ADDR(RTE_INB_RD_TIMER_CFG2(i)), "DELTA_RUT_CNT");
        DBG_PR_REG("RD_ACTION_ADDR", value);
        pr("\n");

        while (addr != 0) {
            j = addr;
            sprintf(buf, "INB_RD_ACTION_TBL_%u", j);
            mera_debug_print_reg_header(pr, buf);
            REG_RD(RTE_INB_RD_ACTION_ADDRS(j), &value);
            addr = RTE_INB_RD_ACTION_ADDRS_FRM_DATA_CP_ADDR_X(value);
            DBG_PR_REG("RD_ACTION_ADDRS", value);
            DBG_PR_REG_M("FRM_DATA_CP_ADDR", RTE_INB_RD_ACTION_ADDRS_FRM_DATA_CP_ADDR, value);
            DBG_PR_REG_M("RD_ACTION_ADDR", RTE_INB_RD_ACTION_ADDRS_RD_ACTION_ADDR, value);
            REG_RD(RTE_INB_RD_ACTION_MISC(j), &value);
            DBG_PR_REG("RD_ACTION_MISC", value);
            DBG_PR_REG_M("DG_DATA_LEN", RTE_INB_RD_ACTION_MISC_DG_DATA_LEN, value);
            DBG_PR_REG_M("MAGIC_ENA", RTE_INB_RD_ACTION_MISC_RD_MAGIC_ENA, value);
            DBG_PR_REG_M("STATE_STICKY", RTE_INB_RD_ACTION_MISC_STATE_STICKY_ENA, value);
            DBG_PR_REG_M("INTERN_ENA", RTE_INB_RD_ACTION_MISC_INTERN_ENA, value);
            DBG_PR_REG_M("RD_CNT", RTE_INB_RD_ACTION_MISC_RD_CNT, value);
            DBG_REG(REG_ADDR(RTE_INB_BASE_RAI_ADDR(j)), "BASE_RAI_ADDR");
            DBG_REG(REG_ADDR(RTE_INB_RD_ACTION_STICKY_BITS(j)), "STICKY_BITS");
            pr("\n");

            while (addr != 0) {
                k = addr;
                sprintf(buf, "INB_FRM_CP_TBL_%u", k);
                mera_debug_print_reg_header(pr, buf);
                REG_RD(RTE_INB_FRM_DATA_CP_ADDRS(k), &value);
                DBG_PR_REG("DATA_CP_ADDRS", value);
                DBG_PR_REG_M("DATA_CP_ADDR", RTE_INB_FRM_DATA_CP_ADDRS_FRM_DATA_CP_ADDR, value);
                DBG_PR_REG_M("DATA_CTRL_ADDR", RTE_INB_FRM_DATA_CP_ADDRS_FRM_DATA_CTRL_ADDR, value);
                addr = RTE_INB_FRM_DATA_CP_ADDRS_FRM_DATA_CP_ADDR_X(value);
                REG_RD(RTE_INB_FRM_DATA_BYTE_ADDR1(k), &value);
                DBG_PR_REG("DATA_BYTE_ADDR1", value);
                DBG_PR_REG_M("FRM_BYTE_ADDR",  RTE_INB_FRM_DATA_BYTE_ADDR1_DG_FRM_DATA_BYTE_ADDR, value);
                DBG_PR_REG_M("VLD_FRM_BYTE_ADDR", RTE_INB_FRM_DATA_BYTE_ADDR1_DG_VLD_FRM_DATA_BYTE_ADDR, value);
                REG_RD(RTE_INB_FRM_DATA_BYTE_ADDR2(k), &value);
                DBG_PR_REG("DATA_BYTE_ADDR2", value);
                DBG_PR_REG_M("STS_FRM_BYTE_ADDR", RTE_INB_FRM_DATA_BYTE_ADDR2_DG_STATUS_FRM_DATA_BYTE_ADDR, value);
                REG_RD(RTE_INB_FRM_DATA_CP_MISC(k), &value);
                DBG_PR_REG("DATA_CP_MISC", value);
                DBG_PR_REG_M("VLD_CLR_MODE", RTE_INB_FRM_DATA_CP_MISC_DG_VLD_CLR_MODE, value);
                DBG_PR_REG_M("VLD_SET_MODE", RTE_INB_FRM_DATA_CP_MISC_DG_VLD_SET_MODE, value);
                DBG_PR_REG_M("VLD_ERR_MODE", RTE_INB_FRM_DATA_CP_MISC_DG_VLD_ERR_MODE, value);
                DBG_PR_REG_M("STS_CLR_MODE", RTE_INB_FRM_DATA_CP_MISC_DG_STATUS_CLR_MODE, value);
                DBG_PR_REG_M("STS_SET_MODE", RTE_INB_FRM_DATA_CP_MISC_DG_STATUS_SET_MODE, value);
                DBG_PR_REG_M("STS_ERR_MODE", RTE_INB_FRM_DATA_CP_MISC_DG_STATUS_ERR_MODE, value);
                DBG_PR_REG_M("SOF", RTE_INB_FRM_DATA_CP_MISC_SOF, value);
                DBG_PR_REG_M("EOF", RTE_INB_FRM_DATA_CP_MISC_EOF, value);
                DBG_PR_REG_M("LAST_TX_CNT", RTE_INB_FRM_DATA_CP_MISC_LAST_FRM_TX_CNT, value);
                DBG_PR_REG_M("STICKY_ENA", RTE_INB_FRM_DATA_CP_MISC_STATE_STICKY_ENA, value);
                pr("\n");
            }
            REG_RD(RTE_INB_RD_ACTION_ADDRS(j), &value);
            addr = RTE_INB_RD_ACTION_ADDRS_RD_ACTION_ADDR_X(value);
        }
    }

    return 0;
}
