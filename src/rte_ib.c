// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#define MERA_TRACE_GROUP MERA_TRACE_GROUP_IB
#include "rte_private.h"

int mera_ib_init(struct mera_inst *inst)
{
    T_I("enter");

    // DG status clear/set values for OPC: BadFailure/Good
    REG_WR(RTE_INB_DG_STATUS_CLR_SET,
           RTE_INB_DG_STATUS_CLR_SET_OPC_DG_STATUS_CLR(0x40) |
           RTE_INB_DG_STATUS_CLR_SET_OPC_DG_STATUS_SET(0x00));
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
    mera_rte_time_t     time;
    uint32_t            type = (conf->type == MERA_RTP_TYPE_OPC_UA ? 1 : 0);
    uint32_t            ena = (conf->type == MERA_RTP_TYPE_DISABLED ? 0 : 1);
    uint32_t            len = (conf->length < 60 ? 60 : conf->length);
    uint32_t            inj = (conf->mode == MERA_RTP_IB_MODE_INJ ? 1 : 0);
    uint32_t            i, j, k, m, addr, value, len_old, cnt, chg;

    T_I("enter");
    inst = mera_inst_get(inst);
    ib = &inst->ib;
    MERA_RC(mera_rtp_check(rtp_id));
    rtp = &ib->rtp_tbl[rtp_id];
    MERA_RC(mera_time_get(inst, &conf->time, &time));

    // Check frame length
    if (len > MERA_FRAME_DATA_CNT) {
        T_E("illegal length: %u", len);
        return -1;
    }
    len += (IFH_LEN + 4);
    REG_RD(RTE_INB_RTP_FRM_PORT(rtp_id), &value);
    len_old = RTE_INB_RTP_FRM_PORT_FRM_LEN_X(value);
    cnt = ((len + 31) / 32);
    if (len_old == 0) {
        // Allocate new frame data address
        addr = ib->frm_data_addr;
        if ((addr + cnt) > RTE_IB_FRAME_MEM_SIZE) {
            T_E("frame memory is full");
            return -1;
        }
        rtp->frm_data_addr = addr;
        ib->frm_data_addr += cnt;
        REG_WR(RTE_INB_RTP_ADDRS(rtp_id),
               RTE_INB_RTP_ADDRS_FRM_DATA_ADDR(addr) |
               RTE_INB_RTP_ADDRS_REDUN_ADDR(0));
    } else {
        // Reuse existing frame data address
        if (len_old != len) {
            T_E("length can not be changed");
            return -1;
        }
        REG_RD(RTE_INB_RTP_ADDRS(rtp_id), &value);
        addr = RTE_INB_RTP_ADDRS_FRM_DATA_ADDR_X(value);
    }

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
    REG_WR(RTE_INB_RTP_FRM_POS(rtp_id), RTE_INB_RTP_FRM_POS_PN_CC_FRM_POS(len - 8));
    REG_WR(RTE_INB_RTP_TIMER_CFG1(rtp_id), RTE_INB_RTP_TIMER_CFG1_FIRST_RUT_CNT(time.first));
    REG_WR(RTE_INB_RTP_TIMER_CFG2(rtp_id), RTE_INB_RTP_TIMER_CFG2_DELTA_RUT_CNT(time.delta));
    REG_WR(RTE_INB_TIMER_CMD,
           RTE_INB_TIMER_CMD_TIMER_CMD(ena && inj ? 2 : 1) |
           RTE_INB_TIMER_CMD_TIMER_RSLT(0) |
           RTE_INB_TIMER_CMD_TIMER_TYPE(0) |
           RTE_INB_TIMER_CMD_TIMER_IDX(rtp_id));

    // Frame data
    for (i = 0; i < cnt; i++, addr++) {
        REG_WR(RTE_INB_FRM_DATA_CHG_ADDR, RTE_INB_FRM_DATA_CHG_ADDR_FRM_DATA_CHG_ADDR(addr));
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
    mera_rte_time_t time;

    MERA_RC(mera_ral_check(ral_id));
    inst = mera_inst_get(inst);
    MERA_RC(mera_time_get(inst, &conf->time, &time));
    inst->ib.ral_tbl[ral_id].conf = *conf;
    REG_WR(RTE_INB_RD_TIMER_CFG1(ral_id), RTE_INB_RD_TIMER_CFG1_FIRST_RUT_CNT(time.first));
    REG_WR(RTE_INB_RD_TIMER_CFG2(ral_id), RTE_INB_RD_TIMER_CFG2_DELTA_RUT_CNT(time.delta));
    REG_WR(RTE_INB_TIMER_CMD,
           RTE_INB_TIMER_CMD_TIMER_CMD(2) |
           RTE_INB_TIMER_CMD_TIMER_RSLT(0) |
           RTE_INB_TIMER_CMD_TIMER_TYPE(1) |
           RTE_INB_TIMER_CMD_TIMER_IDX(ral_id));
    return 0;
}

int mera_ib_ral_req(struct mera_inst       *inst,
                    const mera_ib_ral_id_t ral_id,
                    mera_buf_t             *const buf)
{
    uint32_t value;

    MERA_RC(mera_ral_check(ral_id));
    inst = mera_inst_get(inst);
    REG_RD(RTE_INB_BUF3_WR_REQ(ral_id), &value);
    value = RTE_INB_BUF3_WR_REQ_WR_IDX_X(value);
    if (value > 2) {
        T_E("invalid WR_IDX for ral_id %u", ral_id);
        return -1;
    }
    buf->addr = (value * RTE_BUF3_SIZE);
    return 0;
}

int mera_ib_ral_rel(struct mera_inst       *inst,
                    const mera_ib_ral_id_t ral_id)
{
    uint32_t value;

    MERA_RC(mera_ral_check(ral_id));
    inst = mera_inst_get(inst);
    REG_RD(RTE_INB_BUF3_WR_REL(ral_id), &value);
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
    uint32_t            offset;
    uint16_t            addr, found = 0;

    MERA_RC(mera_ral_check(ral_id));
    inst = mera_inst_get(inst);
    ib = &inst->ib;
    ral = &ib->ral_tbl[ral_id];

    // Check if entry already exists
    for (addr = ral->addr; addr != 0; addr = ra->addr) {
        ra = &ib->ra_tbl[addr];
        if (ra->conf.ra_id == conf->ra_id) {
            T_E("ral_id %u already has ra_id %u", ral_id, conf->ra_id);
            return -1;
        }
    }

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
    REG_WR(RTE_INB_BASE_RAI_ADDR(addr), mera_addr_get(&conf->rd_addr));
    offset = mera_addr_offset(&conf->rd_addr);
    REG_WR(RTE_INB_OFFSET_RAI_ADDR(addr), offset);
    // Read mode is NONE(0)/REQ_REL(3)/REQ(1)
    REG_WR(RTE_INB_RD_ACTION_BUF3(addr),
           RTE_INB_RD_ACTION_BUF3_BUF3_ADDR(ral_id) |
           RTE_INB_RD_ACTION_BUF3_BUF3_RD_MODE(offset == 0 ? 0 : ral->cnt == 0 ? 3 : 1));
    REG_WR(RTE_INB_RD_ACTION_MISC(addr),
           RTE_INB_RD_ACTION_MISC_DG_DATA_LEN(conf->length) |
           RTE_INB_RD_ACTION_MISC_RD_MAGIC_ENA(0) |
           RTE_INB_RD_ACTION_MISC_STATE_STICKY_ENA(0) |
           RTE_INB_RD_ACTION_MISC_INTERN_ENA(0) |
           RTE_INB_RD_ACTION_MISC_RD_CNT(0));
    REG_WR(RTE_INB_RD_ACTION_ADDRS(addr),
           RTE_INB_RD_ACTION_ADDRS_FRM_DATA_CP_ADDR(0) |
           RTE_INB_RD_ACTION_ADDRS_RD_ACTION_ADDR(ra->addr));

    if (offset != 0) {
        // Read mode for next entry is NONE(0)/REL(2)
        if (ral->prev != 0) {
            REG_WRM(RTE_INB_RD_ACTION_BUF3(ral->prev),
                    RTE_INB_RD_ACTION_BUF3_BUF3_RD_MODE(ral->cnt == 1 ? 2 : 0),
                    RTE_INB_RD_ACTION_BUF3_BUF3_RD_MODE_M);
        }
        ral->cnt++;
        ral->prev = addr;
    }

    // Update RAL
    REG_WR(RTE_INB_RD_ACTION_ADDR(ral_id), RTE_INB_RD_ACTION_ADDR_RD_ACTION_ADDR(ral->addr));

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
    uint32_t            frm_addr, valid_mode, status_mode, opc;

    inst = mera_inst_get(inst);
    ib = &inst->ib;
    MERA_RC(mera_ral_check(ral_id));
    MERA_RC(mera_rtp_check(conf->rtp_id));
    rtp = &ib->rtp_tbl[conf->rtp_id];
    if (rtp->conf.type == MERA_RTP_TYPE_DISABLED) {
        T_E("rtp_id %u is disabled", conf->rtp_id);
        return -1;
    }

    // Check valid_offset
    opc = (rtp->conf.type == MERA_RTP_TYPE_OPC_UA ? 1 : 0);
    if (conf->valid_offset == 0 &&
        (conf->valid_update || (opc && (conf->opc_seq_update || conf->opc_code_update)))) {
        T_E("valid_offset must be non-zero when update enabled");
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
    if (ra->dg_cnt >= RTE_IB_RA_DG_CNT) {
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
           RTE_INB_FRM_DATA_CP_ADDRS_FRM_DATA_CTRL_ADDR(rtp->frm_data_addr));
    frm_addr = (rtp->frm_data_addr * 32 + IFH_LEN + 14);
    REG_WR(RTE_INB_FRM_DATA_BYTE_ADDR1(addr),
           RTE_INB_FRM_DATA_BYTE_ADDR1_DG_FRM_DATA_BYTE_ADDR(frm_addr + conf->pdu_offset) |
           RTE_INB_FRM_DATA_BYTE_ADDR1_DG_VLD_FRM_DATA_BYTE_ADDR(frm_addr + conf->valid_offset));
    REG_WR(RTE_INB_FRM_DATA_BYTE_ADDR2(addr),
           RTE_INB_FRM_DATA_BYTE_ADDR2_DG_STATUS_FRM_DATA_BYTE_ADDR(frm_addr + conf->valid_offset + 3));

    if (opc && conf->opc_seq_update) {
        // Update OPC sequence number offset
        frm_addr += (conf->valid_offset + 1);
        REG_WR(RTE_INB_FRM_DATA_CHG_ADDR, RTE_INB_FRM_DATA_CHG_ADDR_FRM_DATA_CHG_ADDR(frm_addr / 32));
        REG_WRM_SET(RTE_INB_FRM_DATA_OPC_DG_SEQ_NUM_BYTE_POS, 1 << (frm_addr % 32));
    }

    valid_mode = (conf->valid_update == 0 ? 0 : opc ? 2 : 1);
    status_mode = (conf->opc_code_update && opc ? 2 : 0);
    REG_WR(RTE_INB_FRM_DATA_CP_MISC(addr),
           RTE_INB_FRM_DATA_CP_MISC_DG_VLD_CLR_MODE(valid_mode) |
           RTE_INB_FRM_DATA_CP_MISC_DG_VLD_SET_MODE(valid_mode) |
           RTE_INB_FRM_DATA_CP_MISC_DG_VLD_ERR_MODE(0) |
           RTE_INB_FRM_DATA_CP_MISC_DG_STATUS_CLR_MODE(status_mode) |
           RTE_INB_FRM_DATA_CP_MISC_DG_STATUS_SET_MODE(status_mode) |
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

// Number of entries in local sequence number offset table
#define RTE_IB_SEQ_CNT 32

int mera_ib_debug_print(struct mera_inst *inst,
                        const mera_debug_printf_t pr,
                        const mera_debug_info_t   *const info)
{
    mera_ib_t              *ib = &inst->ib;
    mera_ib_rtp_entry_t    *rtp;
    mera_ib_rtp_conf_t     *rc;
    mera_ib_rtp_counters_t cnt;
    mera_ib_ral_entry_t    *ral;
    mera_ib_ra_entry_t     *ra;
    mera_ib_dg_entry_t     *dg;
    mera_ib_dg_conf_t      *dc;
    const char             *txt;
    uint32_t               i, j, k, m, n, value, seq, chg, base, addr, len;
    char                   buf[64];
    struct {
        uint16_t cnt;
        uint16_t val[RTE_IB_SEQ_CNT];
    } seq_table;

    mera_debug_print_header(pr, "RTE Inbound State");
    pr("Next RTP ID    : %u\n", ib->rtp_id);
    addr = ib->frm_data_addr;
    pr("Frame Data Addr: %u (%u bytes used)\n\n", addr, addr * 32);

    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        rtp = &ib->rtp_tbl[i];
        rc = &rtp->conf;
        switch (rc->type) {
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
        pr("Mode  : %s\n", rc->mode == MERA_RTP_IB_MODE_INJ ? "INJ" : "OTF");
        pr("Time  : %s\n", mera_time_txt(buf, &rc->time));
        len = rc->length;
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
            pr("%02x%s", rc->data[j],
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
        pr("Time  : %s\n", mera_time_txt(buf, &ral->conf.time));
        for ( ; addr != 0; addr = ra->addr) {
            ra = &ib->ra_tbl[addr];
            pr("\n  Addr  RA ID  RD Addr            Length  DG_CNT\n");
            pr("  %-6u%-7u%-19s%-8u%u\n",
               addr, ra->conf.ra_id, mera_addr_txt(buf, &ra->conf.rd_addr), ra->conf.length, ra->dg_cnt);
            for (addr = ra->dg_addr; addr != 0; addr = dg->addr) {
                dg = &ib->dg_tbl[addr];
                dc = &dg->conf;
                if (addr == ra->dg_addr) {
                    pr("\n    Addr  RTP  PDU   Vld_Off  Vld_Upd  Seq_Upd  Code_Upd\n");
                }
                pr("    %-6u%-5u%-6u%-9u%-9u%-9u%u\n", addr, dc->rtp_id,
                   dc->pdu_offset, dc->valid_offset, dc->valid_update, dc->opc_seq_update, dc->opc_code_update);
            }
        }
        pr("\n");
    }

    mera_debug_print_header(pr, "RTE Inbound Registers");
    mera_debug_print_reg_header(pr, "RTE Inbound");
    DBG_REG(REG_ADDR(RTE_INB_CFG), "RTE_INB_CFG");
    REG_RD(RTE_INB_DG_VLD_CLR_SET, &value);
    DBG_PR_REG("VLD_CLR_SET", value);
    DBG_PR_REG_M("CLR_IOPS", RTE_INB_DG_VLD_CLR_SET_PN_DG_VLD_CLR_IOPS, value);
    DBG_PR_REG_M("CLR_DSF1", RTE_INB_DG_VLD_CLR_SET_OPC_DG_VLD_CLR_DATA_SET_FLAGS1, value);
    DBG_PR_REG_M("SET_IOPS", RTE_INB_DG_VLD_CLR_SET_PN_DG_VLD_SET_IOPS, value);
    DBG_PR_REG_M("SET_DSF1", RTE_INB_DG_VLD_CLR_SET_OPC_DG_VLD_SET_DATA_SET_FLAGS1, value);
    REG_RD(RTE_INB_DG_STATUS_CLR_SET, &value);
    DBG_PR_REG("STATUS_CLR_SET", value);
    DBG_PR_REG_M("PN_DG_STATUS_CLR", RTE_INB_DG_STATUS_CLR_SET_PN_DG_STATUS_CLR, value);
    DBG_PR_REG_M("OPC_DG_STATUS_CLR", RTE_INB_DG_STATUS_CLR_SET_OPC_DG_STATUS_CLR, value);
    DBG_PR_REG_M("PN_DG_STATUS_SET", RTE_INB_DG_STATUS_CLR_SET_PN_DG_STATUS_SET, value);
    DBG_PR_REG_M("OPC_DG_STATUS_SET", RTE_INB_DG_STATUS_CLR_SET_OPC_DG_STATUS_SET, value);
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
        DBG_REG(REG_ADDR(RTE_INB_RTP_FRM_POS(i)), "RTP_FRM_POS");
        REG_RD(RTE_INB_RTP_ADDRS(i), &value);
        base = RTE_INB_RTP_ADDRS_FRM_DATA_ADDR_X(value);
        DBG_PR_REG("ADDRS", value);
        DBG_PR_REG(":FRM_DATA_ADDR", base);
        DBG_PR_REG(":REDUN_ADDR", RTE_INB_RTP_ADDRS_REDUN_ADDR_X(value));
        REG_WR(RTE_INB_FRM_DATA_CTRL_ACC, RTE_INB_FRM_DATA_CTRL_ACC_FRM_DATA_CTRL_ADDR(base));
        REG_RD(RTE_INB_FRM_DATA_CTRL, &value);
        DBG_PR_REG("FRM_DATA_CTRL", value);
        DBG_PR_REG_M("FRM_TXING", RTE_INB_FRM_DATA_CTRL_FRM_TXING, value);
        DBG_PR_REG_M("FRM_TX_CNT", RTE_INB_FRM_DATA_CTRL_FRM_TX_CNT, value);
        DBG_PR_REG_M("FRM_UPDATING", RTE_INB_FRM_DATA_CTRL_FRM_UPDATING, value);
        DBG_PR_REG_M("FRM_UPD_CNT", RTE_INB_FRM_DATA_CTRL_FRM_UPD_CNT, value);
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
        seq_table.cnt = 0;
        for (j = 0; j < len; j += 32) {
            addr = (base + j / 32);
            REG_WR(RTE_INB_FRM_DATA_ADDR, RTE_INB_FRM_DATA_ADDR_FRM_DATA_ADDR(addr));
            REG_WR(RTE_INB_FRM_DATA_CHG_ADDR, addr);
            REG_RD(RTE_INB_FRM_DATA_CHG_BYTE, &chg);
            REG_RD(RTE_INB_FRM_DATA_OPC_DG_SEQ_NUM_BYTE_POS, &seq);
            pr("%04x: ", addr);
            for (k = 0; k < 8; k++) {
                REG_RD(RTE_INB_FRM_DATA(0, k), &value);
                for (m = 0; m < 4; m++) {
                    n = (m + k * 4);
                    if (chg & (1 << n)) {
                        pr("%02x", (value >> (24 - m * 8)) & 0xff);
                    } else {
                        pr("xx");
                    }
                    if ((seq & (1 << n)) && seq_table.cnt < RTE_IB_SEQ_CNT) {
                        // Save sequence number offset from frame base
                        seq_table.val[seq_table.cnt++] = (j + n);
                    }
                }
                pr(k == 7 ? "\n" : "-");
            }
        }
        for (j = 0; j < seq_table.cnt; j++) {
            pr("%sSeq_Offs_%-2u: %u\n", j == 0 ? "\n" : "", j, seq_table.val[j]);
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
        REG_WR(RTE_INB_BUF3_MISC, RTE_INB_BUF3_MISC_BUF3_ADDR(i));
        REG_RD(RTE_INB_BUF3, &value);
        DBG_PR_REG("INB_BUF3", value);
        DBG_PR_REG_M("RD_IDX", RTE_INB_BUF3_RD_IDX, value);
        DBG_PR_REG_M("WR_IDX", RTE_INB_BUF3_WR_IDX, value);
        DBG_PR_REG_M("AV_IDX", RTE_INB_BUF3_AV_IDX, value);
        DBG_PR_REG_M("AV_NEW", RTE_INB_BUF3_AV_NEW, value);
        DBG_PR_REG_M("TOO_SLOW_CNT", RTE_INB_BUF3_TOO_SLOW_CNT, value);
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
            REG_RD(RTE_INB_RD_ACTION_BUF3(j), &value);
            DBG_PR_REG("RD_ACTION_BUF3", value);
            DBG_PR_REG_M("BUF3_ADDR", RTE_INB_RD_ACTION_BUF3_BUF3_ADDR, value);
            DBG_PR_REG_M("BUF3_RD_MODE", RTE_INB_RD_ACTION_BUF3_BUF3_RD_MODE, value);
            DBG_REG(REG_ADDR(RTE_INB_BASE_RAI_ADDR(j)), "BASE_RAI_ADDR");
            DBG_REG(REG_ADDR(RTE_INB_OFFSET_RAI_ADDR(j)), "OFFSET_RAI_ADDR");
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
                REG_RD(RTE_INB_FRM_DATA_CP_STICKY_BITS(k), &value);
                DBG_PR_REG("CP_STICKY_BITS", value);
                DBG_PR_REG_M("TXING_AT_START", RTE_INB_FRM_DATA_CP_STICKY_BITS_FRM_TXING_AT_START_STICKY, value);
                DBG_PR_REG_M("TXING_AT_END", RTE_INB_FRM_DATA_CP_STICKY_BITS_FRM_TXING_AT_END_STICKY, value);
                DBG_PR_REG_M("SAME_TX_CNT", RTE_INB_FRM_DATA_CP_STICKY_BITS_SAME_FRM_TX_CNT_STICKY, value);
                DBG_PR_REG_M("UPDATING_ON_SOF", RTE_INB_FRM_DATA_CP_STICKY_BITS_FRM_UPDATING_ON_SOF_ERR_STICKY, value);
                DBG_PR_REG_M("NOT_UPDATING_ON_EOF", RTE_INB_FRM_DATA_CP_STICKY_BITS_NOT_FRM_UPDATING_ON_EOF_ERR_STICKY, value);
                pr("\n");
            }
            REG_RD(RTE_INB_RD_ACTION_ADDRS(j), &value);
            addr = RTE_INB_RD_ACTION_ADDRS_RD_ACTION_ADDR_X(value);
        }
    }

    return 0;
}
