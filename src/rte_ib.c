// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#define LAN9662_TRACE_GROUP LAN9662_TRACE_GROUP_IB
#include "rte_private.h"

int lan9662_ib_init(struct lan9662_rte_inst *inst)
{
    T_I("enter");
    return 0;
}

int lan9662_rte_ib_rtp_conf_get(struct lan9662_rte_inst   *inst,
                                const uint16_t            rtp_id,
                                lan9662_rte_ib_rtp_conf_t *const conf)
{
    T_I("enter");
    inst = lan9662_inst_get(inst);
    LAN9662_RC(lan9662_rte_rtp_check(rtp_id));
    *conf = inst->ib.rtp_tbl[rtp_id].conf;
    return 0;
}

#define IFH_LEN 28

int lan9662_rte_ib_rtp_conf_set(struct lan9662_rte_inst         *inst,
                                const uint16_t                  rtp_id,
                                const lan9662_rte_ib_rtp_conf_t *const conf)
{
    lan9662_rte_ib_t *ib;
    uint32_t         type = (conf->type == LAN9662_RTP_TYPE_OPC_UA ? 1 : 0);
    uint32_t         ena = (conf->type == LAN9662_RTP_TYPE_DISABLED ? 0 : 1);
    uint32_t         len = (conf->length < 60 ? 60 : conf->length);
    uint32_t         inj = (conf->mode == LAN9662_RTP_IB_MODE_INJ ? 1 : 0);
    uint32_t         i, j, k, m, addr, value, len_old, cnt, chg;

    T_I("enter");
    inst = lan9662_inst_get(inst);
    ib = &inst->ib;
    LAN9662_RC(lan9662_rte_rtp_check(rtp_id));

    // Check frame length
    if (len > LAN9662_FRAME_DATA_CNT) {
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

    ib->rtp_tbl[rtp_id].conf = *conf;
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
           RTE_INB_RTP_TIMER_CFG2_DELTA_RUT_CNT(LAN9662_RUT_TIME(conf->time)));
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

static int lan9662_rte_ib_rtp_counters_update(struct lan9662_rte_inst       *inst,
                                              const uint16_t                rtp_id,
                                              lan9662_rte_ib_rtp_counters_t *const counters,
                                              int                           clear)
{
    lan9662_rte_ib_rtp_entry_t *rtp;
    uint32_t                   value;

    rtp = &inst->ib.rtp_tbl[rtp_id];
    if (rtp->conf.type != LAN9662_RTP_TYPE_DISABLED) {
        REG_RD(RTE_INB_RTP_CNT(rtp_id), &value);
        lan9662_rte_cnt_16_update(RTE_INB_RTP_CNT_FRM_OTF_CNT_X(value), &rtp->tx_otf, clear);
        lan9662_rte_cnt_16_update(RTE_INB_RTP_CNT_FRM_INJ_CNT_X(value), &rtp->tx_inj, clear);
    }
    if (counters != NULL) {
        counters->tx_otf = rtp->tx_otf.value;
        counters->tx_inj = rtp->tx_inj.value;
    }
    return 0;
}

int lan9662_rte_ib_rtp_counters_get(struct lan9662_rte_inst       *inst,
                                    const uint16_t                rtp_id,
                                    lan9662_rte_ib_rtp_counters_t *const counters)
{
    T_I("enter");
    inst = lan9662_inst_get(inst);
    LAN9662_RC(lan9662_rte_rtp_check(rtp_id));
    return lan9662_rte_ib_rtp_counters_update(inst, rtp_id, counters, 0);
}

int lan9662_rte_ib_rtp_counters_clr(struct lan9662_rte_inst *inst,
                                    const uint16_t          rtp_id)
{
    T_I("enter");
    inst = lan9662_inst_get(inst);
    LAN9662_RC(lan9662_rte_rtp_check(rtp_id));
    return lan9662_rte_ib_rtp_counters_update(inst, rtp_id, NULL, 1);
}

int lan9662_ib_poll(struct lan9662_rte_inst *inst)
{
    lan9662_rte_ib_t *ib = &inst->ib;
    uint32_t         i;

    T_I("enter");
    for (i = 0; i < RTE_POLL_CNT; i++) {
        ib->rtp_id++;
        if (ib->rtp_id >= RTE_IB_RTP_CNT) {
            ib->rtp_id = 1;
        }
        LAN9662_RC(lan9662_rte_ib_rtp_counters_update(inst, ib->rtp_id, NULL, 0));
    }
    return 0;
}

int lan9662_ib_debug_print(struct lan9662_rte_inst *inst,
                           const lan9662_debug_printf_t pr,
                           const lan9662_debug_info_t   *const info)
{
    lan9662_rte_ib_t           *ib = &inst->ib;
    lan9662_rte_ib_rtp_entry_t *rtp;
    const char                 *txt;
    uint32_t                   i, j, k, m, value, chg, base, addr, len;
    char                       buf[32];

    lan9662_debug_print_header(pr, "RTE Inbound State");
    pr("Next RTP ID    : %u\n", ib->rtp_id);
    addr = ib->frm_data_addr;
    pr("Frame Data Addr: %u (%u bytes used)\n\n", addr, addr * 32);

    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        rtp = &ib->rtp_tbl[i];
        switch (rtp->conf.type) {
        case LAN9662_RTP_TYPE_PN:
            txt = "Profinet";
            break;
        case LAN9662_RTP_TYPE_OPC_UA:
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
        pr("Mode  : %s\n", rtp->conf.mode == LAN9662_RTP_IB_MODE_INJ ? "INJ" : "OTF");
        pr("Time  : %u.%03u usec\n", rtp->conf.time / 1000, rtp->conf.time % 1000);
        len = rtp->conf.length;
        pr("Length: %u\n", len);
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

    lan9662_debug_print_header(pr, "RTE Inbound Registers");
    lan9662_debug_print_reg_header(pr, "RTE Inbound");
    lan9662_debug_reg(inst, pr, REG_ADDR(RTE_INB_CFG), "RTE_INB_CFG");
    lan9662_debug_reg(inst, pr, REG_ADDR(RTE_INB_STICKY_BITS), "RTE_INB_STICKY_BITS");
    pr("\n");

    for (i = 1; i < RTE_IB_RTP_CNT; i++) {
        REG_RD(RTE_INB_RTP_MISC(i), &value);
        if (RTE_INB_RTP_MISC_RTP_ENA_X(value) == 0 && !info->full) {
            continue;
        }
        sprintf(buf, "INB_RTP_TBL_%u", i);
        lan9662_debug_print_reg_header(pr, buf);
        lan9662_debug_reg(inst, pr, REG_ADDR(RTE_INB_RTP_MISC(i)), "MISC");
        REG_RD(RTE_INB_RTP_FRM_PORT(i), &value);
        len = RTE_INB_RTP_FRM_PORT_FRM_LEN_X(value);
        lan9662_debug_print_reg(pr, "FRM_PORT", value);
        lan9662_debug_print_reg(pr, ":FRM_LEN", len);
        lan9662_debug_print_reg(pr, ":PORT_NUM", RTE_INB_RTP_FRM_PORT_PORT_NUM_X(value));
        REG_RD(RTE_INB_RTP_ADDRS(i), &value);
        base = RTE_INB_RTP_ADDRS_FRM_DATA_ADDR_X(value);
        lan9662_debug_print_reg(pr, "ADDRS", value);
        lan9662_debug_print_reg(pr, ":FRM_DATA_ADDR", base);
        lan9662_debug_print_reg(pr, ":REDUN_ADDR", RTE_INB_RTP_ADDRS_REDUN_ADDR_X(value));
        lan9662_debug_reg(inst, pr, REG_ADDR(RTE_INB_RTP_TIMER_CFG1(i)), "TIMER_CFG1:FIRST");
        lan9662_debug_reg(inst, pr, REG_ADDR(RTE_INB_RTP_TIMER_CFG2(i)), "TIMER_CFG2:DELTA");
        REG_RD(RTE_INB_RTP_CNT(i), &value);
        lan9662_debug_print_reg(pr, "CNT", value);
        lan9662_debug_print_reg(pr, ":OTF_CNT", RTE_INB_RTP_CNT_FRM_OTF_CNT_X(value));
        lan9662_debug_print_reg(pr, ":INJ_CNT", RTE_INB_RTP_CNT_FRM_INJ_CNT_X(value));
        lan9662_debug_reg(inst, pr, REG_ADDR(RTE_INB_RTP_STICKY_BITS(i)), "STICKY_BITS");
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

    return 0;
}
