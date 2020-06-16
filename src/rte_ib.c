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
                                uint16_t                  rtp_id,
                                lan9662_rte_ib_rtp_conf_t *const conf)
{
    T_I("enter");
    inst = lan9662_inst_get(inst);
    LAN9662_RC(lan9662_rte_rtp_check(rtp_id));
    *conf = inst->ib.rtp_tbl[rtp_id].conf;
    return 0;
}

#define IFH_LEN 28

int lan9662_rte_ib_rtp_conf_set(struct lan9662_rte_inst        *inst,
                                uint16_t                        rtp_id,
                                const lan9662_rte_ib_rtp_conf_t *const conf)
{
    lan9662_rte_ib_t           *ib;
    lan9662_rte_ib_rtp_entry_t *rtp;
    uint32_t type = (conf->type == LAN9662_RTP_TYPE_OPC_UA ? 1 : 0);
    uint32_t ena = (conf->type == LAN9662_RTP_TYPE_DISABLED ? 0 : 1);
    uint16_t len = (conf->length < 60 ? 60 : conf->length);
    uint32_t i, j, k, m, addr, value;

    T_I("enter");
    inst = lan9662_inst_get(inst);
    ib = &inst->ib;
    LAN9662_RC(lan9662_rte_rtp_check(rtp_id));
    if (len > LAN9662_FRAME_DATA_CNT) {
        T_E("illegal length: %u", len);
        return -1;
    }
    len += (IFH_LEN + 4);
    rtp = &ib->rtp_tbl[rtp_id];
    if (rtp->conf.type != LAN9662_RTP_TYPE_DISABLED) {
        T_E("changing existing RTP is not allowed");
        return -1;
    }
    if (!ena) {
        T_E("RTP must be enabled");
        return -1;
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
    REG_WR(RTE_INB_RTP_ADDRS(rtp_id),
           RTE_INB_RTP_ADDRS_FRM_DATA_ADDR(ib->frm_data_addr) |
           RTE_INB_RTP_ADDRS_REDUN_ADDR(0));

    // If conf->time is zero, it is a one-shot and we set FIRST to delay the frame.
    // The delayed one-shot frame is a test feature.
    REG_RD(RTE_SC_TIME, &value);
    value = (conf->time ? 0 : RTE_SC_TIME_SC_RUT_CNT_X(value));
    REG_WR(RTE_INB_RTP_TIMER_CFG1(rtp_id), RTE_INB_RTP_TIMER_CFG1_FIRST_RUT_CNT(value));
    REG_WR(RTE_INB_RTP_TIMER_CFG2(rtp_id),
           RTE_INB_RTP_TIMER_CFG2_DELTA_RUT_CNT(LAN9662_RUT_TIME(conf->time)));
    REG_WR(RTE_INB_TIMER_CMD,
           RTE_INB_TIMER_CMD_TIMER_CMD(ena ? 2 : 1) |
           RTE_INB_TIMER_CMD_TIMER_RSLT(0) |
           RTE_INB_TIMER_CMD_TIMER_TYPE(0) |
           RTE_INB_TIMER_CMD_TIMER_IDX(rtp_id));

    // Frame data
    for (i = 0; i < len; i += 32) {
        addr = ib->frm_data_addr;
        ib->frm_data_addr++;
        REG_WR(RTE_INB_FRM_DATA_CHG_ADDR, addr);
        REG_WR(RTE_INB_FRM_DATA_CHG_BYTE, 0xffffffff);
        REG_WR(RTE_INB_FRM_DATA_ADDR, RTE_INB_FRM_DATA_ADDR_FRM_DATA_ADDR(addr));
        REG_WR(RTE_INB_FRM_DATA_WR_MASK, 0xffffffff);
        for (j = 0; j < 8; j++) {
            value = 0;
            k = (i + j * 4);
            if (k >= IFH_LEN) {
                k -= IFH_LEN;
                for (m = 0; m < 4; m++, k++) {
                    value <<= 8;
                    if (k < conf->length) {
                        value += conf->data[k];
                    }
                }
            }
            REG_WR(RTE_INB_FRM_DATA(0, j), value);
        }
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
    addr = ib->frm_data_addr;
    pr("Frame Data Addr: %u (%u bytes)\n\n", addr, addr * 32);

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
            REG_WR(RTE_INB_FRM_DATA_CHG_ADDR, addr);
            REG_RD(RTE_INB_FRM_DATA_CHG_BYTE, &chg);
            REG_WR(RTE_INB_FRM_DATA_ADDR, RTE_INB_FRM_DATA_ADDR_FRM_DATA_ADDR(addr));
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
