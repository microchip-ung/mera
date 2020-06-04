// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#define LAN9662_TRACE_GROUP LAN9662_TRACE_GROUP_OB
#include "rte_private.h"

int lan9662_ob_init(struct lan9662_rte_inst *inst)
{
    T_I("enter");
    return 0;
}

static int lan9662_ob_rtp_check(uint32_t rtp_id)
{
    if (rtp_id == 0 || rtp_id >= LAN9662_RTE_RTP_CNT) {
        T_E("illegal rtp_id: %u", rtp_id);
        return -1;
    }
    return 0;
}

int lan9662_rte_ob_rtp_conf_get(struct lan9662_rte_inst   *inst,
                                uint16_t                  rtp_id,
                                lan9662_rte_ob_rtp_conf_t *const conf)
{
    T_I("enter");
    inst = lan9662_inst_get(inst);
    LAN9662_RC(lan9662_ob_rtp_check(rtp_id));
    *conf = inst->ob.rtp_tbl[rtp_id].conf;
    return 0;
}

int lan9662_rte_ob_rtp_conf_set(struct lan9662_rte_inst        *inst,
                                uint16_t                        rtp_id,
                                const lan9662_rte_ob_rtp_conf_t *const conf)
{
    uint32_t type = (conf->type == LAN9662_RTE_OB_RTP_TYPE_OPC_UA ? 1 : 0);
    uint32_t ena = (conf->type == LAN9662_RTE_OB_RTP_TYPE_DISABLED ? 0 : 1);

    T_I("enter");
    inst = lan9662_inst_get(inst);
    LAN9662_RC(lan9662_ob_rtp_check(rtp_id));
    inst->ob.rtp_tbl[rtp_id].conf = *conf;
    REG_WR(RTE_OUTB_RTP_MISC(rtp_id),
           RTE_OUTB_RTP_MISC_RTP_GRP_ID(0) |
           RTE_OUTB_RTP_MISC_PDU_TYPE(type) |
           RTE_OUTB_RTP_MISC_RTP_ENA(ena) |
           RTE_OUTB_RTP_MISC_RTP_GRP_STATE_STOPPED_MODE(0) |
           RTE_OUTB_RTP_MISC_DG_DATA_CP_ENA(1) |
           RTE_OUTB_RTP_MISC_WR_ACTION_ADDR(0));
    return 0;
}

int lan9662_rte_ob_rtp_pdu2dg_init(lan9662_rte_ob_rtp_pdu2dg_conf_t *conf)
{
    memset(conf, 0, sizeof(*conf));
    return 0;
}

int lan9662_rte_ob_rtp_pdu2dg_add(struct lan9662_rte_inst                *inst,
                                  uint16_t                               rtp_id,
                                  const lan9662_rte_ob_rtp_pdu2dg_conf_t *conf)
{
    lan9662_rte_ob_t           *ob;
    lan9662_rte_ob_dg_entry_t  *dg, *prev;
    lan9662_rte_ob_rtp_entry_t *rtp;
    uint16_t                   i, addr, new = 0, prev_addr;

    T_I("enter");
    inst = lan9662_inst_get(inst);
    LAN9662_RC(lan9662_ob_rtp_check(rtp_id));

    // Find free DG entry
    ob = &inst->ob;
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
        if (dg->conf.pdu_offset == conf->pdu_offset) {
            // Same PDU offset found
            T_E("rtp_id %u already has PDU offset %u", rtp_id, conf->pdu_offset);
            return -1;
        } else if (dg->conf.pdu_offset > conf->pdu_offset) {
            // Greater PDU offset found
            break;
        } else {
            // Smaller PDU offset found
            prev = dg;
            addr = dg->addr;
        }
    }

    dg = &ob->dg_tbl[new];
    dg->conf = *conf;
    dg->rtp_id = rtp_id;
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
               RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_SECTION_ADDR(dg->conf.dg_addr) |
               RTE_OUTB_DG_DATA_SECTION_ADDR_DG_DATA_LEN(dg->conf.length));
        addr = dg->addr;
    }
    return 0;
}

int lan9662_rte_ob_rtp_pdu2dg_clr(struct lan9662_rte_inst *inst,
                                  uint16_t                rtp_id)
{
    return 0;
}

int lan9662_ob_debug_print(struct lan9662_rte_inst *inst,
                           const lan9662_debug_printf_t pr,
                           const lan9662_debug_info_t   *const info)
{
    lan9662_rte_ob_t           *ob = &inst->ob;
    lan9662_rte_ob_rtp_entry_t *rtp;
    lan9662_rte_ob_dg_entry_t  *dg;
    const char                 *txt;
    uint32_t                   value;
    uint16_t                   i, j, addr;
    char                       buf[32];

    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        rtp = &ob->rtp_tbl[i];
        addr = rtp->addr;
        switch (rtp->conf.type) {
        case LAN9662_RTE_OB_RTP_TYPE_PN:
            txt = "Profinet";
            break;
        case LAN9662_RTE_OB_RTP_TYPE_OPC_UA:
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
                pr("\n  Addr  PDU   DG_Addr  Length\n");
            }
            pr("  %-6u%-6u%-9u%u\n",
               addr, dg->conf.pdu_offset, dg->conf.dg_addr, dg->conf.length);
            addr = dg->addr;
        }
        pr("\n");
    }

    lan9662_debug_print_reg_header(pr, "RTE Outbound");
    lan9662_debug_reg(inst, pr, REG_ADDR(RTE_OUTB_CFG), "OUTB_CFG");
    pr("\n");

    for (i = 1; i < RTE_OB_RTP_CNT; i++) {
        REG_RD(RTE_OUTB_RTP_MISC(i), &value);
        if (RTE_OUTB_RTP_MISC_RTP_ENA_X(value) == 0 && !info->full) {
            continue;
        }
        sprintf(buf, "OUTB_RTP_TBL_%u", i);
        lan9662_debug_print_reg_header(pr, buf);
        lan9662_debug_reg(inst, pr, REG_ADDR(RTE_OUTB_RTP_MISC(i)), "MISC");
        for (j = 0; j < 3; j++) {
            lan9662_debug_reg_inst(inst, pr,
                                   REG_ADDR(RTE_OUTB_DG_ADDR(i, j)), j, "DG_ADDR");
        }
        lan9662_debug_reg(inst, pr, REG_ADDR(RTE_OUTB_PDU_RECV_CNT(i)), "PDU_RECV_CNT");
        pr("\n");
    }

    for (i = 1; i < RTE_OB_DG_CNT; i++) {
        REG_RD(RTE_OUTB_DG_DATA_OFFSET_PDU_POS(i), &value);
        value = RTE_OUTB_DG_DATA_OFFSET_PDU_POS_DG_DATA_OFFSET_PDU_POS_X(value);
        if (value == 0 && !info->full) {
            continue;
        }
        sprintf(buf, "OUTB_DG_TBL_%u", i);
        lan9662_debug_print_reg_header(pr, buf);
        lan9662_debug_reg(inst, pr, REG_ADDR(RTE_OUTB_DG_MISC(i)), "MISC");
        lan9662_debug_reg(inst, pr, REG_ADDR(RTE_OUTB_DG_DATA_OFFSET_PDU_POS(i)),
                          "PDU_POS");
        lan9662_debug_reg(inst, pr, REG_ADDR(RTE_OUTB_DG_DATA_SECTION_ADDR(i)),
                          "DATA_SECTION_ADDR");
        pr("\n");
    }
    return 0;
}
