// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#ifndef _LAN9662_RTE_PRIVATE_H_
#define _LAN9662_RTE_PRIVATE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lan9662/rte.h>
#include "lan9662_regs.h"

#define LAN9662_RC(expr) { int __rc__ = (expr); if (__rc__ < 0) return __rc__; }

typedef struct lan9662_rte_inst {
    lan9662_rte_cb_t cb;
} lan9662_rte_inst_t;

struct lan9662_rte_inst *lan9662_inst_get(struct lan9662_rte_inst *inst);

/* ================================================================= *
 *  Register access
 * ================================================================= */
int lan9662_wr(struct lan9662_rte_inst *inst, uint32_t addr, uint32_t val);
int lan9662_rd(struct lan9662_rte_inst *inst, uint32_t addr, uint32_t *val);
int lan9662_wrm(struct lan9662_rte_inst *inst, uint32_t reg, uint32_t val, uint32_t mask);
void lan9662_reg_error(const char *file, int line);

// TODO This should come from the CML file and go into the auto-generated header
#define LAN9662_TARGET_MAX 22
inline uint32_t lan9662_target_id_to_addr(int target_id)
{
    switch (target_id) {
        case  0: return 0x00300000;
        case  1: return 0x00280000;
        case  2: return 0x00100000;
        case  3: return 0x00110000;
        case  4: return 0x00120000;
        case  5: return 0x00130000;
        case  6: return 0x00140000;
        case  7: return 0x00150000;
        case  8: return 0x00160000;
        case  9: return 0x00170000;
        case 10: return 0x00070000;
        case 11: return 0x00ff0000;
        case 12: return 0x000a0000;
        case 13: return 0x00000000;
        case 14: return 0x00090000;
        case 15: return 0x00080000;
        case 16: return 0x00200000;
        case 17: return 0x00030000;
        case 18: return 0x00380000;
        case 19: return 0x00010000;
        case 20: return 0x00040000;
        case 21: return 0x00050000;
        case 22: return 0x00060000;
        default: return 0xffffffff;
    }
}
// End of hard-coded Adaro constants. //////////////////////////////////////////

inline uint32_t __ioreg(const char *file, int line, int tbaseid, int tinst, int tcnt,
                        int gbase, int ginst, int gcnt, int gwidth,
                        int raddr, int rinst, int rcnt, int rwidth)
{
    if (tbaseid + tinst > LAN9662_TARGET_MAX || tinst >= tcnt ||
        ginst >= gcnt || rinst >= rcnt) {
        lan9662_reg_error(file, line);
        return 0xffffffff;
    }

    return (lan9662_target_id_to_addr(tbaseid + tinst) +
            gbase + ((ginst) * gwidth) +
            raddr + ((rinst) * rwidth)) / 4;
}

#define IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,                \
              raddr, rinst, rcnt, rwidth)                                      \
        __ioreg(__FILE__, __LINE__, tbaseid, tinst, tcnt, gbase, ginst, gcnt,  \
                gwidth, raddr, rinst, rcnt, rwidth)

#define REG_ADDR(p) IOREG(p)

#define REG_RD(...) REG_RD_(__VA_ARGS__)
#define REG_RD_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,            \
                raddr, rinst, rcnt, rwidth, val)                             \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = lan9662_rd(inst, o, val);                                 \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WR(...) REG_WR_(__VA_ARGS__)
#define REG_WR_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,            \
                raddr, rinst, rcnt, rwidth, val)                             \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = lan9662_wr(inst, o, val);                                 \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WRM(...) REG_WRM_(__VA_ARGS__)
#define REG_WRM_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,           \
                 raddr, rinst, rcnt, rwidth, val, msk)                       \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = lan9662_wrm(inst, o, val, msk);                           \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WRM_SET(...) REG_WRM_SET_(__VA_ARGS__)
#define REG_WRM_SET_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,       \
                     raddr, rinst, rcnt, rwidth, msk)                        \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = lan9662_wrm(inst, o, msk, msk);                           \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WRM_CLR(...) REG_WRM_CLR_(__VA_ARGS__)
#define REG_WRM_CLR_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,       \
                     raddr, rinst, rcnt, rwidth, msk)                        \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = lan9662_wrm(inst, o, 0, msk);                             \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WRM_CTL(...) REG_WRM_CTL_(__VA_ARGS__)
#define REG_WRM_CTL_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,       \
                     raddr, rinst, rcnt, rwidth, _cond_, msk)                \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = lan9662_wrm(inst, o, (_cond_) ? (msk) : 0, msk);          \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

/* ================================================================= *
 *  Trace
 * ================================================================= */

extern lan9662_trace_conf_t lan9662_trace_conf[];

// Default trace group
#ifndef LAN9662_TRACE_GROUP
#define LAN9662_TRACE_GROUP LAN9662_TRACE_GROUP_DEFAULT
#endif

#define T_E(...) T_EG(LAN9662_TRACE_GROUP, ##__VA_ARGS__)
#define T_I(...) T_IG(LAN9662_TRACE_GROUP, ##__VA_ARGS__)
#define T_D(...) T_DG(LAN9662_TRACE_GROUP, ##__VA_ARGS__)
#define T_N(...) T_NG(LAN9662_TRACE_GROUP, ##__VA_ARGS__)

#define T_E_HEX(_byte_p, _byte_cnt) T_EG_HEX(LAN9662_TRACE_GROUP, _byte_p, _byte_cnt)
#define T_I_HEX(_byte_p, _byte_cnt) T_IG_HEX(LAN9662_TRACE_GROUP, _byte_p, _byte_cnt)
#define T_D_HEX(_byte_p, _byte_cnt) T_DG_HEX(LAN9662_TRACE_GROUP, _byte_p, _byte_cnt)
#define T_N_HEX(_byte_p, _byte_cnt) T_NG_HEX(LAN9662_TRACE_GROUP, _byte_p, _byte_cnt)

#define LAN9662_T(_grp, _lvl, ...) { if (lan9662_trace_conf[_grp].level >= _lvl) lan9662_callout_trace_printf(_grp, _lvl, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); }
#define T_EG(_grp, ...) LAN9662_T(_grp, LAN9662_TRACE_LEVEL_ERROR, __VA_ARGS__)
#define T_IG(_grp, ...) LAN9662_T(_grp, LAN9662_TRACE_LEVEL_INFO,  __VA_ARGS__)
#define T_DG(_grp, ...) LAN9662_T(_grp, LAN9662_TRACE_LEVEL_DEBUG, __VA_ARGS__)
#define T_NG(_grp, ...) LAN9662_T(_grp, LAN9662_TRACE_LEVEL_NOISE, __VA_ARGS__)

#define LAN9662_HEX(_grp, _lvl, _byte_p, _byte_cnt) { if (lan9662_trace_conf[_grp].level >= _lvl) lan9662_callout_trace_hex_dump(_grp, _lvl, __FILE__, __LINE__, __FUNCTION__, _byte_p, _byte_cnt); }
#define T_EG_HEX(_grp, _byte_p, _byte_cnt) LAN9662_HEX(_grp, LAN9662_TRACE_LEVEL_ERROR, _byte_p, _byte_cnt)
#define T_IG_HEX(_grp, _byte_p, _byte_cnt) LAN9662_HEX(_grp, LAN9662_TRACE_LEVEL_INFO,  _byte_p, _byte_cnt)
#define T_DG_HEX(_grp, _byte_p, _byte_cnt) LAN9662_HEX(_grp, LAN9662_TRACE_LEVEL_DEBUG, _byte_p, _byte_cnt)
#define T_NG_HEX(_grp, _byte_p, _byte_cnt) LAN9662_HEX(_grp, LAN9662_TRACE_LEVEL_NOISE, _byte_p, _byte_cnt)

/* ================================================================= *
 *  Debug print
 * ================================================================= */

void lan9662_debug_print_reg_header(const lan9662_debug_printf_t pr, const char *name);
void lan9662_debug_reg(struct lan9662_rte_inst *inst,
                       const lan9662_debug_printf_t pr, uint32_t addr, const char *name);
int lan9662_ib_debug_print(struct lan9662_rte_inst *inst,
                           const lan9662_debug_printf_t pr,
                           const lan9662_debug_info_t   *const info);
int lan9662_ob_debug_print(struct lan9662_rte_inst *inst,
                           const lan9662_debug_printf_t pr,
                           const lan9662_debug_info_t   *const info);

int lan9662_ib_init(struct lan9662_rte_inst *inst);
int lan9662_ob_init(struct lan9662_rte_inst *inst);

#endif // _LAN9662_RTE_PRIVATE_H_

