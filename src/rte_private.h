// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#ifndef _LAN9662_RTE_PRIVATE_H_
#define _LAN9662_RTE_PRIVATE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lan9662/rte.h>

#define VTSS_BIT(x)                   (1U << (x))
#define VTSS_BITMASK(x)               ((1U << (x)) - 1)
#define VTSS_EXTRACT_BITFIELD(x,o,w)  (((x) >> (o)) & VTSS_BITMASK(w))
#define VTSS_ENCODE_BITFIELD(x,o,w)   (((x) & VTSS_BITMASK(w)) << (o))
#define VTSS_ENCODE_BITMASK(o,w)      (VTSS_BITMASK(w) << (o))

#if 1
#include "lan9662_regs_sr.h"
#else
#include "lan9662_regs.h"
#endif

#define LAN9662_RC(expr) { int __rc__ = (expr); if (__rc__ < 0) return __rc__; }

// RTE general state
typedef struct {
    lan9662_rte_gen_conf_t conf;
} lan9662_rte_gen_t;

// One more entry for direct 1-based indexing
#define RTE_RTP_CNT    (LAN9662_RTE_RTP_CNT + 1)
#define RTE_OB_RTP_CNT RTE_RTP_CNT
#define RTE_OB_DG_CNT  RTE_RTP_CNT
#define RTE_IB_RTP_CNT RTE_RTP_CNT

// Size of one DG section in 4-byte chunks
#define RTE_OB_DG_SEC_SIZE 64

// Number of RTPs to poll every second to avoid multiple wrap arounds of 16-bit counters.
// Minimum cycle time is 200 usec, giving 5000 pps, or 13 seconds to wrap.
#define RTE_POLL_CNT   (RTE_RTP_CNT / 13)

// Convert time in nsec to RUT (50 nsec)
#define LAN9662_RUT_TIME(t_nsec) ((t_nsec) / 50)

typedef struct {
    uint16_t prev;  // Previous value
    uint64_t value; // Accumulated value (64 bits)
} lan9662_rte_counter_t;

// RTP OB entry
typedef struct {
    lan9662_rte_ob_rtp_conf_t conf; // Configuration
    uint16_t                  addr; // First address
    lan9662_rte_counter_t     rx_0;
    lan9662_rte_counter_t     rx_1;
} lan9662_rte_ob_rtp_entry_t;

// DG entry
typedef struct {
    lan9662_rte_ob_rtp_pdu2dg_conf_t conf;   // Configuration
    uint16_t                         rtp_id; // Zero indicates free entry
    uint16_t                         addr;   // Next address
} lan9662_rte_ob_dg_entry_t;

// RTE OB state
typedef struct {
    uint16_t                   rtp_id;
    lan9662_rte_ob_rtp_entry_t rtp_tbl[RTE_OB_RTP_CNT];
    lan9662_rte_ob_dg_entry_t  dg_tbl[RTE_OB_DG_CNT];
} lan9662_rte_ob_t;

// RTP IB entry
typedef struct {
    lan9662_rte_ib_rtp_conf_t conf; // Configuration
    lan9662_rte_counter_t     tx_inj;
    lan9662_rte_counter_t     tx_otf;
} lan9662_rte_ib_rtp_entry_t;

// RTE IB state
typedef struct {
    uint16_t                   rtp_id;
    uint32_t                   frm_data_addr;
    lan9662_rte_ib_rtp_entry_t rtp_tbl[RTE_IB_RTP_CNT];
} lan9662_rte_ib_t;

// RTE state
typedef struct lan9662_rte_inst {
    lan9662_rte_cb_t  cb;
    lan9662_rte_gen_t gen;
    lan9662_rte_ob_t  ob;
    lan9662_rte_ib_t  ib;
} lan9662_rte_inst_t;

struct lan9662_rte_inst *lan9662_inst_get(struct lan9662_rte_inst *inst);

int lan9662_rte_rtp_check(uint16_t rtp_id);
void lan9662_rte_cnt_16_update(uint16_t value, lan9662_rte_counter_t *counter, int clear);


int lan9662_ib_init(struct lan9662_rte_inst *inst);
int lan9662_ob_init(struct lan9662_rte_inst *inst);
int lan9662_ib_poll(struct lan9662_rte_inst *inst);
int lan9662_ob_poll(struct lan9662_rte_inst *inst);

/* ================================================================= *
 *  Register access
 * ================================================================= */
int lan9662_wr(struct lan9662_rte_inst *inst, uint32_t addr, uint32_t val);
int lan9662_rd(struct lan9662_rte_inst *inst, uint32_t addr, uint32_t *val);
int lan9662_wrm(struct lan9662_rte_inst *inst, uint32_t reg, uint32_t val, uint32_t mask);
void lan9662_reg_error(const char *file, int line);

inline uint32_t lan9662_target_id_to_addr(int target_id)
{
    return (target_id == TARGET_GCB ? LAN966X_TARGET_GCB_OFFSET :
            target_id == TARGET_RTE ? LAN966X_TARGET_RTE_OFFSET : 0xffffffff);
}

inline uint32_t __ioreg(const char *file, int line, int tbaseid, int tinst, int tcnt,
                        int gbase, int ginst, int gcnt, int gwidth,
                        int raddr, int rinst, int rcnt, int rwidth)
{
    uint32_t addr = lan9662_target_id_to_addr(tbaseid + tinst);

    if (addr == 0xffffffff || tinst >= tcnt ||
        ginst >= gcnt || rinst >= rcnt) {
        lan9662_reg_error(file, line);
        return 0xffffffff;
    }

    return (addr +
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

void lan9662_debug_print_header(const lan9662_debug_printf_t pr,
                                const char                   *header);
void lan9662_debug_print_reg_header(const lan9662_debug_printf_t pr, const char *name);
void lan9662_debug_print_reg(const lan9662_debug_printf_t pr, const char *name, uint32_t value);
void lan9662_debug_reg(struct lan9662_rte_inst *inst,
                       const lan9662_debug_printf_t pr, uint32_t addr, const char *name);
void lan9662_debug_reg_inst(struct lan9662_rte_inst *inst,
                            const lan9662_debug_printf_t pr,
                            uint32_t addr, uint32_t i, const char *name);
int lan9662_ib_debug_print(struct lan9662_rte_inst *inst,
                           const lan9662_debug_printf_t pr,
                           const lan9662_debug_info_t   *const info);
int lan9662_ob_debug_print(struct lan9662_rte_inst *inst,
                           const lan9662_debug_printf_t pr,
                           const lan9662_debug_info_t   *const info);

#define DBG_REG(addr, name) lan9662_debug_reg(inst, pr, addr, name)
#define DBG_REG_I(addr, i, name) lan9662_debug_reg_inst(inst, pr, addr, i, name)
#define DBG_PR_REG(name, value) lan9662_debug_print_reg(pr, name, value)

#endif // _LAN9662_RTE_PRIVATE_H_

