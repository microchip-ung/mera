// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#ifndef _MERA_PRIVATE_H_
#define _MERA_PRIVATE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lan9662/rte.h>

#define VTSS_BIT(x)                   (1U << (x))
#define VTSS_BITMASK(x)               ((1U << (x)) - 1)
#define VTSS_EXTRACT_BITFIELD(x,o,w)  (((x) >> (o)) & VTSS_BITMASK(w))
#define VTSS_ENCODE_BITFIELD(x,o,w)   (((x) & VTSS_BITMASK(w)) << (o))
#define VTSS_ENCODE_BITMASK(o,w)      (VTSS_BITMASK(w) << (o))

#if __INTPTR_MAX__ == __INT32_MAX__
#if !defined(PRIu64)
#define PRIu64 "llu"
#endif
#elif __INTPTR_MAX__ == __INT64_MAX__
#if !defined(PRIu64)
#define PRIu64 "lu"
#endif
#else
#error "Environment not 32 or 64-bit."
#endif

#if 1
#include "lan9662_regs_sr.h"
#else
#include "lan9662_regs.h"
#endif

#define MERA_RC(expr) { int __rc__ = (expr); if (__rc__ < 0) return __rc__; }

// RTE general state
typedef struct {
    mera_gen_conf_t conf;
} mera_gen_t;

// One more entry for direct 1-based indexing
#define RTE_RTP_CNT    (MERA_RTP_CNT + 1)
#define RTE_OB_RTP_CNT RTE_RTP_CNT
#define RTE_OB_DG_CNT  RTE_RTP_CNT
#if defined(MERA_FPGA)
#define RTE_OB_WA_CNT  36
#define RTE_IB_RA_CNT  36
#else
#define RTE_OB_WA_CNT  577
#define RTE_IB_RA_CNT  577
#endif
#define RTE_IB_RTP_CNT RTE_RTP_CNT
#define RTE_IB_DG_CNT  RTE_RTP_CNT

// Size of one DG section in 4-byte chunks
#if defined(MERA_FPGA)
#define RTE_OB_DG_SEC_SIZE 64
#else
#define RTE_OB_DG_SEC_SIZE 1024
#endif

// Number of RTPs to poll every second to avoid multiple wrap arounds of 16-bit counters.
// Minimum cycle time is 200 usec, giving 5000 pps, or 13 seconds to wrap.
#define RTE_POLL_CNT   (RTE_RTP_CNT / 13)

// Convert time in nsec to RUT (50 nsec)
#define MERA_RUT_TIME(t_nsec) ((t_nsec) / 50)

// Block size of triple buffer system
#define RTE_BUF3_SIZE (42 * 1024)

typedef struct {
    uint16_t prev;  // Previous value
    uint64_t value; // Accumulated value (64 bits)
} mera_counter_t;

// RTP OB entry
typedef struct {
    mera_ob_rtp_conf_t conf; // Configuration
    uint16_t           addr; // First address
    mera_counter_t     rx_0; // Rx_0 counter
    mera_counter_t     rx_1; // Rx_1 counter
} mera_ob_rtp_entry_t;

// DG entry
typedef struct {
    mera_ob_dg_conf_t conf;    // Configuration
    mera_rtp_id_t     rtp_id;  // Zero indicates free entry
    uint16_t          addr;    // Next address
    uint16_t          dg_addr; // Allocated DG address
} mera_ob_dg_entry_t;

// WAL entry
typedef struct {
    mera_ob_wal_conf_t conf; // Configuration
    uint16_t           addr; // First WA address
} mera_ob_wal_entry_t;

// WA entry
typedef struct {
    mera_bool_t       used; // Used indication
    uint16_t          addr; // Next address
    mera_ob_wa_conf_t conf; // Configuration
} mera_ob_wa_entry_t;

// RTE OB state
typedef struct {
    mera_rtp_id_t       rtp_id;  // Counter polling
    uint16_t            dg_addr; // Next free DG address
    mera_ob_rtp_entry_t rtp_tbl[RTE_OB_RTP_CNT];
    mera_ob_dg_entry_t  dg_tbl[RTE_OB_DG_CNT];
    mera_ob_wa_entry_t  wa_tbl[RTE_OB_WA_CNT];
    mera_ob_wal_entry_t wal_tbl[MERA_OB_WAL_CNT];
} mera_ob_t;

// RTP IB entry
typedef struct {
    mera_ib_rtp_conf_t conf;          // Configuration
    uint32_t           frm_data_addr; // Allocated frame data address
    mera_counter_t     tx_inj;        // Tx injection counter
    mera_counter_t     tx_otf;        // Tx on the fly counter
} mera_ib_rtp_entry_t;

// RAL entry
typedef struct {
    mera_ib_ral_conf_t conf; // Configuration
    uint16_t           addr; // First RA address
} mera_ib_ral_entry_t;

// RA entry
typedef struct {
    mera_bool_t       used;    // Used indication
    uint16_t          addr;    // Next RA address
    uint16_t          dg_addr; // First DG address
    uint16_t          dg_cnt;  // Number of DG entries
    mera_ib_ra_conf_t conf;    // Configuration
} mera_ib_ra_entry_t;

// DG entry
typedef struct {
    mera_ib_dg_conf_t conf; // Configuration
    uint16_t          addr; // Next DG address
} mera_ib_dg_entry_t;

// RTE IB state
typedef struct {
    mera_rtp_id_t       rtp_id;        // Counter polling
    uint32_t            frm_data_addr; // Next free frame data address
    mera_ib_rtp_entry_t rtp_tbl[RTE_IB_RTP_CNT];
    mera_ib_ra_entry_t  ra_tbl[RTE_IB_RA_CNT];
    mera_ib_ral_entry_t ral_tbl[MERA_IB_RAL_CNT];
    mera_ib_dg_entry_t  dg_tbl[RTE_IB_DG_CNT];
} mera_ib_t;

// RTE state
typedef struct mera_inst {
    mera_cb_t  cb;
    mera_gen_t gen;
    mera_ob_t  ob;
    mera_ib_t  ib;
} mera_inst_t;

struct mera_inst *mera_inst_get(struct mera_inst *inst);

int mera_rtp_check(const mera_rtp_id_t rtp_id);
void mera_cnt_16_update(uint16_t value, mera_counter_t *counter, int clear);

int mera_ib_init(struct mera_inst *inst);
int mera_ob_init(struct mera_inst *inst);
int mera_ib_poll(struct mera_inst *inst);
int mera_ob_poll(struct mera_inst *inst);
uint32_t mera_addr_get(const mera_addr_t *addr);
uint32_t mera_addr_offset(const mera_addr_t *addr);
char *mera_addr_txt(char *buf, mera_addr_t *addr);

/* ================================================================= *
 *  Register access
 * ================================================================= */
int mera_wr(struct mera_inst *inst, uint32_t addr, uint32_t val);
int mera_rd(struct mera_inst *inst, uint32_t addr, uint32_t *val);
int mera_wrm(struct mera_inst *inst, uint32_t reg, uint32_t val, uint32_t mask);
void mera_reg_error(const char *file, int line);

inline uint32_t mera_target_id_to_addr(int target_id)
{
    return (target_id == TARGET_GCB ? LAN966X_TARGET_GCB_OFFSET :
            target_id == TARGET_RTE ? LAN966X_TARGET_RTE_OFFSET : 0xffffffff);
}

inline uint32_t __ioreg(const char *file, int line, int tbaseid, int tinst, int tcnt,
                        int gbase, int ginst, int gcnt, int gwidth,
                        int raddr, int rinst, int rcnt, int rwidth)
{
    uint32_t addr = mera_target_id_to_addr(tbaseid + tinst);

    if (addr == 0xffffffff || tinst >= tcnt ||
        ginst >= gcnt || rinst >= rcnt) {
        mera_reg_error(file, line);
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
        int __rc = mera_rd(inst, o, val);                                 \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WR(...) REG_WR_(__VA_ARGS__)
#define REG_WR_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,            \
                raddr, rinst, rcnt, rwidth, val)                             \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = mera_wr(inst, o, val);                                 \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WRM(...) REG_WRM_(__VA_ARGS__)
#define REG_WRM_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,           \
                 raddr, rinst, rcnt, rwidth, val, msk)                       \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = mera_wrm(inst, o, val, msk);                           \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WRM_SET(...) REG_WRM_SET_(__VA_ARGS__)
#define REG_WRM_SET_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,       \
                     raddr, rinst, rcnt, rwidth, msk)                        \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = mera_wrm(inst, o, msk, msk);                           \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WRM_CLR(...) REG_WRM_CLR_(__VA_ARGS__)
#define REG_WRM_CLR_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,       \
                     raddr, rinst, rcnt, rwidth, msk)                        \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = mera_wrm(inst, o, 0, msk);                             \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

#define REG_WRM_CTL(...) REG_WRM_CTL_(__VA_ARGS__)
#define REG_WRM_CTL_(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth,       \
                     raddr, rinst, rcnt, rwidth, _cond_, msk)                \
    do {                                                                     \
        uint32_t o = IOREG(tbaseid, tinst, tcnt, gbase, ginst, gcnt, gwidth, \
                           raddr, rinst, rcnt, rwidth);                      \
        int __rc = mera_wrm(inst, o, (_cond_) ? (msk) : 0, msk);          \
        if (__rc != 0)                                                       \
            return __rc;                                                     \
    } while (0)

/* ================================================================= *
 *  Trace
 * ================================================================= */

extern mera_trace_conf_t mera_trace_conf[];

// Default trace group
#ifndef MERA_TRACE_GROUP
#define MERA_TRACE_GROUP MERA_TRACE_GROUP_DEFAULT
#endif

#define T_E(...) T_EG(MERA_TRACE_GROUP, ##__VA_ARGS__)
#define T_I(...) T_IG(MERA_TRACE_GROUP, ##__VA_ARGS__)
#define T_D(...) T_DG(MERA_TRACE_GROUP, ##__VA_ARGS__)
#define T_N(...) T_NG(MERA_TRACE_GROUP, ##__VA_ARGS__)

#define T_E_HEX(_byte_p, _byte_cnt) T_EG_HEX(MERA_TRACE_GROUP, _byte_p, _byte_cnt)
#define T_I_HEX(_byte_p, _byte_cnt) T_IG_HEX(MERA_TRACE_GROUP, _byte_p, _byte_cnt)
#define T_D_HEX(_byte_p, _byte_cnt) T_DG_HEX(MERA_TRACE_GROUP, _byte_p, _byte_cnt)
#define T_N_HEX(_byte_p, _byte_cnt) T_NG_HEX(MERA_TRACE_GROUP, _byte_p, _byte_cnt)

#define MERA_T(_grp, _lvl, ...) { if (mera_trace_conf[_grp].level >= _lvl) mera_callout_trace_printf(_grp, _lvl, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); }
#define T_EG(_grp, ...) MERA_T(_grp, MERA_TRACE_LEVEL_ERROR, __VA_ARGS__)
#define T_IG(_grp, ...) MERA_T(_grp, MERA_TRACE_LEVEL_INFO,  __VA_ARGS__)
#define T_DG(_grp, ...) MERA_T(_grp, MERA_TRACE_LEVEL_DEBUG, __VA_ARGS__)
#define T_NG(_grp, ...) MERA_T(_grp, MERA_TRACE_LEVEL_NOISE, __VA_ARGS__)

#define MERA_HEX(_grp, _lvl, _byte_p, _byte_cnt) { if (mera_trace_conf[_grp].level >= _lvl) mera_callout_trace_hex_dump(_grp, _lvl, __FILE__, __LINE__, __FUNCTION__, _byte_p, _byte_cnt); }
#define T_EG_HEX(_grp, _byte_p, _byte_cnt) MERA_HEX(_grp, MERA_TRACE_LEVEL_ERROR, _byte_p, _byte_cnt)
#define T_IG_HEX(_grp, _byte_p, _byte_cnt) MERA_HEX(_grp, MERA_TRACE_LEVEL_INFO,  _byte_p, _byte_cnt)
#define T_DG_HEX(_grp, _byte_p, _byte_cnt) MERA_HEX(_grp, MERA_TRACE_LEVEL_DEBUG, _byte_p, _byte_cnt)
#define T_NG_HEX(_grp, _byte_p, _byte_cnt) MERA_HEX(_grp, MERA_TRACE_LEVEL_NOISE, _byte_p, _byte_cnt)

/* ================================================================= *
 *  Debug print
 * ================================================================= */

void mera_debug_print_header(const mera_debug_printf_t pr,
                             const char                *header);
void mera_debug_print_reg_header(const mera_debug_printf_t pr, const char *name);
void mera_debug_print_reg(const mera_debug_printf_t pr, const char *name, uint32_t value);
void mera_debug_print_reg_mask(const mera_debug_printf_t pr, const char *name, uint32_t value, uint32_t mask);
void mera_debug_reg(struct mera_inst *inst,
                    const mera_debug_printf_t pr, uint32_t addr, const char *name);
void mera_debug_reg_inst(struct mera_inst *inst,
                         const mera_debug_printf_t pr,
                         uint32_t addr, uint32_t i, const char *name);
int mera_ib_debug_print(struct mera_inst *inst,
                        const mera_debug_printf_t pr,
                        const mera_debug_info_t   *const info);
int mera_ob_debug_print(struct mera_inst *inst,
                        const mera_debug_printf_t pr,
                        const mera_debug_info_t   *const info);

#define DBG_REG(addr, name) mera_debug_reg(inst, pr, addr, name)
#define DBG_REG_I(addr, i, name) mera_debug_reg_inst(inst, pr, addr, i, name)
#define DBG_PR_REG(name, value) mera_debug_print_reg(pr, name, value)
#define DBG_PR_REG_M(name, fld, value) mera_debug_print_reg_mask(pr, name, fld##_X(value), fld##_M);

#endif // _MERA_PRIVATE_H_

