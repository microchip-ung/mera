// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#ifndef _MERA_RTE_H_
#define _MERA_RTE_H_

#include <stdint.h>
#include <stdarg.h>

typedef uint8_t mera_bool_t;

// Private type.
struct mera_inst;

typedef int (*mera_reg_rd_t)(struct mera_inst *inst,
                             const uintptr_t  addr,
                             uint32_t         *data);

typedef int (*mera_reg_wr_t)(struct mera_inst *inst,
                             const uintptr_t  addr,
                             const uint32_t   data);

typedef struct {
    mera_reg_rd_t reg_rd;
    mera_reg_wr_t reg_wr;
} mera_cb_t;

struct mera_inst *mera_create(const mera_cb_t *cb);

void mera_destroy(struct mera_inst *inst);

/* - RTE general --------------------------------------------------- */

// RTE general configuration
typedef struct {
    mera_bool_t enable; // Enable/disable RTE
} mera_gen_conf_t;

// Get RTE general configuration.
// conf [OUT]  RTE general configuration.
int mera_gen_conf_get(struct mera_inst *inst,
                      mera_gen_conf_t  *const conf);

// Set RTE general configuration.
// conf [IN]  RTE general configuration.
int mera_gen_conf_set(struct mera_inst      *inst,
                      const mera_gen_conf_t *const conf);


// Poll statistics, call approximately every second
int mera_poll(struct mera_inst *inst);

// Indicate FPGA implementation for now
#define MERA_FPGA 1

// Number RTP IDs (1-based)
#if defined(MERA_FPGA)
#define MERA_RTP_CNT 31
#else
#define MERA_RTP_CNT 512
#endif

// RTP ID (1-based)
typedef uint16_t mera_rtp_id_t;

// Number of Outbound Write Action List IDs (0-based)
#define MERA_OB_WAL_CNT MERA_RTP_CNT

// Outbound Write Action List ID (0-based)
typedef uint16_t mera_ob_wal_id_t;

// RTP entry type
typedef enum {
    MERA_RTP_TYPE_DISABLED, // Disabled
    MERA_RTP_TYPE_PN,       // Profinet
    MERA_RTP_TYPE_OPC_UA,   // OPC-UA
} mera_rtp_type_t;

/* - RTE Outbound -------------------------------------------------- */

// RTP Outbound configuration
typedef struct {
    mera_rtp_type_t  type;        // RTP entry type
    uint16_t         length;      // Number of bytes after Etype, excluding FCS (zero disables length check)
    uint8_t          pn_ds;       // Profinet DataStatus, matched using mask 0xb7 (ignore bit 3 and 6)
    uint32_t         opc_grp_ver; // OPC GroupVersion
    mera_bool_t      wal_enable;  // Trigger Write Action List
    mera_ob_wal_id_t wal_id;      // Write Action List ID
} mera_ob_rtp_conf_t;

// Get RTP Outbound configuration
int mera_ob_rtp_conf_get(struct mera_inst    *inst,
                         const mera_rtp_id_t rtp_id,
                         mera_ob_rtp_conf_t  *const conf);

// Set RTP Outbound configuration
int mera_ob_rtp_conf_set(struct mera_inst         *inst,
                         const mera_rtp_id_t      rtp_id,
                         const mera_ob_rtp_conf_t *const conf);

// Outbound data group ID, must be unique for RTP
typedef uint16_t mera_ob_dg_id_t;

// RTP PDU-to-DG configuration
typedef struct {
    mera_ob_dg_id_t id;         // Data group ID
    uint16_t        pdu_offset; // PDU offset after Ethernet Type
    uint16_t        length;     // Data length
} mera_ob_rtp_pdu2dg_conf_t;

// Initalize PDU-to-DG configuration
int mera_ob_rtp_pdu2dg_init(mera_ob_rtp_pdu2dg_conf_t *const conf);

// Add PDU-to-DG configuration
int mera_ob_rtp_pdu2dg_add(struct mera_inst                *inst,
                           const mera_rtp_id_t             rtp_id,
                           const mera_ob_rtp_pdu2dg_conf_t *const conf);

// Outbound Write Action List configuration
typedef struct {
    uint32_t time; // Time [nsec]
} mera_ob_wal_conf_t;

// Get Outbound Write Action List configuration
int mera_ob_wal_conf_get(struct mera_inst       *inst,
                         const mera_ob_wal_id_t wal_id,
                         mera_ob_wal_conf_t     *const conf);

// Set Outbound Write Action List configuration
int mera_ob_wal_conf_set(struct mera_inst         *inst,
                         const mera_ob_wal_id_t   wal_id,
                         const mera_ob_wal_conf_t *const conf);

// Outbound Write Action configuration
typedef struct {
    mera_bool_t     internal; // Internal data transfer or data group transfer
    mera_rtp_id_t   rtp_id;   // RTP ID (non-internal transfer)
    mera_ob_dg_id_t dg_id;    // Data group ID (non-internal transfer)
    uint32_t        rd_addr;  // Read address (internal transfer)
    uint16_t        length;   // Data length (internal transfer)
    uint32_t        wr_addr;  // Write address
} mera_ob_wa_conf_t;

// Initialize Write Action configuration
int mera_ob_wa_init(mera_ob_wa_conf_t *const conf);

// Add Write Action configuration
int mera_ob_wa_add(struct mera_inst        *inst,
                   const mera_ob_wal_id_t  wal_id,
                   const mera_ob_wa_conf_t *const conf);

// Flush all outbound configuration
int mera_ob_flush(struct mera_inst *inst);

// TODO: Once we can find the PDU data in the DG memory, then we need to
// continue and do the 3-buffer operation

// Outbound counters
typedef struct {
    uint64_t rx_0; // Received PDUs with sub_id zero
    uint64_t rx_1; // Received PDUs with sub_id one
} mera_ob_rtp_counters_t;

int mera_ob_rtp_counters_get(struct mera_inst       *inst,
                             const mera_rtp_id_t    rtp_id,
                             mera_ob_rtp_counters_t *const counters);

int mera_ob_rtp_counters_clr(struct mera_inst    *inst,
                             const mera_rtp_id_t rtp_id);

/* - RTE Inbound --------------------------------------------------- */

// Inbound mode
typedef enum {
    MERA_RTP_IB_MODE_INJ, // Frame injection
    MERA_RTP_IB_MODE_OTF, // On the fly frame processing
} mera_rtp_ib_mode_t;

// Maximum size of frame data
#define MERA_FRAME_DATA_CNT 1514

// RTP Inbound configuration
typedef struct {
    mera_rtp_type_t    type;   // Type
    mera_rtp_ib_mode_t mode;   // Mode
    uint32_t           time;   // Cycle time [nsec] (INJ mode)
    uint16_t           port;   // Egress chip port (INJ mode)
    uint16_t           length; // Frame length (excluding IFH and FCS)
    uint8_t            data[MERA_FRAME_DATA_CNT];   // Frame data
    uint8_t            update[MERA_FRAME_DATA_CNT]; // Frame update, if non-zero (OTF mode)
} mera_ib_rtp_conf_t;

// Get RTP Outbound configuration
int mera_ib_rtp_conf_get(struct mera_inst    *inst,
                         const mera_rtp_id_t rtp_id,
                         mera_ib_rtp_conf_t  *const conf);

// Set RTP Outbound configuration
int mera_ib_rtp_conf_set(struct mera_inst         *inst,
                         const mera_rtp_id_t      rtp_id,
                         const mera_ib_rtp_conf_t *const conf);

// Flush all inbound configuration
int mera_ib_flush(struct mera_inst *inst);

// Inbound counters
typedef struct {
    uint64_t tx_inj; // Tx injected frames
    uint64_t tx_otf; // Tx on the fly frames
} mera_ib_rtp_counters_t;

int mera_ib_rtp_counters_get(struct mera_inst       *inst,
                             const mera_rtp_id_t    rtp_id,
                             mera_ib_rtp_counters_t *const counters);

int mera_ib_rtp_counters_clr(struct mera_inst    *inst,
                             const mera_rtp_id_t rtp_id);

/* - Trace --------------------------------------------------------- */

// Trace groups
typedef enum
{
    MERA_TRACE_GROUP_DEFAULT, // Default trace group
    MERA_TRACE_GROUP_IB,      // RTE inbound
    MERA_TRACE_GROUP_OB,      // RTE outbound

    MERA_TRACE_GROUP_CNT      // Number of trace groups
} mera_trace_group_t;

// For debug print
#define MERA_TRACE_GROUP_ALL MERA_TRACE_GROUP_CNT

// Trace levels
typedef enum {
    MERA_TRACE_LEVEL_NONE,  // No trace
    MERA_TRACE_LEVEL_ERROR, // Error trace
    MERA_TRACE_LEVEL_INFO,  // Information trace
    MERA_TRACE_LEVEL_DEBUG, // Debug trace
    MERA_TRACE_LEVEL_NOISE, // More debug information

    MERA_TRACE_LEVEL_CNT    // Number of trace levels
} mera_trace_level_t;

// Trace group configuration
typedef struct
{
    mera_trace_level_t level; // Trace level
} mera_trace_conf_t;

// Get trace configuration
// group [IN]  Trace group
// conf [OUT]  Trace group configuration.
int mera_trace_conf_get(const mera_trace_group_t group,
                        mera_trace_conf_t        *const conf);


// Set trace configuration
// group [IN]  Trace group
// conf [IN]   Trace group configuration.
int mera_trace_conf_set(const mera_trace_group_t group,
                        const mera_trace_conf_t  *const conf);

#if defined(__GNUC__) && (__GNUC__ > 2)
#define MERA_ATTR_PRINTF(X, Y) __attribute__ ((format(printf,X,Y)))
#else
#define MERA_ATTR_PRINTF(X, Y)
#endif

// Trace callout function
//
// group [IN]     Trace group
// level [IN]     Trace level
// file [IN]      File name string
// line [IN]      Line number in file
// function [IN]  Function name string
// format [IN]    Print format string
void mera_callout_trace_printf(const mera_trace_group_t  group,
                               const mera_trace_level_t  level,
                               const char                *file,
                               const int                 line,
                               const char                *function,
                               const char                *format,
                               ...) MERA_ATTR_PRINTF(6, 7);

// Trace hex-dump callout function
//
// group [IN]     Trace group
// level [IN]     Trace level
// file [IN]      The file from where the trace were called.
// line [IN]      The line from where the trace were called.
// function [IN]  The function from where the trace were called.
// byte_p [IN]    Pointer to start of area to print
// byte_cnt [IN]  Number of bytes to print
void mera_callout_trace_hex_dump(const mera_trace_group_t group,
                                 const mera_trace_level_t level,
                                 const char               *file,
                                 const int                line,
                                 const char               *function,
                                 const uint8_t            *byte_p,
                                 const int                byte_cnt);

/* - Debug print --------------------------------------------------- */

// Debug groups
typedef enum
{
    MERA_DEBUG_GROUP_ALL, // All groups
    MERA_DEBUG_GROUP_GEN, // RTE general
    MERA_DEBUG_GROUP_IB,  // RTE inbound
    MERA_DEBUG_GROUP_OB,  // RTE outbound

    MERA_DEBUG_GROUP_CNT      // Number of trace groups
} mera_debug_group_t;

// Debug information structure
typedef struct {
    mera_debug_group_t group; // Debug group
    mera_bool_t        full;  // Full information dump
    mera_bool_t        clear; // Clear counters
} mera_debug_info_t;

// Debug printf function
// The signature is similar to that of printf(). However, the return value is
// not used anywhere within MERA.
typedef int (*mera_debug_printf_t)(const char *fmt, ...) MERA_ATTR_PRINTF(1, 2);

// Get default debug information structure
// info [OUT]  Debug information
int mera_debug_info_get(mera_debug_info_t *const info);

// Print default information
// prntf [IN]  Debug printf function.
// info [IN]   Debug information
int mera_debug_info_print(struct mera_inst          *inst,
                          const mera_debug_printf_t pr,
                          const mera_debug_info_t   *const info);

#endif // _MERA_RTE_H_
