// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#ifndef _LAN9662_RTE_RTE_H_
#define _LAN9662_RTE_RTE_H_

#include <stdint.h>
#include <stdarg.h>

typedef uint8_t lan9662_bool_t;

// Private type.
struct lan9662_rte_inst;

typedef int (*lan9662_rte_reg_rd_t)(struct lan9662_rte_inst *inst,
                                    const uintptr_t         addr,
                                    uint32_t                *data);

typedef int (*lan9662_rte_reg_wr_t)(struct lan9662_rte_inst *inst,
                                    const uintptr_t         addr,
                                    const uint32_t          data);

typedef struct {
    lan9662_rte_reg_rd_t reg_rd;
    lan9662_rte_reg_wr_t reg_wr;
} lan9662_rte_cb_t;

struct lan9662_rte_inst *lan9662_rte_create(const lan9662_rte_cb_t *cb);

void lan9662_rte_destroy(struct lan9662_rte_inst *inst);

/* - RTE general --------------------------------------------------- */

// RTE general configuration
typedef struct {
    lan9662_bool_t enable; // Enable/disable RTE
} lan9662_rte_gen_conf_t;

// Get RTE general configuration.
// conf [OUT]  RTE general configuration.
int lan9662_rte_gen_conf_get(struct lan9662_rte_inst *inst,
                             lan9662_rte_gen_conf_t  *const conf);

// Set RTE general configuration.
// conf [IN]  RTE general configuration.
int lan9662_rte_gen_conf_set(struct lan9662_rte_inst      *inst,
                             const lan9662_rte_gen_conf_t *const conf);


// Poll statistics, call approximately every second
int lan9662_rte_poll(struct lan9662_rte_inst *inst);

// Number of 1-based RTP IDs
#define LAN9662_RTE_RTP_CNT 31

// RTP entry type
typedef enum {
    LAN9662_RTP_TYPE_DISABLED, // Disabled
    LAN9662_RTP_TYPE_PN,       // Profinet
    LAN9662_RTP_TYPE_OPC_UA,   // OPC-UA
} lan9662_rtp_type_t;

/* - RTE Outbound -------------------------------------------------- */

// RTP Outbound configuration
typedef struct {
    lan9662_rtp_type_t type;        // RTP entry type
    uint16_t           length;      // Number of bytes after Etype, excluding FCS (zero disables length check)
    uint8_t            pn_ds;       // Profinet DataStatus, matched using mask 0x37
    uint32_t           opc_grp_ver; // OPC GroupVersion
} lan9662_rte_ob_rtp_conf_t;

// Get RTP Outbound configuration
int lan9662_rte_ob_rtp_conf_get(struct lan9662_rte_inst   *inst,
                                const uint16_t            rtp_id,
                                lan9662_rte_ob_rtp_conf_t *const conf);

// Set RTP Outbound configuration
int lan9662_rte_ob_rtp_conf_set(struct lan9662_rte_inst        *inst,
                                const uint16_t                 rtp_id,
                                const lan9662_rte_ob_rtp_conf_t *const conf);

// RTP PDU-to-DG configuration
typedef struct {
    uint32_t pdu_offset;
    uint32_t length;
    uint32_t dg_addr;
} lan9662_rte_ob_rtp_pdu2dg_conf_t;

// Initalize PDU-to-DG configuration
int lan9662_rte_ob_rtp_pdu2dg_init(lan9662_rte_ob_rtp_pdu2dg_conf_t *const conf);

// Add PDU-to-DG configuration
int lan9662_rte_ob_rtp_pdu2dg_add(struct lan9662_rte_inst                *inst,
                                  const uint16_t                         rtp_id,
                                  const lan9662_rte_ob_rtp_pdu2dg_conf_t *const conf);

// Clear all PDU-to-DG entries
int lan9662_rte_ob_rtp_pdu2dg_clr(struct lan9662_rte_inst *inst,
                                  const uint16_t          rtp_id);

// For debugging only. Notice that it is a 2-buffer system from pdu to dg,
// meaning that we need to use RTE:OUTB_DG_DATA_RTP_CTRL:OUTB_DG_DATA_RTP_CTRL
// to read the latest updated section, or just inject 2 frames to update both of
// them.
int lan9662_rte_ob_dg_data_get(struct lan9662_rte_inst      *inst,
                               uint32_t                      addr,
                               uint32_t                     *value);

int lan9662_rte_ob_dg_data_bulk_get(struct lan9662_rte_inst      *inst,
                                    uint32_t                      addr,
                                    uint32_t                      length,
                                    uint32_t                     *value);

// TODO: Once we can find the PDU data in the DG memory, then we need to
// continue and do the 3-buffer operation

// Outbound counters
typedef struct {
    uint64_t rx_0; // Received PDUs with sub_id zero
    uint64_t rx_1; // Received PDUs with sub_id one
} lan9662_rte_ob_rtp_counters_t;

int lan9662_rte_ob_rtp_counters_get(struct lan9662_rte_inst       *inst,
                                    const uint16_t                rtp_id,
                                    lan9662_rte_ob_rtp_counters_t *const counters);

int lan9662_rte_ob_rtp_counters_clr(struct lan9662_rte_inst *inst,
                                    const uint16_t          rtp_id);

/* - RTE Inbound --------------------------------------------------- */

// Inbound mode
typedef enum {
    LAN9662_RTP_IB_MODE_INJ, // Frame injection
    LAN9662_RTP_IB_MODE_OTF, // On the fly frame processing
} lan9662_rtp_ib_mode_t;

// Maximum size of frame data
#define LAN9662_FRAME_DATA_CNT 1514

// RTP Inbound configuration
typedef struct {
    lan9662_rtp_type_t    type;   // Type
    lan9662_rtp_ib_mode_t mode;   // Mode
    uint32_t              time;   // Cycle time [nsec] (INJ mode)
    uint16_t              port;   // Egress chip port (INJ mode)
    uint16_t              length; // Frame length (excluding IFH and FCS)
    uint8_t               data[LAN9662_FRAME_DATA_CNT];   // Frame data
    uint8_t               update[LAN9662_FRAME_DATA_CNT]; // Frame update, if non-zero (OTF mode)
} lan9662_rte_ib_rtp_conf_t;

// Get RTP Outbound configuration
int lan9662_rte_ib_rtp_conf_get(struct lan9662_rte_inst   *inst,
                                const uint16_t            rtp_id,
                                lan9662_rte_ib_rtp_conf_t *const conf);

// Set RTP Outbound configuration
int lan9662_rte_ib_rtp_conf_set(struct lan9662_rte_inst         *inst,
                                const uint16_t                  rtp_id,
                                const lan9662_rte_ib_rtp_conf_t *const conf);

// Inbound counters
typedef struct {
    uint64_t tx_inj; // Tx injected frames
    uint64_t tx_otf; // Tx on the fly frames
} lan9662_rte_ib_rtp_counters_t;

int lan9662_rte_ib_rtp_counters_get(struct lan9662_rte_inst       *inst,
                                    const uint16_t                rtp_id,
                                    lan9662_rte_ib_rtp_counters_t *const counters);

int lan9662_rte_ib_rtp_counters_clr(struct lan9662_rte_inst *inst,
                                    const uint16_t          rtp_id);

/* - Trace --------------------------------------------------------- */

// Trace groups
typedef enum
{
    LAN9662_TRACE_GROUP_DEFAULT, // Default trace group
    LAN9662_TRACE_GROUP_IB,      // RTE inbound
    LAN9662_TRACE_GROUP_OB,      // RTE outbound

    LAN9662_TRACE_GROUP_CNT      // Number of trace groups
} lan9662_trace_group_t;

// For debug print
#define LAN9662_TRACE_GROUP_ALL LAN9662_TRACE_GROUP_CNT

// Trace levels
typedef enum {
    LAN9662_TRACE_LEVEL_NONE,  // No trace
    LAN9662_TRACE_LEVEL_ERROR, // Error trace
    LAN9662_TRACE_LEVEL_INFO,  // Information trace
    LAN9662_TRACE_LEVEL_DEBUG, // Debug trace
    LAN9662_TRACE_LEVEL_NOISE, // More debug information

    LAN9662_TRACE_LEVEL_CNT    // Number of trace levels
} lan9662_trace_level_t;

// Trace group configuration
typedef struct
{
    lan9662_trace_level_t level; // Trace level
} lan9662_trace_conf_t;

// Get trace configuration
// group [IN]  Trace group
// conf [OUT]  Trace group configuration.
int lan9662_trace_conf_get(const lan9662_trace_group_t group,
                           lan9662_trace_conf_t        *const conf);


// Set trace configuration
// group [IN]  Trace group
// conf [IN]   Trace group configuration.
int lan9662_trace_conf_set(const lan9662_trace_group_t group,
                           const lan9662_trace_conf_t  *const conf);

#if defined(__GNUC__) && (__GNUC__ > 2)
#define LAN9662_ATTR_PRINTF(X, Y) __attribute__ ((format(printf,X,Y)))
#else
#define LAN9662_ATTR_PRINTF(X, Y)
#endif

// Trace callout function
//
// group [IN]     Trace group
// level [IN]     Trace level
// file [IN]      File name string
// line [IN]      Line number in file
// function [IN]  Function name string
// format [IN]    Print format string
void lan9662_callout_trace_printf(const lan9662_trace_group_t  group,
                                  const lan9662_trace_level_t  level,
                                  const char                *file,
                                  const int                 line,
                                  const char                *function,
                                  const char                *format,
                                  ...) LAN9662_ATTR_PRINTF(6, 7);

// Trace hex-dump callout function
//
// group [IN]     Trace group
// level [IN]     Trace level
// file [IN]      The file from where the trace were called.
// line [IN]      The line from where the trace were called.
// function [IN]  The function from where the trace were called.
// byte_p [IN]    Pointer to start of area to print
// byte_cnt [IN]  Number of bytes to print
void lan9662_callout_trace_hex_dump(const lan9662_trace_group_t group,
                                    const lan9662_trace_level_t level,
                                    const char               *file,
                                    const int                line,
                                    const char               *function,
                                    const uint8_t            *byte_p,
                                    const int                byte_cnt);

/* - Debug print --------------------------------------------------- */

// Debug groups
typedef enum
{
    LAN9662_DEBUG_GROUP_ALL, // All groups
    LAN9662_DEBUG_GROUP_GEN, // RTE general
    LAN9662_DEBUG_GROUP_IB,  // RTE inbound
    LAN9662_DEBUG_GROUP_OB,  // RTE outbound

    LAN9662_DEBUG_GROUP_CNT      // Number of trace groups
} lan9662_debug_group_t;

// Debug information structure
typedef struct {
    lan9662_debug_group_t group; // Debug group
    lan9662_bool_t        full;  // Full information dump
    lan9662_bool_t        clear; // Clear counters
} lan9662_debug_info_t;

// Debug printf function
// The signature is similar to that of printf(). However, the return value is
// not used anywhere within LAN9662.
typedef int (*lan9662_debug_printf_t)(const char *fmt, ...) LAN9662_ATTR_PRINTF(1, 2);

// Get default debug information structure
// info [OUT]  Debug information
int lan9662_debug_info_get(lan9662_debug_info_t *const info);

// Print default information
// prntf [IN]  Debug printf function.
// info [IN]   Debug information
int lan9662_debug_info_print(struct lan9662_rte_inst *inst,
                             const lan9662_debug_printf_t pr,
                             const lan9662_debug_info_t   *const info);

#endif // _LAN9662_RTE_RTE_H_
