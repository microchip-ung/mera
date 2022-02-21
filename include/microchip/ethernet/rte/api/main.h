// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#ifndef _MICROCHIP_ETHERNET_RTE_API_MAIN_H_
#define _MICROCHIP_ETHERNET_RTE_API_MAIN_H_

#include <stdint.h>
#include <stdarg.h>

typedef uint8_t mera_bool_t;

// Private type.
struct mera_inst;

// Register read callback
typedef int (*mera_reg_rd_t)(struct mera_inst *inst,
                             const uintptr_t  addr,
                             uint32_t         *data);

// Register write callback
typedef int (*mera_reg_wr_t)(struct mera_inst *inst,
                             const uintptr_t  addr,
                             const uint32_t   data);

// MERA lock structure
typedef struct {
    const char *function; // Function name
    const char *file;     // File name
    int        line;      // Line number
} mera_lock_t;

// MERA lock callback
typedef void (*mera_lock_cb_t)(const mera_lock_t *const lock);

// MERA unlock callback
typedef void (*mera_unlock_cb_t)(const mera_lock_t *const lock);

// Trace groups
typedef enum
{
    MERA_TRACE_GROUP_DEFAULT, // Default trace group
    MERA_TRACE_GROUP_IB,      // RTE inbound
    MERA_TRACE_GROUP_OB,      // RTE outbound

    MERA_TRACE_GROUP_CNT      // Number of trace groups
} mera_trace_group_t;

// Trace levels
typedef enum {
    MERA_TRACE_LEVEL_NONE,  // No trace
    MERA_TRACE_LEVEL_ERROR, // Error trace
    MERA_TRACE_LEVEL_INFO,  // Information trace
    MERA_TRACE_LEVEL_DEBUG, // Debug trace
    MERA_TRACE_LEVEL_NOISE, // More debug information

    MERA_TRACE_LEVEL_CNT    // Number of trace levels
} mera_trace_level_t;

// Trace callback function
//
// group [IN]     Trace group
// level [IN]     Trace level
// file [IN]      File name string
// line [IN]      Line number in file
// function [IN]  Function name string
// format [IN]    Print format string
typedef void (*mera_trace_printf_cb_t)(const mera_trace_group_t  group,
                                       const mera_trace_level_t  level,
                                       const char                *file,
                                       const int                 line,
                                       const char                *function,
                                       const char                *format,
                                       ...);

// Trace hex-dump callback function
//
// group [IN]     Trace group
// level [IN]     Trace level
// file [IN]      The file from where the trace were called.
// line [IN]      The line from where the trace were called.
// function [IN]  The function from where the trace were called.
// byte_p [IN]    Pointer to start of area to print
// byte_cnt [IN]  Number of bytes to print
typedef void (*mera_trace_hex_dump_cb_t)(const mera_trace_group_t group,
                                         const mera_trace_level_t level,
                                         const char               *file,
                                         const int                line,
                                         const char               *function,
                                         const uint8_t            *byte_p,
                                         const int                byte_cnt);

typedef struct {
    mera_reg_rd_t            reg_rd;         // Register read, mandatory
    mera_reg_wr_t            reg_wr;         // Register write, mandatory
    mera_lock_cb_t           lock;           // API lock, optional
    mera_unlock_cb_t         unlock;         // API unlock, optional
    mera_trace_printf_cb_t   trace_printf;   // Trace printf, optional
    mera_trace_hex_dump_cb_t trace_hex_dump; // Trace hex dump, optional
} mera_cb_t;

struct mera_inst *mera_create(const mera_cb_t *cb);

void mera_destroy(struct mera_inst *inst);

/* - RTE general --------------------------------------------------- */

// Poll statistics, call approximately every second
int mera_poll(struct mera_inst *inst);

// For indicating FPGA implementation
//#define MERA_FPGA 1

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

// Number of Inbound Read Action List IDs (0-based)
#define MERA_IB_RAL_CNT MERA_RTP_CNT

// Inbound Read Action List ID (0-based)
typedef uint16_t mera_ib_ral_id_t;

// RTP entry type
typedef enum {
    MERA_RTP_TYPE_DISABLED, // Disabled
    MERA_RTP_TYPE_PN,       // Profinet
    MERA_RTP_TYPE_OPC_UA,   // OPC-UA
} mera_rtp_type_t;

// Number of RTP group IDs
#define MERA_RTP_GRP_CNT (MERA_RTP_CNT / 2)

// RTP group ID, value zero means no group membership
typedef uint16_t mera_rtp_grp_id_t;

// RTE I/O interface
typedef enum {
    MERA_IO_INTF_QSPI,  // QSPI
    MERA_IO_INTF_PI,    // PI
    MERA_IO_INTF_SRAM,  // SRAM
    MERA_IO_INTF_PCIE,  // PCIe
} mera_io_intf_t;

typedef struct {
    mera_io_intf_t intf; // I/O interface
    uint32_t       addr; // Address for read/write access
} mera_addr_t;

// Triple buffer information
typedef struct {
    uint32_t addr; // Base address of requested buffer
} mera_buf_t;

// RTE time offset can be disbled using this value
#define MERA_TIME_OFFSET_NONE 1000000000

// RTE time
// The Super Cycle of the RTE is set to 256 msec, supporting various intervals.
// If the time base is 31.25 usec, the following intervals can be used:
// 31.25 usec
// 62.50 usec
// 125 usec
// 250 usec
// 500 usec
//   1 msec
//   2 msec
//   4 msec
//   8 msec
//  16 msec
//  32 msec
//  64 msec
// 128 msec
typedef struct {
    uint32_t offset;   // Offset from cycle start [nanoseconds]
    uint32_t interval; // Interval between timeouts [nanoseconds]
} mera_time_t;

// RTE events
typedef enum {
    MERA_EVENT_NONE              = 0,        // No event
    MERA_EVENT_RTP_STATE_STOPPED = (1 << 0), // RTP outbound state stopped
    MERA_EVENT_PN_DS_MISMATCH    = (1 << 1), // RTP outbound Profinet DataStatus mismatch
    MERA_EVENT_DG_INVALID        = (1 << 2), // RTP outbound DG invalid
} mera_event_t;

// Enable/disable interrupt generation for one or more events
int mera_event_enable(struct mera_inst   *inst,
                      const mera_event_t ev_mask,
                      const mera_bool_t  enable);

// Poll and clear events
int mera_event_poll(struct mera_inst *inst,
                    mera_event_t     *const ev_mask);

/* - RTE Outbound -------------------------------------------------- */

// RTP Outbound configuration
typedef struct {
    mera_rtp_type_t   type;        // RTP entry type
    mera_rtp_grp_id_t grp_id;      // RTP group ID
    uint16_t          length;      // Expected number of bytes after Etype, excluding FCS (zero disables length check)
    uint8_t           pn_ds;       // Profinet DataStatus, matched using mask 0xb7 (ignore bit 3 and 6)
    mera_bool_t       pn_discard;  // Discard if Profinet DataStatus mismatch
    uint32_t          opc_grp_ver; // OPC GroupVersion
    mera_bool_t       wal_enable;  // Trigger Write Action List
    mera_ob_wal_id_t  wal_id;      // Write Action List ID
    mera_time_t       time;        // Timer
    uint8_t           time_cnt;    // Timeout counter threshold
} mera_ob_rtp_conf_t;

// Get RTP Outbound configuration
int mera_ob_rtp_conf_get(struct mera_inst    *inst,
                         const mera_rtp_id_t rtp_id,
                         mera_ob_rtp_conf_t  *const conf);

// Set RTP Outbound configuration
int mera_ob_rtp_conf_set(struct mera_inst         *inst,
                         const mera_rtp_id_t      rtp_id,
                         const mera_ob_rtp_conf_t *const conf);

// RTP Outbound status
typedef struct {
    mera_bool_t pn_ds_chk; // Profinet DataStatus match check failed
    uint8_t     pn_ds;     // Profinet DataStatus value
} mera_ob_rtp_status_t;

// Get RTP Outbound status
int mera_ob_rtp_status_get(struct mera_inst     *inst,
                           const mera_rtp_id_t  rtp_id,
                           mera_ob_rtp_status_t *const status);

// RTP Outbound state
typedef struct {
    mera_bool_t active; // Active/stopped
} mera_ob_rtp_state_t;

// Get RTP Outbound state
int mera_ob_rtp_state_get(struct mera_inst    *inst,
                          const mera_rtp_id_t rtp_id,
                          mera_ob_rtp_state_t *const state);

// Set RTP Outbound state
int mera_ob_rtp_state_set(struct mera_inst          *inst,
                          const mera_rtp_id_t       rtp_id,
                          const mera_ob_rtp_state_t *const state);

// Get RTP Outbound group state
int mera_ob_rtp_grp_state_get(struct mera_inst        *inst,
                              const mera_rtp_grp_id_t grp_id,
                              mera_ob_rtp_state_t *const state);

// Set RTP Outbound group state
int mera_ob_rtp_grp_state_set(struct mera_inst          *inst,
                              const mera_rtp_grp_id_t   grp_id,
                              const mera_ob_rtp_state_t *const state);

// Outbound Data Group ID, must be unique for RTP
typedef uint16_t mera_ob_dg_id_t;

// Maximum size of data group
#define MERA_DATA_GROUP_CNT 1500

// Outbound Data Group configuration
typedef struct {
    mera_ob_dg_id_t dg_id;           // Data group ID
    uint16_t        pdu_offset;      // PDU offset after Ethernet Type
    uint16_t        length;          // Data length (copied from PDU offset)
    uint16_t        valid_offset;    // Offset after Ethernet Type to Profinet IOPS or OPC DataSetFlags1
    mera_bool_t     valid_chk;       // Profinet (IOPS bit 7) or OPC (DataSetFlags1 bit 0) valid check
    mera_bool_t     opc_seq_chk;     // OPC MessageSequenceNumber check
    mera_bool_t     opc_code_chk;    // OPC StatusCode/Severity check (must be zero)
    mera_bool_t     invalid_default; // Invalid data action: Write defaults (true) or last valid (false)
    uint8_t         data[MERA_DATA_GROUP_CNT]; // Default data
} mera_ob_dg_conf_t;

// Initalize Outbound DG configuration
int mera_ob_dg_init(mera_ob_dg_conf_t *const conf);

// Add Outbound DG configuration
int mera_ob_dg_add(struct mera_inst        *inst,
                   const mera_rtp_id_t     rtp_id,
                   const mera_ob_dg_conf_t *const conf);

// Outbound DG control
typedef struct {
    mera_bool_t enable; // Enable/disable copy of data to DG memory
} mera_ob_dg_ctrl_t;

// Set Outbound DG control
int mera_ob_dg_ctrl_set(struct mera_inst        *inst,
                        const mera_rtp_id_t     rtp_id,
                        const mera_ob_dg_id_t   dg_id,
                        const mera_ob_dg_ctrl_t *const ctrl);

// Outbound DG data
typedef struct {
    uint16_t offset; // Offset in allocated DG memory block
    uint8_t  value;  // Data value to write
} mera_ob_dg_data_t;

// Outbound DG data write
int mera_ob_dg_data_set(struct mera_inst        *inst,
                        const mera_rtp_id_t     rtp_id,
                        const mera_ob_dg_id_t   dg_id,
                        const mera_ob_dg_data_t *const data);

// Outbound DG status
typedef struct {
    mera_bool_t valid_chk;    // Valid check failed
    uint8_t     valid;        // Failed IOPS/DataSetFlags1
    mera_bool_t opc_code_chk; // OPC StatusCode/Severity check failed
    uint16_t    opc_code;     // Failed OPC StatusCode
} mera_ob_dg_status_t;

// Get and clear Outbound DG status
int mera_ob_dg_status_get(struct mera_inst      *inst,
                          const mera_rtp_id_t   rtp_id,
                          const mera_ob_dg_id_t dg_id,
                          mera_ob_dg_status_t   *const status);

// Outbound Write Action List configuration
typedef struct {
    mera_time_t time; // Timer control
} mera_ob_wal_conf_t;

// Get Outbound Write Action List configuration
int mera_ob_wal_conf_get(struct mera_inst       *inst,
                         const mera_ob_wal_id_t wal_id,
                         mera_ob_wal_conf_t     *const conf);

// Set Outbound Write Action List configuration
int mera_ob_wal_conf_set(struct mera_inst         *inst,
                         const mera_ob_wal_id_t   wal_id,
                         const mera_ob_wal_conf_t *const conf);

// Request Outbound Write Action List read buffer
int mera_ob_wal_req(struct mera_inst       *inst,
                    const mera_ob_wal_id_t wal_id,
                    mera_buf_t             *const buf);

// Release Outbound Write Action List read buffer
int mera_ob_wal_rel(struct mera_inst       *inst,
                    const mera_ob_wal_id_t wal_id);

// Outbound Write Action configuration
typedef struct {
    mera_bool_t       internal; // Internal data transfer or data group transfer
    mera_rtp_id_t     rtp_id;   // RTP ID (non-internal transfer)
    mera_rtp_grp_id_t grp_id;   // RTP group ID (non-internal transfer)
    mera_ob_dg_id_t   dg_id;    // Data group ID (non-internal transfer)
    mera_addr_t       rd_addr;  // Read address (internal transfer)
    uint16_t          length;   // Data length (internal transfer)
    mera_addr_t       wr_addr;  // Write address
} mera_ob_wa_conf_t;

// Initialize Write Action configuration
int mera_ob_wa_init(mera_ob_wa_conf_t *const conf);

// Add Write Action configuration
int mera_ob_wa_add(struct mera_inst        *inst,
                   const mera_ob_wal_id_t  wal_id,
                   const mera_ob_wa_conf_t *const conf);

// Flush all outbound configuration
int mera_ob_flush(struct mera_inst *inst);

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
    mera_rtp_grp_id_t  grp_id; // RTP group ID
    mera_rtp_ib_mode_t mode;   // Mode
    mera_time_t        time;   // Cycle time (INJ mode)
    uint16_t           port;   // Egress chip port (INJ mode)
    uint16_t           length; // Frame length (excluding IFH and FCS)
    uint8_t            data[MERA_FRAME_DATA_CNT];   // Frame data
    uint8_t            update[MERA_FRAME_DATA_CNT]; // Frame update, if non-zero (OTF mode)
} mera_ib_rtp_conf_t;

// Get RTP Inbound configuration
int mera_ib_rtp_conf_get(struct mera_inst    *inst,
                         const mera_rtp_id_t rtp_id,
                         mera_ib_rtp_conf_t  *const conf);

// Set RTP Inbound configuration
int mera_ib_rtp_conf_set(struct mera_inst         *inst,
                         const mera_rtp_id_t      rtp_id,
                         const mera_ib_rtp_conf_t *const conf);

// RTP Inbound data
typedef struct {
    uint16_t offset; // Offset in allocated frame memory block
    uint8_t  value;  // Data value to write
} mera_ib_rtp_data_t;

// RTP Inbound data write
int mera_ib_rtp_data_set(struct mera_inst         *inst,
                         const mera_rtp_id_t      rtp_id,
                         const mera_ib_rtp_data_t *const data);

// Inbound Read Action List configuration
typedef struct {
    mera_time_t time; // Timer control
} mera_ib_ral_conf_t;

// Get Inbound Read Action List configuration
int mera_ib_ral_conf_get(struct mera_inst       *inst,
                         const mera_ib_ral_id_t ral_id,
                         mera_ib_ral_conf_t     *const conf);

// Set Inbound Read Action List configuration
int mera_ib_ral_conf_set(struct mera_inst         *inst,
                         const mera_ib_ral_id_t   ral_id,
                         const mera_ib_ral_conf_t *const conf);

// Request Inbound Read Action List write buffer
int mera_ib_ral_req(struct mera_inst       *inst,
                    const mera_ib_ral_id_t ral_id,
                    mera_buf_t             *const buf);

// Release Inbound Read Action List write buffer
int mera_ib_ral_rel(struct mera_inst       *inst,
                    const mera_ib_ral_id_t ral_id);

// Intbound Read Action ID, must be unique for RAL
typedef uint16_t mera_ib_ra_id_t;

// Inbound Read Action configuration
typedef struct {
    mera_ib_ra_id_t ra_id;   // Read Action ID
    mera_addr_t     rd_addr; // Read address
    uint16_t        length;  // Data length
} mera_ib_ra_conf_t;

// Initialize Read Action configuration
int mera_ib_ra_init(mera_ib_ra_conf_t *const conf);

// Add Read Action configuration
int mera_ib_ra_add(struct mera_inst        *inst,
                   const mera_ib_ral_id_t  ral_id,
                   const mera_ib_ra_conf_t *const conf);

// Read Action control
typedef struct {
    mera_bool_t enable; // Enable/disable copy of data to frame memory
} mera_ib_ra_ctrl_t;

int mera_ib_ra_ctrl_set(struct mera_inst        *inst,
                        const mera_ib_ral_id_t  ral_id,
                        const mera_ib_ra_id_t   ra_id,
                        const mera_ib_ra_ctrl_t *const ctrl);

// Inbound Data Group configuration
typedef struct {
    mera_rtp_id_t   rtp_id;          // Inbound RTP
    uint16_t        pdu_offset;      // PDU offset after Ethernet Type
    uint16_t        valid_offset;    // Offset after Ethernet Type to Profinet IOPS or OPC DataSetFlags1
    mera_bool_t     valid_update;    // Update Profinet (IOPS bit 7) or OPC (DataSetFlags1 bit 0)
    mera_bool_t     opc_seq_update;  // OPC MessageSequenceNumber update
    mera_bool_t     opc_code_update; // OPC StatusCode/Severity update
} mera_ib_dg_conf_t;

// Initalize Inbound DG configuration
int mera_ib_dg_init(mera_ib_dg_conf_t *const conf);

// Add Inbound DG configuration
int mera_ib_dg_add(struct mera_inst        *inst,
                   const mera_ib_ral_id_t  ral_id,
                   const mera_ib_ra_id_t   ra_id,
                   const mera_ib_dg_conf_t *const conf);

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

// For debug print
#define MERA_TRACE_GROUP_ALL MERA_TRACE_GROUP_CNT

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
    mera_debug_group_t group;  // Debug group
    mera_rtp_id_t      rtp_id; // RTP ID (zero means all)
    mera_bool_t        full;   // Full information dump
    mera_bool_t        clear;  // Clear counters
} mera_debug_info_t;

#if defined(__GNUC__) && (__GNUC__ > 2)
#define MERA_ATTR_PRINTF(X, Y) __attribute__ ((format(printf,X,Y)))
#else
#define MERA_ATTR_PRINTF(X, Y)
#endif

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

#endif // _MICROCHIP_ETHERNET_RTE_API_MAIN_H_
