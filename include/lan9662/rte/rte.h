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
