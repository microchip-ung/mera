// Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <lan9662-rte-rpc.h>
#include "main.h"
#include "trace.h"
#include "cli.h"

static mscc_appl_trace_module_t trace_module = {
    .name = "json_rpc"
};

enum {
    TRACE_GROUP_DEFAULT,
    TRACE_GROUP_CNT
};

static mscc_appl_trace_group_t trace_groups[TRACE_GROUP_CNT] = {
    // TRACE_GROUP_DEFAULT
    {
        .name = "default",
        .level = LAN9662_TRACE_LEVEL_ERROR
    },
};

// Message format: 4 bytes length field followed by data
#define JSON_RPC_HDR_LEN 4

/* - Error handling ------------------------------------------------ */

int json_rpc_call(json_rpc_req_t *req, int rc)
{
    if (rc != 0) {
        sprintf(req->ptr, "RTE call error");
    }
    return rc;
}

static int json_rpc_obj_type_get(json_rpc_req_t *req, struct json_object *obj, const char *name, json_type type, json_object **obj_value)
{
    if (!json_object_object_get_ex(obj, name, obj_value)) {
        sprintf(req->ptr, "name '%s' not found", name);
        return -1;
    } else if (!json_object_is_type(*obj_value, type)) {
        sprintf(req->ptr, "name '%s' type mismatch", name);
        return -1;
    }
    return 0;
}

static int json_rpc_array_type_get(json_rpc_req_t *req, json_object *obj, int *idx, json_type type, json_object **obj_value)
{
    *obj_value = json_object_array_get_idx(obj, *idx);
    if (*obj_value == NULL) {
        sprintf(req->ptr, "array index '%u' not found", *idx);
        return -1;
    } else if (!json_object_is_type(*obj_value, type)) {
        sprintf(req->ptr, "array index '%u' type mismatch", *idx);
        return -1;
    }
    (*idx)++;
    return 0;
}

// Get any object from array
int json_rpc_get_idx_json_object(json_rpc_req_t *req, json_object *obj, int *idx, json_object **obj_value)
{
    *obj_value = json_object_array_get_idx(obj, *idx);
    if (*obj_value == NULL) {
        sprintf(req->ptr, "array index '%u' not found", *idx);
        return -1;
    }
    (*idx)++;
    return 0;
}

// Get any object from object
int json_rpc_get_name_json_object(json_rpc_req_t *req, json_object *obj, const char *name, json_object **obj_value)
{
    if (!json_object_object_get_ex(obj, name, obj_value)) {
        sprintf(req->ptr, "name '%s' not found", name);
        return -1;
    }
    return 0;
}

/* - Object -------------------------------------------------------- */

int json_rpc_new(json_rpc_req_t *req, json_object **obj)
{
    *obj = json_object_new_object();
    if (*obj == NULL) {
        sprintf(req->ptr, "new: out of memory");
        return -1;
    }
    return 0;
}

// Add to object
int json_rpc_add_name_json_object(json_rpc_req_t *req, json_object *obj, const char *name, json_object *obj_value)
{
    if (obj_value == NULL) {
        sprintf(req->ptr, "name '%s', out of memory", name);
        return -1;
    }
    json_object_object_add(obj, name, obj_value);
    return 0;
}

/* - Array --------------------------------------------------------- */

int json_rpc_array_new(json_rpc_req_t *req, json_object **obj)
{
    *obj = json_object_new_array();
    if (*obj == NULL) {
        sprintf(req->ptr, "new: out of memory");
        return -1;
    }
    return 0;
}

// Add to array
int json_rpc_add_json_array(json_rpc_req_t *req, json_object *obj, json_object *obj_value)
{
    json_object_array_add(obj, obj_value);
    return 0;
}

/* - NULL ---------------------------------------------------------- */

int json_rpc_add_json_null(json_rpc_req_t *req, json_object *obj)
{
    json_object_array_add(obj, NULL);
    return 0;
}

/* - String -------------------------------------------------------- */

// Get from array
int json_rpc_get_idx_json_string(json_rpc_req_t *req, json_object *obj, int *idx, const char **value)
{
    json_object *obj_value;

    JSON_RC(json_rpc_array_type_get(req, obj, idx, json_type_string, &obj_value));
    *value = json_object_get_string(obj_value);
    return 0;
}

// Get from object
int json_rpc_get_name_json_string(json_rpc_req_t *req, json_object *obj, const char *name, const char **value)
{
    json_object *obj_value;

    JSON_RC(json_rpc_obj_type_get(req, obj, name, json_type_string, &obj_value));
    *value = json_object_get_string(obj_value);
    return 0;
}

// Add to array
int json_rpc_add_json_string(json_rpc_req_t *req, json_object *obj, const char *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_string(value));
}

// Add to object
int json_rpc_add_name_json_string(json_rpc_req_t *req, json_object *obj, const char *name, const char *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_string(value));
}

/* - Integer ------------------------------------------------------- */

#define U8_MIN   0x00
#define U8_MAX   0xff
#define I8_MIN   0xffffffffffffff80   /* -127 */
#define I8_MAX   0x7f
#define U16_MIN  0x0000
#define U16_MAX  0xffff
#define I16_MIN  0xffffffffffff8000   /* -32768 */
#define I16_MAX  0x7fff
#define U32_MIN  0x00000000
#define U32_MAX  0xffffffff
#define I32_MIN  0xffffffff80000000   /* -2147483648 */
#define I32_MAX  0x7fffffff
#define U64_MIN  0x0000000000000000
#define U64_MAX  0x7fffffffffffffff
#define I64_MIN  0x8000000000000000   /* -9223372036854775808 */
#define I64_MAX  0x7fffffffffffffff

static int json_rpc_int_range_check(json_rpc_req_t *req, const char *name, json_object *obj, int64_t *value, int64_t min, int64_t max)
{
    *value = json_object_get_int64(obj);
    if (*value < min || *value > max) {
        sprintf(req->ptr, "%s: illegal value: %" PRIi64 ", legal range: [%" PRIi64 " ; %" PRIi64 "]", name, *value, min, max);
        return -1;
    }
    return 0;
}

static int json_rpc_int_get(json_rpc_req_t *req, json_object *obj, int64_t *value, int64_t min, int64_t max)
{
    return json_rpc_int_range_check(req, "raw", obj, value, min, max);
}

static int json_rpc_obj_int_get(json_rpc_req_t *req, json_object *obj, const char *name, int64_t *value, int64_t min, int64_t max)
{
    json_object *obj_value;

    JSON_RC(json_rpc_obj_type_get(req, obj, name, json_type_int, &obj_value));
    return json_rpc_int_range_check(req, name, obj_value, value, min, max);
}

static int json_rpc_array_int_get(json_rpc_req_t *req, json_object *obj, int *idx, int64_t *value, int64_t min, int64_t max)
{
    json_object *obj_value;
    char        name[32];

    JSON_RC(json_rpc_array_type_get(req, obj, idx, json_type_int, &obj_value));
    sprintf(name, "array index %u", *idx);
    return json_rpc_int_range_check(req, name, obj_value, value, min, max);
}

// Get from array
int json_rpc_get_idx_uint8_t(json_rpc_req_t *req, json_object *obj, int *idx, uint8_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_array_int_get(req, obj, idx, &val, U8_MIN, U8_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_idx_int8_t(json_rpc_req_t *req, json_object *obj, int *idx, int8_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_array_int_get(req, obj, idx, &val, I8_MIN, I8_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_idx_uint16_t(json_rpc_req_t *req, json_object *obj, int *idx, uint16_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_array_int_get(req, obj, idx, &val, U16_MIN, U16_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_idx_int16_t(json_rpc_req_t *req, json_object *obj, int *idx, int16_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_array_int_get(req, obj, idx, &val, I16_MIN, I16_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_idx_uint32_t(json_rpc_req_t *req, json_object *obj, int *idx, uint32_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_array_int_get(req, obj, idx, &val, U32_MIN, U32_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_idx_int32_t(json_rpc_req_t *req, json_object *obj, int *idx, int32_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_array_int_get(req, obj, idx, &val, I32_MIN, I32_MAX));
    *value = val;
    return 0;
}

int json_rpc_add_name_int(json_rpc_req_t *req, json_object *obj, const char *name, int *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_int(*value));
}

int json_rpc_add_int(json_rpc_req_t *req, json_object *obj, int *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_int(*value));
}

int json_rpc_get_idx_int(json_rpc_req_t *req, json_object *obj, int *idx, int *value)
{
    int64_t val;

    JSON_RC(json_rpc_array_int_get(req, obj, idx, &val, I32_MIN, I32_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_int(json_rpc_req_t *req, json_object *obj, int *value)
{
    int64_t val;

    JSON_RC(json_rpc_int_get(req, obj, &val, I32_MIN, I32_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_name_int(json_rpc_req_t *req, json_object *obj, const char *name, int *value)
{
    int64_t val;

    JSON_RC(json_rpc_obj_int_get(req, obj, name, &val, I32_MIN, I32_MAX));
    *value = val;
    return 0;
}


int json_rpc_get_idx_uint64_t(json_rpc_req_t *req, json_object *obj, int *idx, uint64_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_array_int_get(req, obj, idx, &val, U64_MIN, U64_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_idx_int64_t(json_rpc_req_t *req, json_object *obj, int *idx, int64_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_array_int_get(req, obj, idx, &val, I64_MIN, I64_MAX));
    *value = val;
    return 0;
}

// Get from object
int json_rpc_get_name_uint8_t(json_rpc_req_t *req, json_object *obj, const char *name, uint8_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_obj_int_get(req, obj, name, &val, U8_MIN, U8_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_name_int8_t(json_rpc_req_t *req, json_object *obj, const char *name, int8_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_obj_int_get(req, obj, name, &val, I8_MIN, I8_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_name_uint16_t(json_rpc_req_t *req, json_object *obj, const char *name, uint16_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_obj_int_get(req, obj, name, &val, U16_MIN, U16_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_name_int16_t(json_rpc_req_t *req, json_object *obj, const char *name, int16_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_obj_int_get(req, obj, name, &val, I16_MIN, I16_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_name_uint32_t(json_rpc_req_t *req, json_object *obj, const char *name, uint32_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_obj_int_get(req, obj, name, &val, U32_MIN, U32_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_name_int32_t(json_rpc_req_t *req, json_object *obj, const char *name, int32_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_obj_int_get(req, obj, name, &val, I32_MIN, I32_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_name_uint64_t(json_rpc_req_t *req, json_object *obj, const char *name, uint64_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_obj_int_get(req, obj, name, &val, U64_MIN, U64_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_name_int64_t(json_rpc_req_t *req, json_object *obj, const char *name, int64_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_obj_int_get(req, obj, name, &val, I64_MIN, I64_MAX));
    *value = val;
    return 0;
}

// Get from raw object
int json_rpc_get_uint8_t(json_rpc_req_t *req, json_object *obj, uint8_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_int_get(req, obj, &val, U8_MIN, U8_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_int8_t(json_rpc_req_t *req, json_object *obj, int8_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_int_get(req, obj, &val, I8_MIN, I8_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_uint16_t(json_rpc_req_t *req, json_object *obj, uint16_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_int_get(req, obj, &val, U16_MIN, U16_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_int16_t(json_rpc_req_t *req, json_object *obj, int16_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_int_get(req, obj, &val, I16_MIN, I16_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_uint32_t(json_rpc_req_t *req, json_object *obj, uint32_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_int_get(req, obj, &val, U32_MIN, U32_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_int32_t(json_rpc_req_t *req, json_object *obj, int32_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_int_get(req, obj, &val, I32_MIN, I32_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_uint64_t(json_rpc_req_t *req, json_object *obj, uint64_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_int_get(req, obj, &val, U64_MIN, U64_MAX));
    *value = val;
    return 0;
}

int json_rpc_get_int64_t(json_rpc_req_t *req, json_object *obj, int64_t *value)
{
    int64_t val;

    JSON_RC(json_rpc_int_get(req, obj, &val, I64_MIN, I64_MAX));
    *value = val;
    return 0;
}

// Add to array
int json_rpc_add_uint8_t(json_rpc_req_t *req, json_object *obj, uint8_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_int(*value));
}

int json_rpc_add_int8_t(json_rpc_req_t *req, json_object *obj, int8_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_int(*value));
}

int json_rpc_add_uint16_t(json_rpc_req_t *req, json_object *obj, uint16_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_int(*value));
}

int json_rpc_add_int16_t(json_rpc_req_t *req, json_object *obj, int16_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_int(*value));
}

int json_rpc_add_uint32_t(json_rpc_req_t *req, json_object *obj, uint32_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_int64(*value));
}

int json_rpc_add_int32_t(json_rpc_req_t *req, json_object *obj, int32_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_int(*value));
}

int json_rpc_add_uint64_t(json_rpc_req_t *req, json_object *obj, uint64_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_int64(*value));
}

int json_rpc_add_int64_t(json_rpc_req_t *req, json_object *obj, int64_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_int64(*value));
}

// Add to object
int json_rpc_add_name_uint8_t(json_rpc_req_t *req, json_object *obj, const char *name, uint8_t *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_int(*value));
}

int json_rpc_add_name_int8_t(json_rpc_req_t *req, json_object *obj, const char *name, int8_t *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_int(*value));
}

int json_rpc_add_name_uint16_t(json_rpc_req_t *req, json_object *obj, const char *name, uint16_t *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_int(*value));
}

int json_rpc_add_name_int16_t(json_rpc_req_t *req, json_object *obj, const char *name, int16_t *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_int(*value));
}

int json_rpc_add_name_uint32_t(json_rpc_req_t *req, json_object *obj, const char *name, uint32_t *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_int64(*value));
}

int json_rpc_add_name_int32_t(json_rpc_req_t *req, json_object *obj, const char *name, int32_t *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_int(*value));
}

int json_rpc_add_name_uint64_t(json_rpc_req_t *req, json_object *obj, const char *name, uint64_t *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_int64(*value));
}

int json_rpc_add_name_int64_t(json_rpc_req_t *req, json_object *obj, const char *name, int64_t *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_int64(*value));
}


/* - Boolean ------------------------------------------------------- */

// Get from array
int json_rpc_get_idx_lan9662_bool_t(json_rpc_req_t *req, json_object *obj, int *idx, lan9662_bool_t *value)
{
    json_object *obj_value;

    JSON_RC(json_rpc_array_type_get(req, obj, idx, json_type_boolean, &obj_value));
    *value = json_object_get_boolean(obj_value);
    return 0;
}

// Get from object
int json_rpc_get_name_lan9662_bool_t(json_rpc_req_t *req, json_object *obj, const char *name, lan9662_bool_t *value)
{
    json_object *obj_value;

    JSON_RC(json_rpc_obj_type_get(req, obj, name, json_type_boolean, &obj_value));
    *value = json_object_get_boolean(obj_value);
    return 0;
}

// Add to array
int json_rpc_add_lan9662_bool_t(json_rpc_req_t *req, json_object *obj, lan9662_bool_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_boolean(*value));
}

// Add to object
int json_rpc_add_name_lan9662_bool_t(json_rpc_req_t *req, json_object *obj, const char *name, lan9662_bool_t *value)
{
    return json_rpc_add_name_json_object(req, obj, name, json_object_new_boolean(*value));
}

/* - Static method table ------------------------------------------- */

static json_rpc_method_t json_rpc_static_table[] = {
    { NULL, NULL}
};
/* - JSON-RPC parser ----------------------------------------------- */

static int find_and_call_method(const char *method_name, json_rpc_req_t *req)
{
    int                 found = 0;
    json_rpc_method_t   *method;

    for (method = json_rpc_table; method->cb != NULL && !found; method++) {
        if (!strcmp(method->name, method_name)) {
            found = 1;
            method->cb(req);
        }
    }
    for (method = json_rpc_static_table; method->cb != NULL && !found; method++) {
        if (!strcmp(method->name, method_name)) {
            found = 1;
            method->cb(req);
        }
    }

    return (found);
}

static int json_cli(int argc, const char **argv)
{
    int found = 0;
    json_rpc_req_t req = {};
    const char *m_str = 0, *p_str = 0;
    json_object       *obj_result = 0;
    const char *reply;

    req.ptr = req.buf;

    obj_result = json_object_new_object();
    req.result = json_object_new_array();

    if (req.result == NULL || obj_result == NULL) {
        T_I("Alloc error");

        if (obj_result)
            json_object_put(obj_result);

        if (req.result)
            json_object_put(req.result);

        return -1;
    }

    if (argc != 3) {
        cli_printf("Usage: call <method> <params>");
        return -1;
    }

    m_str = argv[1];
    p_str = argv[2];

    req.params = json_tokener_parse(p_str);
    if (req.params == NULL) {
        snprintf(req.buf, 1024, "Could not parse parameters");
        req.error = 1;
        goto OUT;
    }

    found = find_and_call_method(m_str, &req);

    if (!found) {
        snprintf(req.buf, 1024, "Method not found");
        req.error = 1;
        goto OUT;
    }

OUT:
    if (req.error) {
        json_object_object_add(obj_result, "error",
                               json_object_new_string(req.buf));
        json_object_put(req.result);
        req.result = 0;
    } else {
        json_object_object_add(obj_result, "result", req.result);
        req.result = NULL;
    }

    reply = json_object_to_json_string(obj_result);

    cli_printf("%s\n", reply);

    json_object_put(obj_result);

    if (req.error) {
        return -1;
    } else {
        return 0;
    }
}

static cli_cmd_t cli_cmd_table[] = {
    {
        "call <method> <params>",
        "Call an API method using JSON syntax",
        0,
        0,
        json_cli,
    },
};

void mscc_appl_json_rpc_init(mscc_appl_init_t *init)
{
    int i;

    switch (init->cmd) {
    case MSCC_INIT_CMD_REG:
        mscc_appl_trace_register(&trace_module, trace_groups, TRACE_GROUP_CNT);
        break;

    case MSCC_INIT_CMD_INIT:
        for (i = 0; i < sizeof(cli_cmd_table)/sizeof(cli_cmd_t); i++) {
            mscc_appl_cli_cmd_reg(&cli_cmd_table[i]);
        }
        break;

    default:
        break;
    }
}
