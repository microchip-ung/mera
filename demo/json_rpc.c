// Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
//#include <rte-rpc.h>
#include "json_rpc.h"
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
int json_rpc_get_idx_mesa_bool_t(json_rpc_req_t *req, json_object *obj, int *idx, lan9662_bool_t *value)
{
    json_object *obj_value;

    JSON_RC(json_rpc_array_type_get(req, obj, idx, json_type_boolean, &obj_value));
    *value = json_object_get_boolean(obj_value);
    return 0;
}

// Get from object
int json_rpc_get_name_mesa_bool_t(json_rpc_req_t *req, json_object *obj, const char *name, lan9662_bool_t *value)
{
    json_object *obj_value;

    JSON_RC(json_rpc_obj_type_get(req, obj, name, json_type_boolean, &obj_value));
    *value = json_object_get_boolean(obj_value);
    return 0;
}

// Add to array
int json_rpc_add_mesa_bool_t(json_rpc_req_t *req, json_object *obj, lan9662_bool_t *value)
{
    return json_rpc_add_json_array(req, obj, json_object_new_boolean(*value));
}

// Add to object
int json_rpc_add_name_mesa_bool_t(json_rpc_req_t *req, json_object *obj, const char *name, lan9662_bool_t *value)
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

#if 0
    for (method = json_rpc_table; method->cb != NULL && !found; method++) {
        if (!strcmp(method->name, method_name)) {
            found = 1;
            method->cb(req);
        }
    }
#endif
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

static int json_rpc_parse(int fd, char *msg)
{
    json_object       *obj_req, *obj_rep, *obj_result, *obj_error, *obj_method, *obj_id;
    const char        *method_name, *reply;
    json_rpc_req_t    req = {};
    int               send_reply = 0, found = 0;
    uint32_t          len, *p;
    char              hdr[JSON_RPC_HDR_LEN];

    T_N("request: %s", msg);

    req.idx = 0;
    req.result = NULL;
    sprintf(req.buf, "internal error");
    if ((obj_req = json_tokener_parse(msg)) == NULL) {
        T_I("json_tokener_parse failed");
    } else if (!json_object_object_get_ex(obj_req, "method", &obj_method)) {
        T_I("method object not found");
    } else if (json_object_get_type(obj_method) != json_type_string) {
        T_I("method object not string");
    } else if (!json_object_object_get_ex(obj_req, "params", &req.params)) {
        T_I("params object not found");
    } else if (json_object_get_type(req.params) != json_type_array) {
        T_I("params object not array");
    } else if (!json_object_object_get_ex(obj_req, "id", &obj_id)) {
        T_I("id object not found");
    } else if ((req.result = json_object_new_array()) == NULL) {
        T_I("alloc reply object failed");
    } else {
        // Lookup and call method
        send_reply = 1;
        method_name = json_object_get_string(obj_method);
        req.ptr = req.buf;
        req.ptr += sprintf(req.ptr, "method '%s': ", method_name);

        found = find_and_call_method(method_name, &req);

        if (!found) {
            sprintf(req.ptr, "not found");
            req.error = 1;
        }
    }
    
    if (send_reply && (obj_rep = json_object_new_object()) != NULL) {
        if (req.error) {
            obj_result = NULL;
            obj_error = json_object_new_string(req.buf);
        } else {
            obj_result = req.result;
            req.result = NULL; // Ownership transferred to obj_rep below
            obj_error = NULL;
        }
        json_object_object_add(obj_rep, "result", obj_result);
        json_object_object_add(obj_rep, "error", obj_error);
        json_object_object_add(obj_rep, "id", json_object_get(obj_id));
        reply = json_object_to_json_string(obj_rep);
        len = strlen(reply);
        p = (uint32_t *)hdr;
        *p = htonl(len);
        T_I("reply length: %u", len);
        T_D("reply: %s", reply);
        if (write(fd, hdr, sizeof(hdr)) != sizeof(hdr) || 
            write(fd, reply, len) != len) {
            T_E("write error");
        }
        json_object_put(obj_rep);
    }

    // Free objects (the call ignores NULL object)
    json_object_put(obj_req);
    json_object_put(req.result);

    return 0;
}

typedef struct {
    int                fd;
    struct sockaddr_in addr;
    uint32_t           len;
    uint32_t           rx_cnt;
    char               *msg;
} json_rpc_con_t;

#define FD_FREE (-1)
#define JSON_RPC_CON_MAX 4
static json_rpc_con_t json_rpc_con_table[JSON_RPC_CON_MAX];

static json_rpc_con_t *json_rpc_connection_lookup(int fd)
{
    int            i;
    json_rpc_con_t *con;

    for (i = 0; i < JSON_RPC_CON_MAX; i++) {
        con = &json_rpc_con_table[i];
        if (con->fd == fd) {
            return con;
        }
    }
    return NULL;
}

static void json_rpc_connection(int fd, void *ref)
{
    int            n, error = 1;
    uint32_t       len;
    json_rpc_con_t *con;
    char           hdr[JSON_RPC_HDR_LEN], *p = hdr;

    // Lookup connection
    if ((con = json_rpc_connection_lookup(fd)) == NULL) {
        T_E("connection not found");
        return;
    }

    if (con->len == 0) {
        // Read header
        if ((n = read(fd, hdr, sizeof(hdr))) < sizeof(hdr)) {
            T_I("header small");
        } else if ((len = ntohl(*(uint32_t *)p)) == 0 || len > (100 * 1024)) {
            T_E("illegal length: %u", len);
        } else if ((con->msg = (char *)malloc(len + 1)) == NULL) {
            T_E("msg malloc failed");
        } else {
            T_I("data length: %u", len);
            con->len = len;
            return;
        }
    } else if ((n = read(fd, con->msg + con->rx_cnt, con->len - con->rx_cnt)) <= 0) {
        // Read data failed
        T_I("no data");
    } else {
        // Read data success
        error = 0;
        con->rx_cnt += n;
        if (con->rx_cnt != con->len) {
            // Message not complete
            return;
        }
        con->msg[con->len] = 0;
        error = json_rpc_parse(fd, con->msg);
    }

    // Free message
    if (con->msg) {
        free(con->msg);
    }
    memset(con, 0, sizeof(*con));

    if (error) {
        T_I("closing connection");
        close(fd);
        if (fd_read_register(fd, NULL, NULL)) {
            T_E("Failed to un-rgister fd");
        }
        con->fd = FD_FREE;
    } else {
        // Preserve file descriptor
        con->fd = fd;
    }
}

static void json_rpc_accept(int fd, void *ref)
{
    json_rpc_con_t *con;
    socklen_t      len = sizeof(con->addr);
    
    // Lookup free connection
    if ((con = json_rpc_connection_lookup(FD_FREE)) == NULL) {
        T_E("no free connection");
    } else if ((fd = accept(fd, (struct sockaddr *)&con->addr, &len)) < 0) {
        T_E("accept() failed: %s", strerror(errno));
    } else if (fd_read_register(fd, json_rpc_connection, NULL) < 0) {
        T_E("fd_read_register() failed");
    } else {
        T_N("new connection accepted");
        con->fd = fd;
    }
}

static void json_rpc_init(void)
{
    int                i, fd;
    struct sockaddr_in addr;

    T_D("enter");
    for (i = 0; i < JSON_RPC_CON_MAX; i++) {
        json_rpc_con_table[i].fd = FD_FREE;
    }
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(4321);
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        T_E("socket failed: %s", strerror(errno));
    } else if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        T_E("bind failed: %s", strerror(errno));
        close(fd);
    } else if (listen(fd, 1) < 0) {
        T_E("listen failed: %s", strerror(errno));
        close(fd);
    } else if (fd_read_register(fd, json_rpc_accept, NULL) < 0) {
        T_E("fd_read_register() failed");
        close(fd);
    }
    T_D("exit");
}

void mscc_appl_json_rpc_init(mscc_appl_init_t *init)
{
    int i;

    switch (init->cmd) {
    case MSCC_INIT_CMD_REG:
        mscc_appl_trace_register(&trace_module, trace_groups, TRACE_GROUP_CNT);
        break;

    case MSCC_INIT_CMD_INIT:
        json_rpc_init();

        for (i = 0; i < sizeof(cli_cmd_table)/sizeof(cli_cmd_t); i++) {
            mscc_appl_cli_cmd_reg(&cli_cmd_table[i]);
        }

        break;

    default:
        break;
    }
}
