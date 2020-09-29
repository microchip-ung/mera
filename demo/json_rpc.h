// Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT


#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include "microchip/ethernet/rte/api.h"

typedef struct {
    int         idx;
    int         error;
    char        *ptr;
    char        buf[1024];
    json_object *params;
    json_object *result;
} json_rpc_req_t;

typedef int (* json_rpc_cb_t)(json_rpc_req_t *req);

typedef struct {
    const char    *name;
    json_rpc_cb_t cb;
} json_rpc_method_t;

extern json_rpc_method_t json_rpc_table[];

#define JSON_RC(expr) { int _rc = (expr); if (_rc != 0) { req->error = 1; return _rc; } }

int json_rpc_call(json_rpc_req_t *req, int rc);

// Any object
int json_rpc_get_idx_json_object(json_rpc_req_t *req, json_object *obj, int *idx, json_object **obj_value);
int json_rpc_get_name_json_object(json_rpc_req_t *req, json_object *obj, const char *name, json_object **obj_value);

// Object
int json_rpc_new(json_rpc_req_t *req, json_object **obj);
int json_rpc_add_name_json_object(json_rpc_req_t *req, json_object *obj, const char *name, json_object *obj_value);

// Array
int json_rpc_array_new(json_rpc_req_t *req, json_object **obj);
int json_rpc_add_json_array(json_rpc_req_t *req, json_object *obj, json_object *obj_value);

// NULL
int json_rpc_add_json_null(json_rpc_req_t *req, json_object *obj);

// String
int json_rpc_get_idx_json_string(json_rpc_req_t *req, json_object *obj, int *idx, const char **value);
int json_rpc_get_name_json_string(json_rpc_req_t *req, json_object *obj, const char *name, const char **value);
int json_rpc_add_json_string(json_rpc_req_t *req, json_object *obj, const char *value);
int json_rpc_add_name_json_string(json_rpc_req_t *req, json_object *obj, const char *name, const char *value);

// Integer
int json_rpc_get_idx_uint8_t(json_rpc_req_t *req, json_object *obj, int *idx, uint8_t *value);
int json_rpc_get_idx_int8_t(json_rpc_req_t *req, json_object *obj, int *idx, int8_t *value);
int json_rpc_get_idx_uint16_t(json_rpc_req_t *req, json_object *obj, int *idx, uint16_t *value);
int json_rpc_get_idx_int16_t(json_rpc_req_t *req, json_object *obj, int *idx, int16_t *value);
int json_rpc_get_idx_uint32_t(json_rpc_req_t *req, json_object *obj, int *idx, uint32_t *value);
int json_rpc_get_idx_int32_t(json_rpc_req_t *req, json_object *obj, int *idx, int32_t *value);
int json_rpc_get_idx_uint64_t(json_rpc_req_t *req, json_object *obj, int *idx, uint64_t *value);
int json_rpc_get_idx_int64_t(json_rpc_req_t *req, json_object *obj, int *idx, int64_t *value);
int json_rpc_get_name_uint8_t(json_rpc_req_t *req, json_object *obj, const char *name, uint8_t *value);
int json_rpc_get_name_int8_t(json_rpc_req_t *req, json_object *obj, const char *name, int8_t *value);
int json_rpc_get_name_uint16_t(json_rpc_req_t *req, json_object *obj, const char *name, uint16_t *value);
int json_rpc_get_name_int16_t(json_rpc_req_t *req, json_object *obj, const char *name, int16_t *value);
int json_rpc_get_name_uint32_t(json_rpc_req_t *req, json_object *obj, const char *name, uint32_t *value);
int json_rpc_get_name_int32_t(json_rpc_req_t *req, json_object *obj, const char *name, int32_t *value);
int json_rpc_get_name_uint64_t(json_rpc_req_t *req, json_object *obj, const char *name, uint64_t *value);
int json_rpc_get_name_int64_t(json_rpc_req_t *req, json_object *obj, const char *name, int64_t *value);
int json_rpc_get_uint8_t(json_rpc_req_t *req, json_object *obj, uint8_t *value);
int json_rpc_get_int8_t(json_rpc_req_t *req, json_object *obj, int8_t *value);
int json_rpc_get_uint16_t(json_rpc_req_t *req, json_object *obj, uint16_t *value);
int json_rpc_get_int16_t(json_rpc_req_t *req, json_object *obj, int16_t *value);
int json_rpc_get_uint32_t(json_rpc_req_t *req, json_object *obj, uint32_t *value);
int json_rpc_get_int32_t(json_rpc_req_t *req, json_object *obj, int32_t *value);
int json_rpc_get_uint64_t(json_rpc_req_t *req, json_object *obj, uint64_t *value);
int json_rpc_get_int64_t(json_rpc_req_t *req, json_object *obj, int64_t *value);
int json_rpc_add_uint8_t(json_rpc_req_t *req, json_object *obj, uint8_t *value);
int json_rpc_add_int8_t(json_rpc_req_t *req, json_object *obj, int8_t *value);
int json_rpc_add_uint16_t(json_rpc_req_t *req, json_object *obj, uint16_t *value);
int json_rpc_add_int16_t(json_rpc_req_t *req, json_object *obj, int16_t *value);
int json_rpc_add_uint32_t(json_rpc_req_t *req, json_object *obj, uint32_t *value);
int json_rpc_add_int32_t(json_rpc_req_t *req, json_object *obj, int32_t *value);
int json_rpc_add_uint64_t(json_rpc_req_t *req, json_object *obj, uint64_t *value);
int json_rpc_add_int64_t(json_rpc_req_t *req, json_object *obj, int64_t *value);
int json_rpc_add_name_uint8_t(json_rpc_req_t *req, json_object *obj, const char *name, uint8_t *value);
int json_rpc_add_name_int8_t(json_rpc_req_t *req, json_object *obj, const char *name, int8_t *value);
int json_rpc_add_name_uint16_t(json_rpc_req_t *req, json_object *obj, const char *name, uint16_t *value);
int json_rpc_add_name_int16_t(json_rpc_req_t *req, json_object *obj, const char *name, int16_t *value);
int json_rpc_add_name_uint32_t(json_rpc_req_t *req, json_object *obj, const char *name, uint32_t *value);
int json_rpc_add_name_int32_t(json_rpc_req_t *req, json_object *obj, const char *name, int32_t *value);
int json_rpc_add_name_uint64_t(json_rpc_req_t *req, json_object *obj, const char *name, uint64_t *value);
int json_rpc_add_name_int64_t(json_rpc_req_t *req, json_object *obj, const char *name, int64_t *value);

int json_rpc_add_name_int(json_rpc_req_t *req, json_object *obj, const char *name, int *value);
int json_rpc_add_int(json_rpc_req_t *req, json_object *obj, int *value);

int json_rpc_get_idx_int(json_rpc_req_t *req, json_object *obj, int *idx, int *value);
int json_rpc_get_name_int(json_rpc_req_t *req, json_object *obj, const char *name, int *value);
int json_rpc_get_int(json_rpc_req_t *req, json_object *obj, int *value);

// Boolean
int json_rpc_get_idx_mera_bool_t(json_rpc_req_t *req, json_object *obj, int *idx, mera_bool_t *value);
int json_rpc_get_name_mera_bool_t(json_rpc_req_t *req, json_object *obj, const char *name, mera_bool_t *value);
int json_rpc_add_mera_bool_t(json_rpc_req_t *req, json_object *obj, mera_bool_t *value);
int json_rpc_add_name_mera_bool_t(json_rpc_req_t *req, json_object *obj, const char *name, mera_bool_t *value);
