// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#include "rte_private.h"

struct lan9662_rte_inst *lan9662_rte_create(const lan9662_rte_cb_t *cb) {
    struct lan9662_rte_inst *p = calloc(1, sizeof(struct lan9662_rte_inst));

    if (!p) {
        return p;
    }

    p->cb = *cb;

    return p;
}

void lan9662_rte_destroy(struct lan9662_rte_inst *inst) {
    free(inst);
}

int lan9662_rte_test(struct lan9662_rte_inst *inst) {
    printf("This is a test\n");
    return 0;
}

int lan9662_rte_plus(struct lan9662_rte_inst *inst, int a, int b) {
    return a + b;
}

