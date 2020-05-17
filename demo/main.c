// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdlib.h>
#include <lan9662/rte.h>

int main() {
    lan9662_rte_cb_t cb = {};
    struct lan9662_rte_inst *inst = lan9662_rte_create(&cb);

    lan9662_rte_test(inst);

    lan9662_rte_destroy(inst);

    return 0;
}
