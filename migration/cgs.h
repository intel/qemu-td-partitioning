/*
 * QEMU Migration for Confidential Guest Support
 *
 * Copyright (C) 2022 Intel Corp.
 *
 * Authors:
 *      Wei Wang <wei.w.wang@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_MIGRATION_CGS_H
#define QEMU_MIGRATION_CGS_H
#include "qemu/osdep.h"
#include "migration.h"

typedef struct CgsMig {
    bool (*is_ready)(void);
    int (*savevm_state_setup)(void);
} CgsMig;

bool cgs_mig_is_ready(void);
int cgs_mig_savevm_state_setup(QEMUFile *f);

#endif
