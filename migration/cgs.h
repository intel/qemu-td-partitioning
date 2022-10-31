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
    int (*savevm_state_setup)(uint32_t nr_channels);
    int (*savevm_state_start)(QEMUFile *f);
    long (*savevm_state_ram_start_epoch)(QEMUFile *f);
    long (*savevm_state_ram)(QEMUFile *f,
                             hwaddr *gfns,
                             uint64_t gfn_num);
    int (*savevm_state_downtime)(void);
} CgsMig;

bool cgs_mig_is_ready(void);
int cgs_mig_savevm_state_setup(QEMUFile *f);
int cgs_mig_savevm_state_start(QEMUFile *f);
long cgs_ram_save_start_epoch(QEMUFile *f);
long cgs_mig_savevm_state_ram(QEMUFile *f, RAMBlock *block, ram_addr_t offset,
                              hwaddr *gfns, uint64_t gfn_num);
int cgs_mig_savevm_state_downtime(QEMUFile *f);

#endif
