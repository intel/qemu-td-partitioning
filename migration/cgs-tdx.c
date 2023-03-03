/*
 * QEMU Migration for Intel TDX Guests
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

#include "cgs.h"
#include "target/i386/kvm/tdx.h"

typedef struct TdxMigStream {
    int fd;
    void *mbmd;
    void *buf_list;
    void *mac_list;
    void *gpa_list;
} TdxMigStream;

typedef struct TdxMigState {
    uint32_t nr_streams;
    TdxMigStream *streams;
} TdxMigState;

TdxMigState tdx_mig;

static bool tdx_mig_is_ready(void)
{
    return tdx_premig_is_done();
}

static int tdx_mig_stream_create(TdxMigStream *stream)
{
    int ret;

    ret = kvm_create_device(kvm_state, KVM_DEV_TYPE_TDX_MIG_STREAM, false);
    if (ret < 0) {
        error_report("Failed to create stream due to %s", strerror(ret));
        return ret;
    }
    stream->fd = ret;

    return 0;
}

static int tdx_mig_stream_setup(uint32_t nr_channels)
{
    TdxMigStream *stream;
    struct kvm_dev_tdx_mig_attr tdx_mig_attr;
    struct kvm_device_attr attr = {
        .group = KVM_DEV_TDX_MIG_ATTR,
        .addr = (uint64_t)&tdx_mig_attr,
        .attr = sizeof(struct kvm_dev_tdx_mig_attr),
    };
    size_t map_size;
    off_t map_offset;
    int ret;

    /* Multiple streams are not supported currently */
    assert(nr_channels == 1);

    tdx_mig.nr_streams = nr_channels;
    tdx_mig.streams = g_malloc0(sizeof(struct TdxMigStream) * 1);
    stream = &tdx_mig.streams[0];

    ret = tdx_mig_stream_create(stream);
    if (ret) {
        return ret;
    }

    /*
     * Tell the tdx_mig driver the number of pages to add to buffer list for
     * TD private page export/import. Currently, TD private pages are migrated
     * one by one.
     */
    tdx_mig_attr.buf_list_pages = 1;
    tdx_mig_attr.version = KVM_DEV_TDX_MIG_ATTR_VERSION;
    if (kvm_device_ioctl(stream->fd, KVM_SET_DEVICE_ATTR, &attr) < 0) {
        return -EIO;
    }

    memset(&tdx_mig_attr, 0, sizeof(struct kvm_dev_tdx_mig_attr));
    tdx_mig_attr.version = KVM_DEV_TDX_MIG_ATTR_VERSION;
    if (kvm_device_ioctl(stream->fd, KVM_GET_DEVICE_ATTR, &attr) < 0) {
        return -EIO;
    }

    map_offset = TDX_MIG_STREAM_MBMD_MAP_OFFSET;
    map_size = (TDX_MIG_STREAM_GPA_LIST_MAP_OFFSET -
                TDX_MIG_STREAM_MBMD_MAP_OFFSET) * TARGET_PAGE_SIZE;
    stream->mbmd = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                        stream->fd, map_offset);
    if (stream->mbmd == MAP_FAILED) {
        ret = -errno;
        error_report("Failed to map mbmd due to %s", strerror(ret));
        return ret;
    }

    map_offset = TDX_MIG_STREAM_GPA_LIST_MAP_OFFSET * TARGET_PAGE_SIZE;
    map_size = (TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET -
                TDX_MIG_STREAM_GPA_LIST_MAP_OFFSET) * TARGET_PAGE_SIZE;
    stream->gpa_list = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                            stream->fd, map_offset);
    if (stream->gpa_list == MAP_FAILED) {
        ret = -errno;
        error_report("Failed to map gpa list due to %s", strerror(ret));
        return ret;
    }

    map_offset = TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET * TARGET_PAGE_SIZE;
    map_size = (TDX_MIG_STREAM_BUF_LIST_MAP_OFFSET -
                TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET) * TARGET_PAGE_SIZE;
    stream->mac_list = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                            stream->fd, map_offset);
    if (stream->mac_list == MAP_FAILED) {
        ret = -errno;
        error_report("Failed to map mac list due to %s", strerror(ret));
        return ret;
    }

    map_offset = TDX_MIG_STREAM_BUF_LIST_MAP_OFFSET * TARGET_PAGE_SIZE;
    map_size = tdx_mig_attr.buf_list_pages * TARGET_PAGE_SIZE;
    stream->buf_list = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                            stream->fd, map_offset);
    if (stream->buf_list == MAP_FAILED) {
        ret = -errno;
        error_report("Failed to map buf list due to %s", strerror(ret));
        return ret;
    }

    return 0;
}

void tdx_mig_init(CgsMig *cgs_mig)
{
    cgs_mig->is_ready = tdx_mig_is_ready;
    cgs_mig->savevm_state_setup = tdx_mig_stream_setup;
    cgs_mig->loadvm_state_setup = tdx_mig_stream_setup;
}
