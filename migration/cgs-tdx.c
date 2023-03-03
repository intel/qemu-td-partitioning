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

#include "qemu/osdep.h"
#include "qemu-file.h"
#include "cgs.h"
#include "target/i386/kvm/tdx.h"

typedef struct TdxMigHdr {
    uint16_t flags;
    uint16_t buf_list_num;
} TdxMigHdr;

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

static int tdx_mig_stream_ioctl(TdxMigStream *stream, int cmd_id,
                                __u32 metadata, void *data)
{
    struct kvm_tdx_cmd tdx_cmd;
    int ret;

    memset(&tdx_cmd, 0x0, sizeof(tdx_cmd));

    tdx_cmd.id = cmd_id;
    tdx_cmd.flags = metadata;
    tdx_cmd.data = (__u64)(unsigned long)data;

    ret = kvm_device_ioctl(stream->fd, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    if (ret) {
        error_report("Failed to send migration cmd %d to the driver: %s",
                      cmd_id, strerror(ret));
    }

    return ret;
}

static uint64_t tdx_mig_put_mig_hdr(QEMUFile *f, uint64_t num, uint16_t flags)
{
    TdxMigHdr hdr = {
        .flags = flags,
        .buf_list_num = (uint16_t)num,
    };

    qemu_put_buffer(f, (uint8_t *)&hdr, sizeof(hdr));

    return sizeof(hdr);
}

static inline uint64_t tdx_mig_stream_get_mbmd_bytes(TdxMigStream *stream)
{
    /*
     * The first 2 bytes in MBMD buffer tells the overall size of the mbmd
     * data (see TDX module v1.5 ABI spec).
     */
    uint16_t bytes = *(uint16_t *)stream->mbmd;

    return (uint64_t)bytes;
}

static int tdx_mig_savevm_state_start(QEMUFile *f)
{
    TdxMigStream *stream = &tdx_mig.streams[0];
    uint64_t mbmd_bytes, buf_list_bytes, exported_num = 0;
    int ret;

    /* Export mbmd and buf_list */
    ret = tdx_mig_stream_ioctl(stream, KVM_TDX_MIG_EXPORT_STATE_IMMUTABLE,
                               0, &exported_num);
    if (ret) {
        error_report("Failed to export immutable states: %s", strerror(ret));
        return ret;
    }

    mbmd_bytes = tdx_mig_stream_get_mbmd_bytes(stream);
    buf_list_bytes = exported_num * TARGET_PAGE_SIZE;

    tdx_mig_put_mig_hdr(f, exported_num, 0);
    qemu_put_buffer(f, (uint8_t *)stream->mbmd, mbmd_bytes);
    qemu_put_buffer(f, (uint8_t *)stream->buf_list, buf_list_bytes);

    return 0;
}

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
    cgs_mig->savevm_state_start = tdx_mig_savevm_state_start;
    cgs_mig->loadvm_state_setup = tdx_mig_stream_setup;
}
