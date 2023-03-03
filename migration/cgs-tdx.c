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

#define KVM_TDX_MIG_MBMD_TYPE_IMMUTABLE_STATE   0
#define KVM_TDX_MIG_MBMD_TYPE_TD_STATE          1
#define KVM_TDX_MIG_MBMD_TYPE_VCPU_STATE        2
#define KVM_TDX_MIG_MBMD_TYPE_MEMORY_STATE      16
#define KVM_TDX_MIG_MBMD_TYPE_EPOCH_TOKEN       32
#define KVM_TDX_MIG_MBMD_TYPE_ABORT_TOKEN       33

#define GPA_LIST_OP_EXPORT 1

#define TDX_MIG_F_CONTINUE 0x1

typedef struct TdxMigHdr {
    uint16_t flags;
    uint16_t buf_list_num;
} TdxMigHdr;

typedef union GpaListEntry {
    uint64_t val;
    struct {
        uint64_t level:2;
        uint64_t pending:1;
        uint64_t reserved_0:4;
        uint64_t l2_map:3;
#define GPA_LIST_ENTRY_MIG_TYPE_4KB 0
        uint64_t mig_type:2;
        uint64_t gfn:40;
        uint64_t operation:2;
        uint64_t reserved_1:2;
        uint64_t status:5;
        uint64_t reserved_2:3;
    };
} GpaListEntry;

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

static uint8_t tdx_mig_stream_get_mbmd_type(TdxMigStream *stream)
{
    /* TDX module v1.5 ABI spec: MB_TYPE at byte offset 6 */
    return *((uint8_t *)stream->mbmd + 6);
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

static long tdx_mig_save_epoch(QEMUFile *f, bool in_order_done)
{
    TdxMigStream *stream = &tdx_mig.streams[0];
    uint64_t flags = in_order_done ? TDX_MIG_EXPORT_TRACK_F_IN_ORDER_DONE : 0;
    long tdx_hdr_bytes, mbmd_bytes;
    int ret;

    ret = tdx_mig_stream_ioctl(stream, KVM_TDX_MIG_EXPORT_TRACK, 0, &flags);
    if (ret) {
        return ret;
    }

    mbmd_bytes = tdx_mig_stream_get_mbmd_bytes(stream);

    /* Epoch only has mbmd data */
    tdx_hdr_bytes = tdx_mig_put_mig_hdr(f, 0, 0);
    qemu_put_buffer(f, (uint8_t *)stream->mbmd, mbmd_bytes);

    return tdx_hdr_bytes + mbmd_bytes;
}

static long tdx_mig_savevm_state_ram_start_epoch(QEMUFile *f)
{
    return tdx_mig_save_epoch(f, false);
}

static void tdx_mig_gpa_list_setup(union GpaListEntry *gpa_list, hwaddr *gfns,
                                   uint64_t gfn_num)
{
    /* The default migrtion flow currently migrates only 1 page each time */
    assert(gfn_num == 1);

    gpa_list[0].val = 0;
    gpa_list[0].gfn = gfns[0];
    gpa_list[0].mig_type = GPA_LIST_ENTRY_MIG_TYPE_4KB;
    gpa_list[0].operation = GPA_LIST_OP_EXPORT;
}

static long tdx_mig_save_ram(QEMUFile *f, TdxMigStream *stream)
{
    uint64_t num = 1;
    uint64_t hdr_bytes, mbmd_bytes, gpa_list_bytes,
             buf_list_bytes, mac_list_bytes;
    int ret;

    /* Export mbmd, buf list, mac list and gpa list */
    ret = tdx_mig_stream_ioctl(stream, KVM_TDX_MIG_EXPORT_MEM, 0, &num);
    if (ret) {
        return ret;
    }

    mbmd_bytes = tdx_mig_stream_get_mbmd_bytes(stream);
    buf_list_bytes = TARGET_PAGE_SIZE;
    mac_list_bytes = sizeof(Int128);
    gpa_list_bytes = sizeof(GpaListEntry);

    hdr_bytes = tdx_mig_put_mig_hdr(f, 1, 0);
    qemu_put_buffer(f, (uint8_t *)stream->mbmd, mbmd_bytes);
    qemu_put_buffer(f, (uint8_t *)stream->buf_list, buf_list_bytes);
    qemu_put_buffer(f, (uint8_t *)stream->gpa_list, gpa_list_bytes);
    qemu_put_buffer(f, (uint8_t *)stream->mac_list, mac_list_bytes);

    return hdr_bytes + mbmd_bytes + gpa_list_bytes +
           buf_list_bytes + mac_list_bytes;
}

static long tdx_mig_savevm_state_ram(QEMUFile *f, ram_addr_t *gfns,
                                     uint64_t gfn_num)
{
    TdxMigStream *stream = &tdx_mig.streams[0];

    tdx_mig_gpa_list_setup((GpaListEntry *)stream->gpa_list, gfns, gfn_num);
    return tdx_mig_save_ram(f, stream);
}

static int tdx_mig_savevm_state_downtime(void)
{
    TdxMigStream *stream = &tdx_mig.streams[0];

    return tdx_mig_stream_ioctl(stream, KVM_TDX_MIG_EXPORT_PAUSE, 0, 0);
}

static int tdx_mig_save_td(QEMUFile *f, TdxMigStream *stream)
{
    int ret;
    uint64_t mbmd_bytes, buf_list_bytes, exported_num = 0;

    ret = tdx_mig_stream_ioctl(stream, KVM_TDX_MIG_EXPORT_STATE_TD, 0,
                               &exported_num);
    if (ret) {
        return ret;
    }

    mbmd_bytes = tdx_mig_stream_get_mbmd_bytes(stream);
    buf_list_bytes = exported_num * TARGET_PAGE_SIZE;

    /*
     * The TD-scope states and vCPU states are sent together, so add the
     * CONTINUE flag to have the destination side continue the loading.
     */
    tdx_mig_put_mig_hdr(f, exported_num, TDX_MIG_F_CONTINUE);
    qemu_put_buffer(f, (uint8_t *)stream->mbmd, mbmd_bytes);
    qemu_put_buffer(f, (uint8_t *)stream->buf_list, buf_list_bytes);

    return 0;
}

static int tdx_mig_save_one_vcpu(QEMUFile *f, TdxMigStream *stream)
{
    uint64_t mbmd_bytes, buf_list_bytes, exported_num = 0;
    int ret;

    ret = tdx_mig_stream_ioctl(stream, KVM_TDX_MIG_EXPORT_STATE_VP, 0,
                               &exported_num);
    if (ret) {
        return ret;
    }

    mbmd_bytes = tdx_mig_stream_get_mbmd_bytes(stream);
    buf_list_bytes = exported_num * TARGET_PAGE_SIZE;
    /* Ask the destination to continue to load the next vCPU states */
    tdx_mig_put_mig_hdr(f, exported_num, TDX_MIG_F_CONTINUE);

    qemu_put_buffer(f, (uint8_t *)stream->mbmd, mbmd_bytes);
    qemu_put_buffer(f, (uint8_t *)stream->buf_list, buf_list_bytes);

    return 0;
}

static int tdx_mig_save_vcpus(QEMUFile *f, TdxMigStream *stream)
{
    CPUState *cpu;
    int ret;

    CPU_FOREACH(cpu) {
        ret = tdx_mig_save_one_vcpu(f, stream);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

static int tdx_mig_savevm_state_end(QEMUFile *f)
{
    TdxMigStream *stream = &tdx_mig.streams[0];
    int ret;

    ret = tdx_mig_save_td(f, stream);
    if (ret) {
        return ret;
    }

    ret = tdx_mig_save_vcpus(f, stream);
    if (ret) {
        return ret;
    }

    ret = tdx_mig_save_epoch(f, true);
    if (ret < 0) {
        return ret;
    }

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

static void tdx_mig_stream_cleanup(TdxMigStream *stream)
{
    struct kvm_dev_tdx_mig_attr tdx_mig_attr;
    struct kvm_device_attr attr = {
        .group = KVM_DEV_TDX_MIG_ATTR,
        .addr = (uint64_t)&tdx_mig_attr,
        .attr = sizeof(struct kvm_dev_tdx_mig_attr),
    };
    size_t unmap_size;
    int ret;

    memset(&tdx_mig_attr, 0, sizeof(struct kvm_dev_tdx_mig_attr));
    ret = kvm_device_ioctl(stream->fd, KVM_GET_DEVICE_ATTR, &attr);
    if (ret < 0) {
        error_report("tdx mig cleanup failed: %s", strerror(ret));
        return;
    }

    unmap_size = (TDX_MIG_STREAM_GPA_LIST_MAP_OFFSET -
                  TDX_MIG_STREAM_MBMD_MAP_OFFSET) * TARGET_PAGE_SIZE;
    munmap(stream->mbmd, unmap_size);

    unmap_size = (TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET -
                  TDX_MIG_STREAM_GPA_LIST_MAP_OFFSET) * TARGET_PAGE_SIZE;
    munmap(stream->gpa_list, unmap_size);

    unmap_size = (TDX_MIG_STREAM_BUF_LIST_MAP_OFFSET -
                  TDX_MIG_STREAM_MAC_LIST_MAP_OFFSET) * TARGET_PAGE_SIZE;
    munmap(stream->mac_list, unmap_size);

    unmap_size = tdx_mig_attr.buf_list_pages * TARGET_PAGE_SIZE;
    munmap(stream->buf_list, unmap_size);
    close(stream->fd);
}

static void tdx_mig_cleanup(void)
{
    tdx_mig_stream_cleanup(&tdx_mig.streams[0]);

    g_free(tdx_mig.streams);
    tdx_mig.streams = NULL;
}

static int tdx_mig_savevm_state_ram_cancel(hwaddr gfn_end)
{
    TdxMigStream *stream = &tdx_mig.streams[0];
    int ret;

    /* No page has been exported yet. */
    if (!gfn_end) {
        return 0;
    }

    ret = tdx_mig_stream_ioctl(stream, KVM_TDX_MIG_EXPORT_ABORT, 0, &gfn_end);
    if (ret) {
        return ret;
    }

    return 0;
}

static int tdx_mig_loadvm_state(QEMUFile *f)
{
    TdxMigStream *stream = &tdx_mig.streams[0];
    uint64_t mbmd_bytes, buf_list_bytes, mac_list_bytes, gpa_list_bytes;
    uint64_t buf_list_num = 0;
    bool should_continue = true;
    uint8_t mbmd_type;
    int ret, cmd_id;
    TdxMigHdr hdr;

    while (should_continue) {
        if (should_continue && qemu_peek_le16(f, sizeof(hdr)) == 0) {
            continue;
        }

        qemu_get_buffer(f, (uint8_t *)&hdr, sizeof(hdr));
        mbmd_bytes = qemu_peek_le16(f, 0);
        qemu_get_buffer(f, (uint8_t *)stream->mbmd, mbmd_bytes);
        mbmd_type = tdx_mig_stream_get_mbmd_type(stream);

        buf_list_num = hdr.buf_list_num;
        buf_list_bytes = buf_list_num * TARGET_PAGE_SIZE;
        if (buf_list_num) {
            qemu_get_buffer(f, (uint8_t *)stream->buf_list, buf_list_bytes);
        }

        switch (mbmd_type) {
        case KVM_TDX_MIG_MBMD_TYPE_IMMUTABLE_STATE:
            cmd_id = KVM_TDX_MIG_IMPORT_STATE_IMMUTABLE;
            break;
        case KVM_TDX_MIG_MBMD_TYPE_MEMORY_STATE:
            cmd_id = KVM_TDX_MIG_IMPORT_MEM;
            mac_list_bytes = buf_list_num * sizeof(Int128);
            gpa_list_bytes = buf_list_num * sizeof(GpaListEntry);
            qemu_get_buffer(f, (uint8_t *)stream->gpa_list, gpa_list_bytes);
            qemu_get_buffer(f, (uint8_t *)stream->mac_list, mac_list_bytes);
            break;
        case KVM_TDX_MIG_MBMD_TYPE_EPOCH_TOKEN:
            cmd_id = KVM_TDX_MIG_IMPORT_TRACK;
            break;
        case KVM_TDX_MIG_MBMD_TYPE_TD_STATE:
            cmd_id = KVM_TDX_MIG_IMPORT_STATE_TD;
            break;
        case KVM_TDX_MIG_MBMD_TYPE_VCPU_STATE:
            cmd_id = KVM_TDX_MIG_IMPORT_STATE_VP;
            break;
        default:
            error_report("%s: unsupported mb_type %d", __func__, mbmd_type);
            return -1;
        }

        ret = tdx_mig_stream_ioctl(stream, cmd_id, 0, &buf_list_num);
        if (ret) {
            if (buf_list_num != 0) {
                error_report("%s: buf_list_num=%lx", __func__, buf_list_num);
            }
            break;
        }
        should_continue = hdr.flags & TDX_MIG_F_CONTINUE;
    }

    return ret;
}

void tdx_mig_init(CgsMig *cgs_mig)
{
    cgs_mig->is_ready = tdx_mig_is_ready;
    cgs_mig->savevm_state_setup = tdx_mig_stream_setup;
    cgs_mig->savevm_state_start = tdx_mig_savevm_state_start;
    cgs_mig->savevm_state_ram_start_epoch =
                        tdx_mig_savevm_state_ram_start_epoch;
    cgs_mig->savevm_state_ram = tdx_mig_savevm_state_ram;
    cgs_mig->savevm_state_downtime = tdx_mig_savevm_state_downtime;
    cgs_mig->savevm_state_end = tdx_mig_savevm_state_end;
    cgs_mig->savevm_state_cleanup = tdx_mig_cleanup;
    cgs_mig->savevm_state_ram_cancel = tdx_mig_savevm_state_ram_cancel;
    cgs_mig->loadvm_state_setup = tdx_mig_stream_setup;
    cgs_mig->loadvm_state = tdx_mig_loadvm_state;
    cgs_mig->loadvm_state_cleanup = tdx_mig_cleanup;
}
