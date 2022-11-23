/*
 * common header for vfio based device assignment support
 *
 * Copyright Red Hat, Inc. 2012
 *
 * Authors:
 *  Alex Williamson <alex.williamson@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Based on qemu-kvm device-assignment:
 *  Adapted for KVM by Qumranet.
 *  Copyright (c) 2007, Neocleus, Alex Novik (alex@neocleus.com)
 *  Copyright (c) 2007, Neocleus, Guy Zana (guy@neocleus.com)
 *  Copyright (C) 2008, Qumranet, Amit Shah (amit.shah@qumranet.com)
 *  Copyright (C) 2008, Red Hat, Amit Shah (amit.shah@redhat.com)
 *  Copyright (C) 2008, IBM, Muli Ben-Yehuda (muli@il.ibm.com)
 */

#ifndef HW_VFIO_VFIO_COMMON_H
#define HW_VFIO_VFIO_COMMON_H

#include "exec/memory.h"
#include "qemu/queue.h"
#include "qemu/notify.h"
#include "ui/console.h"
#include "hw/display/ramfb.h"
#ifdef CONFIG_LINUX
#include <linux/vfio.h>
#endif
#include "sysemu/sysemu.h"
#include "hw/vfio/vfio-container-base.h"
#include "sysemu/iommufd_device.h"

#define VFIO_MSG_PREFIX "vfio %s: "

#define TYPE_VFIO_IOMMU_DEVICE "qemu:vfio-iommu-device"

extern const MemoryListener vfio_memory_listener;

enum {
    VFIO_DEVICE_TYPE_PCI = 0,
    VFIO_DEVICE_TYPE_PLATFORM = 1,
    VFIO_DEVICE_TYPE_CCW = 2,
    VFIO_DEVICE_TYPE_AP = 3,
};

typedef struct VFIOMmap {
    MemoryRegion mem;
    void *mmap;
    off_t offset;
    size_t size;
} VFIOMmap;

typedef struct VFIORegion {
    struct VFIODevice *vbasedev;
    off_t fd_offset; /* offset of region within device fd */
    MemoryRegion *mem; /* slow, read/write access */
    size_t size;
    uint32_t flags; /* VFIO region flags (rd/wr/mmap) */
    uint32_t nr_mmaps;
    VFIOMmap *mmaps;
    uint8_t nr; /* cache the region number for debug */
} VFIORegion;

typedef struct VFIOMigration {
    struct VFIODevice *vbasedev;
    VMChangeStateEntry *vm_state;
    Notifier migration_state;
    uint32_t device_state;
    int data_fd;
    void *data_buffer;
    size_t data_buffer_size;
    uint64_t mig_flags;
    uint64_t precopy_init_size;
    uint64_t precopy_dirty_size;
    bool initial_data_sent;
} VFIOMigration;

struct VFIOGroup;

typedef struct VFIOLegacyContainer {
    VFIOContainer bcontainer;
    int fd; /* /dev/vfio/vfio, empowered by the attached groups */
    MemoryListener prereg_listener;
    unsigned iommu_type;
    QLIST_HEAD(, VFIOGroup) group_list;
} VFIOLegacyContainer;

#ifdef CONFIG_IOMMUFD
typedef struct VFIOIOASHwpt {
    uint32_t hwpt_id;
    QLIST_HEAD(, VFIODevice) device_list;
    QLIST_ENTRY(VFIOIOASHwpt) next;
} VFIOIOASHwpt;

typedef struct IOMMUFDBackend IOMMUFDBackend;

typedef struct VFIOIOMMUFDContainer {
    VFIOContainer bcontainer;
    IOMMUFDBackend *be;
    uint32_t ioas_id;
    QLIST_HEAD(, VFIOIOASHwpt) hwpt_list;
} VFIOIOMMUFDContainer;
#endif

typedef QLIST_HEAD(VFIOAddressSpaceList, VFIOAddressSpace) VFIOAddressSpaceList;
extern VFIOAddressSpaceList vfio_address_spaces;

typedef struct VFIODeviceOps VFIODeviceOps;

typedef struct VFIODevice {
    QLIST_ENTRY(VFIODevice) next;
    struct VFIOGroup *group;
    VFIOContainer *container;
    char *sysfsdev;
    char *name;
    DeviceState *dev;
    int fd;
    int type;
    bool reset_works;
    bool needs_reset;
    bool no_mmap;
    bool ram_block_discard_allowed;
    OnOffAuto enable_migration;
    VFIODeviceOps *ops;
    unsigned int num_irqs;
    unsigned int num_regions;
    unsigned int flags;
    VFIOMigration *migration;
    IOMMUFDDevice idev;
    Error *migration_blocker;
    OnOffAuto pre_copy_dirty_page_tracking;
    bool dirty_pages_supported;
    bool dirty_tracking;
#ifdef CONFIG_IOMMUFD
    int devid;
    VFIOIOASHwpt *hwpt;
    IOMMUFDBackend *iommufd;
#endif
    __u64 handle;
} VFIODevice;

struct VFIODeviceOps {
    void (*vfio_compute_needs_reset)(VFIODevice *vdev);
    int (*vfio_hot_reset_multi)(VFIODevice *vdev);
    void (*vfio_eoi)(VFIODevice *vdev);
    Object *(*vfio_get_object)(VFIODevice *vdev);
    void (*vfio_save_config)(VFIODevice *vdev, QEMUFile *f);
    int (*vfio_load_config)(VFIODevice *vdev, QEMUFile *f);
};

typedef struct VFIOGroup {
    int fd;
    int groupid;
    VFIOLegacyContainer *container;
    QLIST_HEAD(, VFIODevice) device_list;
    QLIST_ENTRY(VFIOGroup) next;
    QLIST_ENTRY(VFIOGroup) container_next;
    bool ram_block_discard_allowed;
} VFIOGroup;

typedef struct VFIODMABuf {
    QemuDmaBuf buf;
    uint32_t pos_x, pos_y, pos_updates;
    uint32_t hot_x, hot_y, hot_updates;
    int dmabuf_id;
    QTAILQ_ENTRY(VFIODMABuf) next;
} VFIODMABuf;

typedef struct VFIODisplay {
    QemuConsole *con;
    RAMFBState *ramfb;
    struct vfio_region_info *edid_info;
    struct vfio_region_gfx_edid *edid_regs;
    uint8_t *edid_blob;
    QEMUTimer *edid_link_timer;
    struct {
        VFIORegion buffer;
        DisplaySurface *surface;
    } region;
    struct {
        QTAILQ_HEAD(, VFIODMABuf) bufs;
        VFIODMABuf *primary;
        VFIODMABuf *cursor;
    } dmabuf;
} VFIODisplay;

void vfio_host_win_add(VFIOContainer *bcontainer,
                       hwaddr min_iova, hwaddr max_iova,
                       uint64_t iova_pgsizes);
int vfio_host_win_del(VFIOContainer *bcontainer, hwaddr min_iova,
                      hwaddr max_iova);
VFIOAddressSpace *vfio_get_address_space(AddressSpace *as);
void vfio_put_address_space(VFIOAddressSpace *space);

void vfio_put_base_device(VFIODevice *vbasedev);
void vfio_disable_irqindex(VFIODevice *vbasedev, int index);
void vfio_unmask_single_irqindex(VFIODevice *vbasedev, int index);
void vfio_mask_single_irqindex(VFIODevice *vbasedev, int index);
int vfio_set_irq_signaling(VFIODevice *vbasedev, int index, int subindex,
                           int action, int fd, Error **errp);
void vfio_region_write(void *opaque, hwaddr addr,
                           uint64_t data, unsigned size);
uint64_t vfio_region_read(void *opaque,
                          hwaddr addr, unsigned size);
int vfio_region_setup(Object *obj, VFIODevice *vbasedev, VFIORegion *region,
                      int index, const char *name);
int vfio_region_mmap(VFIORegion *region);
void vfio_region_mmaps_set_enabled(VFIORegion *region, bool enabled);
void vfio_region_unmap(VFIORegion *region);
void vfio_region_exit(VFIORegion *region);
void vfio_region_finalize(VFIORegion *region);
void vfio_reset_handler(void *opaque);
struct vfio_device_info *vfio_get_device_info(int fd);
int vfio_attach_device(char *name, VFIODevice *vbasedev,
                       AddressSpace *as, bool secure,
                       Error **errp);
void vfio_detach_device(VFIODevice *vbasedev);

extern int vfio_kvm_device_fd;

int vfio_kvm_device_add_fd(int fd);
int vfio_kvm_device_del_fd(int fd);

extern const MemoryRegionOps vfio_region_ops;
typedef QLIST_HEAD(VFIOGroupList, VFIOGroup) VFIOGroupList;
extern VFIOGroupList vfio_group_list;

bool vfio_mig_active(void);
int vfio_block_multiple_devices_migration(VFIODevice *vbasedev, Error **errp);
void vfio_unblock_multiple_devices_migration(void);
bool vfio_viommu_preset(VFIODevice *vbasedev);
int64_t vfio_mig_bytes_transferred(void);
void vfio_reset_bytes_transferred(void);

#ifdef CONFIG_LINUX
int vfio_get_region_info(VFIODevice *vbasedev, int index,
                         struct vfio_region_info **info);
int vfio_get_dev_region_info(VFIODevice *vbasedev, uint32_t type,
                             uint32_t subtype, struct vfio_region_info **info);
bool vfio_has_region_cap(VFIODevice *vbasedev, int region, uint16_t cap_type);
struct vfio_info_cap_header *
vfio_get_region_info_cap(struct vfio_region_info *info, uint16_t id);
bool vfio_get_info_dma_avail(struct vfio_iommu_type1_info *info,
                             unsigned int *avail);
struct vfio_info_cap_header *
vfio_get_device_info_cap(struct vfio_device_info *info, uint16_t id);
struct vfio_info_cap_header *
vfio_get_cap(void *ptr, uint32_t cap_offset, uint16_t id);
bool vfio_check_path_with_fd(VFIODevice *vbasedev, Error **errp);
#endif
extern const MemoryListener vfio_prereg_listener;

int vfio_spapr_create_window(VFIOLegacyContainer *container,
                             MemoryRegionSection *section,
                             hwaddr *pgsize);
int vfio_spapr_remove_window(VFIOLegacyContainer *container,
                             hwaddr offset_within_address_space);

bool vfio_migration_realize(VFIODevice *vbasedev, Error **errp);
void vfio_migration_exit(VFIODevice *vbasedev);

int vfio_bitmap_alloc(VFIOBitmap *vbmap, hwaddr size);
bool vfio_devices_all_running_and_mig_active(VFIOContainer *container);
bool vfio_devices_all_device_dirty_tracking(VFIOContainer *container);
int vfio_devices_query_dirty_bitmap(VFIOContainer *container,
                                    VFIOBitmap *vbmap, hwaddr iova,
                                    hwaddr size);
int vfio_get_dirty_bitmap(VFIOContainer *container, uint64_t iova,
                                 uint64_t size, ram_addr_t ram_addr);

#endif /* HW_VFIO_VFIO_COMMON_H */
