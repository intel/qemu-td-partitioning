/*
 * Common TDX services for tdxio based device support
 * Authors:
 *  Jingqi Liu   <jingqi.liu@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"

#include <linux/netlink.h>
#include <sys/ioctl.h>

#include "sysemu/kvm.h"
#include "hw/boards.h"
#include "hw/i386/pc.h"
#include "hw/i386/apic_internal.h"
#include "hw/pci/pci.h"
#include "hw/vfio/pci.h"
#include "tdx.h"
#include "tdxio.h"

#define DEBUG_TDXIO

#ifdef DEBUG_TDXIO
#define DPRINTF(fmt, ...) \
    do { printf("%s: %d: " fmt, __func__, __LINE__, ## __VA_ARGS__); } while(0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

bool tdx_service_init = false;

static void *tdx_dispatch_serv_thread_fn(void *arg);


static struct TdxService tdx_dispatch_service = {
    .name = "tdx service",
    .func = tdx_dispatch_serv_thread_fn
};

/* Below GUIDs are based on GHCI 2.0_0.6.4. */

/* TDCM Service GUID */
QemuUUID tdcm_guid = {{
    .fields = {
        0x6270da51, 0x9a23, 0x4b6b,
        0x81, 0xce, {0xdd, 0xd8, 0x69, 0x70, 0xf2, 0x96}
    }
}};

static void dump_memory(uint64_t addr, uint32_t size)
{
    int i;

    for (i = 0; i < size; i++) {
        if (!(i%16))
            printf("\n0x%08lx: ", addr + i);
        printf("%02x ", *(uint8_t *)(addr + i));
    }
    printf("\n");
    return;
}

static VFIOPCIDevice *find_vfio_by_devid(uint32_t devid)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    PCMachineState *pcms = PC_MACHINE(ms);
    PCIBus *bus = pcms->bus;
    PCIDevice *pdev;

    pdev = pci_find_device(bus, (devid >> 8) & 0xff,
                           (devid) & 0xff);
    if (!pdev) {
        return NULL;
    }

    return (VFIOPCIDevice *)object_dynamic_cast(OBJECT(pdev), TYPE_VFIO_PCI);
}

static int get_spdm_fd(VFIOPCIDevice* vdev)
{
    DIR *dir;
    struct dirent *stdir;
    static char bdf[100];
    static char path[1024];
    static char buf[1024];
    int n;

    if ((dir = opendir("/sys/class/spdm/")) == NULL) {
        warn_report("open /sys/class/spdm failed!\n");
        return -1;
    }

    // int guest_bus = pci_bus_num(PCI_BUS(qdev_get_parent_bus(DEVICE(vdev))));
    // int guest_devfn = PCI_DEVICE(vdev)->devfn;
    // info_report("tdcm guest bus %d, dev %d, fun %d", guest_bus, guest_devfn >> 3, guest_devfn & 0x07);
    // info_report("tdcm host bus %d, dev %d, fun %d", vdev->host.bus, vdev->host.slot, vdev->host.function);
    sprintf(bdf, "%04x:%02x:%02x.%x", vdev->host.domain, vdev->host.bus, vdev->host.slot, vdev->host.function);

#define SPDM_DEVICE "spdm"
#define SPDM_MGR_DEVICE "spdm_mgr_user"

    while ((stdir = readdir(dir))) {
        if (strncmp(stdir->d_name, SPDM_DEVICE, strlen(SPDM_DEVICE)) != 0 ||
            strncmp(stdir->d_name, SPDM_MGR_DEVICE, strlen(SPDM_MGR_DEVICE)) == 0)
            continue;

        sprintf(path, "/sys/class/spdm/%s/device", stdir->d_name);
        n = readlink(path, buf, sizeof(buf));
        buf[n] = '\0';

        if (strcmp(g_path_get_basename(buf), bdf) == 0) {
            sprintf(buf, "/dev/%s", stdir->d_name);
            printf("open %s\n", buf);
            return open(buf, O_RDONLY);
        }
    }

    return -1;
}

static GHashTable *handle_table_get(void)
{
    static GHashTable *handle_table;

    if (handle_table == NULL) {
        handle_table = g_hash_table_new(g_int64_hash, g_int64_equal);
    }

    return handle_table;
}

static uint8_t tdx_serv_tdcm_get_dev_handle(struct TdxEvent *event)
{
    struct tdcm_cmd_get_dev_handle *cmd = (void *)event->cmd;
    struct tdcm_resp_get_dev_handle *resp = (void *)event->resp;
    VFIOPCIDevice *vdev = find_vfio_by_devid(cmd->devid);
    uint8_t ret = TDCM_RESP_STS_OK;

    if (vdev) {
        struct kvm_tdisp_info info = { 0 };

        info.devid = vdev->host.bus << 8 | vdev->host.slot << 5 | vdev->host.function;

        ret = kvm_vm_ioctl(kvm_state, KVM_TDISP_GET_INFO, &info);
        if (ret)
            return TDCM_RESP_STS_FAIL;

        resp->dev_handle = info.handle;
        vdev->handle = info.handle;
        g_hash_table_insert(handle_table_get(), &vdev->handle, vdev);
    } else {
        resp->dev_handle = 0;
    }

    DPRINTF("devid %x handle %llx vdev %p\n",
            cmd->devid, resp->dev_handle, vdev);

    return ret;
}

static uint8_t tdx_serv_tdcm_devif(struct TdxEvent *event)
{
    struct tdcm_cmd_devif *cmd = (void *)event->cmd;
    struct kvm_tdisp_user_request req = { 0 };
    int ret;

    req.handle = cmd->dev_handle;
    req.parm.raw = cmd->req_param;
    req.info.raw = cmd->req_info;

    ret = kvm_vm_ioctl(kvm_state, KVM_TDISP_USER_REQUEST, &req);
    if (ret) {
        DPRINTF("handle 0x%llx, TDISP request fail. ret %d\n",
                cmd->dev_handle, ret);
        return TDCM_RESP_STS_FAIL;
    }

    return TDCM_RESP_STS_OK;
}

static uint8_t tdx_serv_tdcm_get_dev_info(struct TdxEvent *event)
{
    struct tdcm_cmd_get_dev_info *tdcm_cmd = (void *)event->cmd;
    struct tdcm_resp_get_dev_info *tdcm_resp = (void *)event->resp;
    struct spdm_dev_info dev_info;
    uint32_t hdr_size, len;
    VFIOPCIDevice *vdev = NULL;
    int ret;
    int spdm_fd;

    vdev = g_hash_table_lookup(handle_table_get(), &tdcm_cmd->dev_handle);

    if (!vdev) {
        DPRINTF("handle 0x%llx, no SPDM device found\n",
                tdcm_cmd->dev_handle);
        return TDCM_RESP_STS_FAIL;
    }

    spdm_fd = get_spdm_fd(vdev);
    if (spdm_fd < 0) {
        DPRINTF("handle 0x%llx, fail to get spdm fd\n",
                tdcm_cmd->dev_handle);
        return TDCM_RESP_STS_FAIL;
    }

    ret = dev_info.size = ioctl(spdm_fd, SPDM_GET_DEVICE_INFO_SIZE);
    if (ret <= 0) {
        DPRINTF("handle 0x%llx SPDM dev %d,"
                "fail to get device info size. ret %d\n",
                tdcm_cmd->dev_handle, spdm_fd, ret);
        close(spdm_fd);
        return TDCM_RESP_STS_FAIL;
    }

    hdr_size = sizeof(struct tdcm_resp_get_dev_info);
    len = tdcm_resp->resp.length - hdr_size;
    DPRINTF("len 0x%x\n", len);

        if (dev_info.size > len) {
        DPRINTF("No enough response buffer 0x%x for DEV_INFO_DATA 0x%x.\n",
                len, dev_info.size);
        tdcm_resp->resp.status = SERV_RESP_STS_BUF_SMALL;
        close(spdm_fd);
        return TDCM_RESP_STS_FAIL;
    }

    dev_info.data = tdcm_resp->dev_info_data;
    ret = ioctl(spdm_fd, SPDM_GET_DEVICE_INFO, tdcm_resp->dev_info_data);
    if (ret) {
        DPRINTF("handle 0x%llx SPDM dev %d, fail to get dev info data. ret %d\n",
                tdcm_cmd->dev_handle, spdm_fd, ret);
        close(spdm_fd);
        return TDCM_RESP_STS_FAIL;
    }

    tdcm_resp->resp.length = hdr_size + dev_info.size;

    DPRINTF("handle %llx dev_info_data %p spdm_dev %d resp.length 0x%x\n",
            tdcm_cmd->dev_handle, dev_info.data, spdm_fd,
            tdcm_resp->resp.length);

    close(spdm_fd);
    return TDCM_RESP_STS_OK;
}

static int tdx_serv_tdcm(struct TdxEvent *event)
{
    struct tdx_serv_resp *resp = (void *)event->resp;
    struct tdcm_cmd_hdr *tdcm_cmd = (void *)(event->cmd +
                                    sizeof(struct tdx_serv_cmd));
    struct tdcm_resp_hdr *tdcm_resp = (void *)(event->resp +
                                      sizeof(struct tdx_serv_resp));

    switch (tdcm_cmd->command) {
    case TDCM_CMD_GET_DEV_HANDLE:
        resp->length = sizeof(struct tdcm_resp_get_dev_handle);
        tdcm_resp->status = tdx_serv_tdcm_get_dev_handle(event);
        break;
    case TDCM_CMD_TDISP:
        /* TODO: call TDISP kernel driver */

        resp->length = sizeof(struct tdcm_resp_devif);
        tdcm_resp->status = tdx_serv_tdcm_devif(event);
        break;
    case TDCM_CMD_MAP_DMA_GPA:
        /* TODO: call MAP_DMA_GPA kernel driver */

        resp->length = sizeof(struct tdx_serv_resp) +
                       sizeof(struct tdcm_resp_hdr);
        tdcm_resp->status = TDCM_RESP_STS_FAIL;
        break;
    case TDCM_CMD_GET_DEV_INFO:
        tdcm_resp->status = tdx_serv_tdcm_get_dev_info(event);
        break;
    default:
        resp->length = sizeof(struct tdx_serv_resp) +
                       sizeof(struct tdcm_resp_hdr);
        tdcm_resp->status = TDCM_RESP_STS_FAIL;
        break;
    }

    event->done = true;
    return TDX_RESP_SERV;
}

static int tdx_event_handle(struct TdxEvent *event)
{
    struct tdx_serv_cmd *cmd = (void *)event->cmd;
    struct tdx_serv_resp *resp = (void *)event->resp;
    int ret = TDX_RESP_SERV;

    DPRINTF("command buffer guid:\n");
    dump_memory((uint64_t)&cmd->guid, 16);

    /* The response GUID is filled by TPA TD. */
    memcpy(&resp->guid, &cmd->guid, sizeof(QemuUUID));

    resp->status = SERV_RESP_STS_RETURN;

    if (qemu_uuid_is_equal(&cmd->guid, &tdcm_guid)) {
        ret = tdx_serv_tdcm(event);
    } else {
        resp->status = SERV_RESP_STS_UNSUPPORT;
        event->done = true;
    }

    return ret;
}

static void *tdx_dispatch_serv_thread_fn(void *arg)
{
    struct TdxService *service = arg;
    struct TdxEvent *event;
    int ret;

event_handle:
    qemu_sem_wait(&service->sem);

    while (1) {
        qemu_mutex_lock(&service->mutex);
        if (!QLIST_EMPTY(&service->event_list)) {
            event = QLIST_FIRST(&service->event_list);
            QLIST_REMOVE(event, list);
            service->event_num--;
        } else {
            qemu_mutex_unlock(&service->mutex);
            break;
        }
        qemu_mutex_unlock(&service->mutex);

        DPRINTF("%s: evt %p num %u vector %lld\n", __func__,
                event, service->event_num, event->notify);
        ret = tdx_event_handle(event);

        /* Inject interrupt to notify TPA to get response. */
        if (ret == TDX_RESP_SERV) {
            /* copy response data back */
            if (address_space_write(
                &address_space_memory, event->resp_gpa,
                MEMTXATTRS_UNSPECIFIED, (void*)event->resp,
                ((struct tdx_serv_resp *)event->resp)->length) !=
                    MEMTX_OK) {
                printf("%s: write resp buf failed\n", __func__);
            }

            // TODO: Inject MSI interrupt to notify TPA
        }
        DPRINTF("%s: event %p is done.\n", __func__, event);
    }

    if (!service->exit) {
        goto event_handle;
    }

    return NULL;
}

static int tdx_init_service(struct TdxService *tdx_service)
{
    if (!tdx_service)
        return -1;

    tdx_service->thread = g_malloc0(sizeof(QemuThread));
    qemu_mutex_init(&tdx_service->mutex);
    qemu_sem_init(&tdx_service->sem, 0);

    qemu_thread_create(tdx_service->thread,
                       tdx_service->name,
                       tdx_service->func, tdx_service,
                       QEMU_THREAD_DETACHED);

    DPRINTF("Service %s initialized.\n", tdx_service->name);
    return 0;
}

int tdx_services_init(void)
{
    int ret = 0;

    /* Common service */
    ret = tdx_init_service(&tdx_dispatch_service);
    if (ret < 0) {
        fprintf(stderr, "kvm: Failed to initialize TDX service. %d\n", ret);
        return ret;
    }

    /* Normal-TD service */

    tdx_service_init = true;
    printf("Success to initialize TDX services.\n");

    return ret;
}
