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

static bool is_tpa_td(void)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx;

    tdx = TDX_GUEST(ms->cgs);

    return tdx->tpa_td;
}

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

static void tdx_queue_service(struct TdxService *tdx_service,
                              struct TdxEvent *event)
{
    qemu_mutex_lock(&tdx_service->mutex);
    QLIST_INSERT_HEAD(&tdx_service->event_list, event, list);
    tdx_service->event_num++;
    qemu_mutex_unlock(&tdx_service->mutex);

    DPRINTF("queue event %p event num %u\n", event, tdx_service->event_num);
    qemu_sem_post(&tdx_service->sem);
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

struct x86_msi {
    union {
        struct {
            uint32_t    reserved_0              : 2,
                        dest_mode_logical       : 1,
                        redirect_hint           : 1,
                        reserved_1              : 1,
                        virt_destid_8_14        : 7,
                        destid_0_7              : 8,
                        base_address            : 12;
        } QEMU_PACKED x86_address_lo;
        uint32_t address_lo;
    };
    union {
        struct {
            uint32_t    reserved        : 8,
                        destid_8_31     : 24;
        } QEMU_PACKED x86_address_hi;
        uint32_t address_hi;
    };
    union {
        struct {
            uint32_t    vector                  : 8,
                        delivery_mode           : 3,
                        dest_mode_logical       : 1,
                        reserved                : 2,
                        active_low              : 1,
                        is_level                : 1;
        } QEMU_PACKED x86_data;
        uint32_t data;
    };
};

static void tdx_inject_notification(CPUState *cs, run_on_cpu_data data)
{
    X86CPU *cpu = X86_CPU(cs);
    struct TdxEvent *event = data.host_ptr;
    struct x86_msi x86_msi;
    struct kvm_msi msi;
    int ret;

    x86_msi = (struct x86_msi) {
        .x86_address_lo  = {
            .reserved_0 = 0,
            .dest_mode_logical = 0,
            .redirect_hint = 0,
            .reserved_1 = 0,
            .virt_destid_8_14 = 0,
            .destid_0_7 = cpu->apic_id & 0xff,
        },
        .x86_address_hi = {
            .reserved = 0,
            .destid_8_31 = cpu->apic_id >> 8,
        },
        .x86_data = {
            .vector = event->notify,
            .delivery_mode = APIC_DM_FIXED,
            .dest_mode_logical = 0,
            .reserved = 0,
            .active_low = 0,
            .is_level = 0,
        },
    };
    msi = (struct kvm_msi) {
        .address_lo = x86_msi.address_lo,
        .address_hi = x86_msi.address_hi,
        .data = x86_msi.data,
        .flags = 0,
        .devid = 0,
    };

    ret = kvm_vm_ioctl(kvm_state, KVM_SIGNAL_MSI, &msi);
    if (ret < 0)
        DPRINTF("Injected interrupt %llu ioctl failed %d\n", event->notify, ret);

    if (event->done) {
        g_free((void*)event->cmd);
        g_free((void*)event->resp);
        g_free(event);
    }
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

            async_run_on_cpu(event->cpu, tdx_inject_notification,
                             RUN_ON_CPU_HOST_PTR(event));
            DPRINTF("%s: event %p, inject interrupt to notify TPA.\n", __func__, event);
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

void tdx_handle_service(X86CPU *cpu, struct kvm_tdx_vmcall
                               *vmcall)
{
    struct TdxEvent *event;
    uint32_t cmd_len, resp_len;
    hwaddr cmd_gpa, resp_gpa;
    void *cmd, *resp;
    int ret;

    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    cmd_gpa = vmcall->in_r12;
    resp_gpa = vmcall->in_r13;

    /* alloc & fill cmd buffer */
    cmd_len = sizeof(struct tdx_serv_cmd);
    cmd = g_malloc(cmd_len);
    if (address_space_read(&address_space_memory, cmd_gpa,
                           MEMTXATTRS_UNSPECIFIED, cmd,
                           cmd_len) != MEMTX_OK) {
        printf("%s: read cmd header failed\n", __func__);
        goto err_free_cmd;
    }

    cmd_len = ((struct tdx_serv_cmd *)cmd)->length;
    if (!cmd_len || cmd_len < sizeof(struct tdx_serv_cmd)) {
        printf("%s: invalid cmd length\n", __func__);
        goto err_free_cmd;
    }

    cmd = g_realloc(cmd, cmd_len);
    if (address_space_read(&address_space_memory, cmd_gpa,
                           MEMTXATTRS_UNSPECIFIED, cmd,
                           cmd_len) != MEMTX_OK) {
        printf("%s: read cmd buf failed\n", __func__);
        goto err_free_cmd;
    }

    /* alloc and fill resp buffer */
    resp_len = sizeof(struct tdx_serv_resp);
    resp = g_malloc(resp_len);
    if (address_space_read(&address_space_memory, resp_gpa,
                           MEMTXATTRS_UNSPECIFIED, resp,
                           resp_len) != MEMTX_OK) {
        printf("%s: read resp header failed\n", __func__);
        goto err_free_resp;
    }

    resp_len = ((struct tdx_serv_resp *)resp)->length;
    if (!resp_len || resp_len < sizeof(struct tdx_serv_resp)) {
        printf("%s: invalid resp length\n", __func__);
        goto err_free_resp;
    }

    resp = g_realloc(resp, resp_len);

    /* create a TdxEvent and handle events */
    event = g_malloc0(sizeof(struct TdxEvent));
    event->cpu = &cpu->parent_obj;
    event->cmd = (__u64)cmd;
    event->resp = (__u64)resp;
    event->notify = vmcall->in_r14;
    event->timeout = vmcall->in_r15;
    event->resp_gpa = resp_gpa;
    event->done = false;

    if (!event->notify) {
        printf("%s: no notification vector, sync service request\n", __func__);
        ret = tdx_event_handle(event);
        if (ret == TDX_NOT_RESP_SERV) {
            DPRINTF("Need event notification to defer handling.");
        }

        /* copy response data back */
        if (address_space_write(
                &address_space_memory, event->resp_gpa,
                MEMTXATTRS_UNSPECIFIED, (void*)event->resp,
                ((struct tdx_serv_resp *)event->resp)->length) != MEMTX_OK) {
                printf("%s: write resp buf failed\n", __func__);
                goto err_free_event;
        }

        if (event->done) {
            g_free(event);
            g_free(resp);
            g_free(cmd);
        }
    } else {
        printf("%s: notification vector 0x%llx, async service request\n",
               __func__, event->notify);
        tdx_queue_service(&tdx_dispatch_service, event);
    }

    vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
    return;

err_free_event:
    g_free(event);
err_free_resp:
    g_free(resp);
err_free_cmd:
    g_free(cmd);
    return;
}
