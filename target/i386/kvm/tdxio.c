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
#include "spdm.h"

#define DEBUG_TDXIO

#ifdef DEBUG_TDXIO
#define DPRINTF(fmt, ...) \
    do { printf("%s: %d: " fmt, __func__, __LINE__, ## __VA_ARGS__); } while(0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define __UEVENT_BUFFER_SIZE (256 * 1024)
#define __UEVENT_LISTEN_ALL -1

#define TDX_SERVICE_NAME "tdx-service"

bool tdx_service_init = false;

static EventNotifier tdx_spdmmgr_notifier;
static int tdx_spdmmgr_eventfd;
struct SpdmMgrRequest spdmmgr_request;

static void *tdx_dispatch_serv_thread_fn(void *arg);
static void *tdx_tpa_serv_thread_fn(void *arg);
static void *tdx_spdm_serv_thread_fn(void *arg);
static void *tdx_spdmmgr_listener_fn(void *arg);
static void tdx_serv_request_handler(void *opaque);
static void tdx_serv_tpa_handle(struct TdxEvent *event);
static int tdx_serv_spdm_handle(struct TdxEvent *event);

static struct TdxService tdx_dispatch_service = {
    .name = "tdx service",
    .func = tdx_dispatch_serv_thread_fn
};

static struct TdxService tdx_tpa_serv = {
    .name = "tpa service",
    .func = tdx_tpa_serv_thread_fn
};

static struct TdxService tdx_spdm_serv = {
    .name = "spdm service",
    .func = tdx_spdm_serv_thread_fn
};

struct SpdmMgrListener spdmmgr_listener = {
    .func = tdx_spdmmgr_listener_fn
};

/* Below GUIDs are based on GHCI 2.0_0.6.4. */

/* Query Service GUID */
QemuUUID query_guid = {{
    .fields = {
        0xfb6fc5e1, 0x3378, 0x4acb,
        0x89, 0x64, {0xfa, 0x5e, 0xe4, 0x3b, 0x9c, 0x8a}
    }
}};

/* TPA Service GUID */
QemuUUID tpa_guid = {{
    .fields = {
        0x0320dae8, 0x75b6, 0x4ac8,
        0xa9, 0xda, {0x2d, 0xe6, 0x9d, 0x18, 0x59, 0xda}
    }
}};

/* SPDM Service GUID */
QemuUUID spdm_guid = {{
    .fields = {
        0xa148b5dd, 0x50c, 0x4be4,
        0xa6, 0x30, {0xe5, 0xe5, 0x30, 0x1f, 0x2a, 0x9b}
    }
}};

/* TDCM Service GUID */
QemuUUID tdcm_guid = {{
    .fields = {
        0x6270da51, 0x9a23, 0x4b6b,
        0x81, 0xce, {0xdd, 0xd8, 0x69, 0x70, 0xf2, 0x96}
    }
}};

/* TPA Device Information HOB GUID */
QemuUUID tpa_dev_info_hob_guid = {{
    .fields = {
        0x7142fad8, 0xd60b, 0x42a6,
        0xb9, 0x99, {0x69, 0x3a, 0xc0, 0x53, 0x63, 0x9b}
    }
}};

/* TPA SPDM Policy HOB GUID */
QemuUUID tpa_spdm_policy_hob_guid = {{
    .fields = {
        0xe724fd4, 0x60ef, 0x4e3b,
        0xa2, 0x84, {0x44, 0x3d, 0x79, 0x2e, 0x39, 0x1}
    }
}};

/* TPA TDISP Policy HOB GUID */
QemuUUID tpa_tdisp_policy_hob_guid = {{
    .fields = {
        0xaf024a2c, 0x3f4f, 0x4247,
        0x80, 0x4a, {0x9b, 0x69, 0x61, 0x4c, 0xf, 0xfa}
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

static const char *search_key(const char *searchkey, const char *buf, size_t buflen)
{
    size_t bufpos = 0;
    size_t searchkeylen = strlen(searchkey);
    while (bufpos < buflen) {
        const char *key;
        int keylen;
        key = &buf[bufpos];
        keylen = strlen(key);
        if (keylen == 0)
            break;
        if ((strncmp(searchkey, key, searchkeylen) == 0) && key[searchkeylen] == '=')
            return &key[searchkeylen + 1];
        bufpos += keylen + 1;
    }
    return NULL;
}

static void *tdx_spdmmgr_listener_fn(void *arg)
{
    struct sockaddr_nl rcv_addr = { 0 };
    char buf[__UEVENT_BUFFER_SIZE] = { 0 };
    struct iovec iov = { buf, __UEVENT_BUFFER_SIZE };
    char control[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr hdr = {
        &rcv_addr, sizeof(rcv_addr), &iov, 1,
        control,   sizeof(control),  0,
    };
    struct SpdmMgrListener *listener = arg;
    struct spdm_eventfd eventfd;

    for (;;) {
        const char *action, *devpath;
        const char *devname = NULL;
        int sk_fd = listener->sk_fd;
        ssize_t r;

        r = recvmsg(sk_fd, &hdr, 0);
        if (r <= 0) {
            fprintf(stderr, "%s - Failed to receive uevent\n", strerror(errno));
            break;
        }

        action = search_key("ACTION", buf, r);
        devpath = search_key("DEVPATH", buf, r);
        devname = search_key("DEVNAME", buf, r);

        if (devname && strstr(devname, "spdm_mgr_user")) {
            struct SpdmDevice *spdm_dev;
            int sg_num, bus_num, dev_num, func, index, mgr;
            int fd = -1, ret;
            uint32_t devid = 0;
            char *str, dev[30];

            /* Example: DEVPATH=
             * /devices/pci0000:00/0000:00:0a.0/0000:0a:00.0/spdm/spdm0/spdm_mgr_user0
             * Uevent may show more than one time for the same device. (check uevent.log)
             */
            str = strstr(devpath, "/spdm");

            /* Subtract the size of format string: xxxx:xx:xx.x */
            str -= 12;
            ret = sscanf(str, "%04x:%02x:%02x.%01x/spdm/spdm%d/spdm_mgr_user%d",
                         &sg_num, &bus_num, &dev_num, &func, &index, &mgr);
            if (ret == 6) {
                /* Based on GHCI 2.0_0.6.4:
                 * Byte 0 [Bit0~2]: PCI Function Number
                 * Byte 0 [Bit3~7]: PCI Device Number
                 * BYTE 1: PCI Bus Number
                 * BYTE 2, 3: PCI Segment Number
                 */
                devid = ((sg_num & 0xFFFF) << 16) |
                        ((bus_num & 0xFF) << 8)   |
                        ((dev_num << 3) & 0xFF)   |
                        ((func & 0x7) );
                sprintf(dev, "/dev/spdm_mgr_user%d", mgr);
                DPRINTF("devid: 0x%x, dev: %s\n", devid, dev);
            }

            /* action: device add */
            DPRINTF("spdm events: action %s devname %s\n", action, devname);
            DPRINTF("devpath %s\n", devpath);
            if (!strcmp(action, "add")) {
                fd = open(dev, O_RDONLY);
                if (fd < 0) {
                    fprintf(stderr, "%s - Failed to open device %s\n",
                            strerror(errno), dev);
                    continue;
                }

                spdm_dev = g_malloc0(sizeof(struct SpdmDevice));
                spdm_dev->fd = fd;
                spdm_dev->devid = devid;

                /* Set SPDM device request eventfd. */
                eventfd.fd = tdx_spdmmgr_eventfd;
                ret = ioctl(fd, SPDM_SET_EVENTFD, &eventfd);
                if (ret) {
                    DPRINTF("Fail to set the eventfd %d on SPDM device %p.\n",
                            eventfd.fd, spdm_dev);
                    close(fd);
                    continue;
                }

                spdm_dev->devpath = g_malloc0(strlen(devpath) + 1);
                strcpy(spdm_dev->devpath, devpath);

                /* Set request eventfd notifier. */
                qemu_set_fd_handler(tdx_spdmmgr_eventfd,
                                    tdx_serv_request_handler,
                                    NULL, spdm_dev);

                qemu_mutex_lock(&listener->mutex);
                QLIST_INSERT_HEAD(&listener->device_list, spdm_dev, list);
                listener->device_num++;
                qemu_mutex_unlock(&listener->mutex);

                DPRINTF("Add device %p fd %d num %u\n",
                        spdm_dev, fd, listener->device_num);
            } else if (!strcmp(action, "remove")) {
                /* Remove from the listener device list. */
                qemu_mutex_lock(&listener->mutex);
                QLIST_FOREACH(spdm_dev, &listener->device_list, list) {
                    if (spdm_dev->devid == devid) {
                        listener->device_num--;
                        QLIST_REMOVE(spdm_dev, list);
                        break;
                    }
                }
                qemu_mutex_unlock(&listener->mutex);

                if (listener->device_num == 0)
                    qemu_set_fd_handler(tdx_spdmmgr_eventfd, NULL, NULL, NULL);

                DPRINTF("Remove spdm_dev %p num %u\n",
                        spdm_dev, listener->device_num);

                close(spdm_dev->fd);
                g_free(spdm_dev->devpath);
                g_free(spdm_dev);
            }
        }
    }

    return NULL;
}

/* Initialize the thread to listen to
 * the uevent of SPDM manager devices.
 */
static int tdx_spdmmgr_listener_init(struct SpdmMgrListener *listener)
{
    int sk_fd, ret = -1;
    socklen_t sk_addr_len;
    int rcv_buf_sz = __UEVENT_BUFFER_SIZE;
    struct sockaddr_nl sk_addr = { 0 };

    sk_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
                   NETLINK_KOBJECT_UEVENT);
    if (sk_fd < 0) {
        fprintf(stderr, "%s - Failed to open uevent socket\n", strerror(errno));
        return -1;
    }

    ret = setsockopt(sk_fd, SOL_SOCKET, SO_RCVBUF, &rcv_buf_sz,
                    sizeof(rcv_buf_sz));
    if (ret < 0) {
        fprintf(stderr, "%s - Failed to set socket options\n", strerror(errno));
        goto on_error;
    }

    sk_addr.nl_family = AF_NETLINK;
    sk_addr.nl_groups = __UEVENT_LISTEN_ALL;

    sk_addr_len = sizeof(sk_addr);
    ret = bind(sk_fd, (struct sockaddr *)&sk_addr, sk_addr_len);
    if (ret < 0) {
        fprintf(stderr, "%s - Failed to bind socket\n", strerror(errno));
        goto on_error;
    }

    ret = getsockname(sk_fd, (struct sockaddr *)&sk_addr, &sk_addr_len);
    if (ret < 0) {
        fprintf(stderr, "%s - Failed to retrieve socket name\n", strerror(errno));
        goto on_error;
    }

    if ((size_t)sk_addr_len != sizeof(sk_addr)) {
        fprintf(stderr, "Invalid socket address size\n");
        goto on_error;
    }

    listener->sk_fd = sk_fd;
    listener->thread = g_malloc0(sizeof(QemuThread));
    qemu_thread_create(listener->thread,
                       "spdm uevent listener",
                       listener->func, listener,
                       QEMU_THREAD_DETACHED);
    qemu_mutex_init(&listener->mutex);

    qemu_mutex_init(&spdmmgr_request.mutex);
    qemu_sem_init(&spdmmgr_request.sem, 0);

    printf("TDX service listener initialized.\n");
    return 0;

on_error:
    close(sk_fd);

    return ret;
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

static int tdx_serv_query(struct TdxEvent *event)
{
    struct tdx_serv_resp *serv_resp = (void *)event->resp;
    struct query_cmd *cmd = (void *)(event->cmd +
                               sizeof(struct tdx_serv_cmd));
    struct query_resp *resp = (void *)(event->resp +
                                 sizeof(struct tdx_serv_resp));

    if (qemu_uuid_is_equal(&cmd->guid, &tpa_guid)  ||
        qemu_uuid_is_equal(&cmd->guid, &spdm_guid) ||
        qemu_uuid_is_equal(&cmd->guid, &tdcm_guid)) {
        resp->status = QUERY_SERV_SUPPORT;
    } else {
        resp->status = QUERY_SERV_UNSUPPORT;
    }

    resp->version = 0;
    resp->command = 0;
    memcpy(&resp->guid, &cmd->guid, sizeof(QemuUUID));

    serv_resp->length = sizeof(struct tdx_serv_resp) +
                        sizeof(struct query_resp);

    event->done = true;
    return TDX_RESP_SERV;
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

static int tdx_serv_tpa_report_status(struct TdxEvent *event)
{
    struct tdx_serv_cmd *serv_cmd = (void *)event->cmd;
    struct tpa_report_status *report = (void *)(event->cmd +
                                       sizeof(struct tdx_serv_cmd));
    struct tdx_serv_resp *resp = (void *)event->resp;
    struct tpa_resp_hdr *tpa_resp = (void *)(event->resp +
                                    sizeof(struct tdx_serv_resp));
    struct SpdmDevRequest *req;
    uint32_t dev_info_size;
    int ret;

    DPRINTF("sizeof(struct tpa_report_status): %ld\n", sizeof(struct tpa_report_status));
    dump_memory((uint64_t)report, sizeof(struct tpa_report_status));

    qemu_mutex_lock(&spdmmgr_request.mutex);
    QLIST_FOREACH(req, &spdmmgr_request.req_list, list) {
        DPRINTF("req->id: 0x%llx,report->tpa_req_id: 0x%llx\n", req->id, report->tpa_req_id);
        if (req->id != report->tpa_req_id)
            continue;

        DPRINTF("req->status: %d\n", req->status);
        if (req->status == SPDM_DEV_REQ_DONE) {
            DPRINTF("Found req %p.\n", req);
            break;
        } else {
            DPRINTF("req %p has not been sent to TPA."
                    "request status %d.\n",
                    req, req->status);
            continue;
        }
    }
    qemu_mutex_unlock(&spdmmgr_request.mutex);

    if (!req || (req->status != SPDM_DEV_REQ_DONE)) {
        DPRINTF("No request found, invalid TpaRequestID 0x%llx.\n",
                report->tpa_req_id);
        resp->status = SERV_RESP_STS_INVLD_PARAM;
        goto report_status_done;
    }

    if ((report->operation == SPDM_SESS_REQ_START_SESSION) &&
        (report->status == SPDM_REQ_RET_SUCCESS)) {
        struct spdm_dev_info dev_info;

        /* Calculate the size of DEV_INFO_DATA */
        dev_info_size = serv_cmd->length -
                        sizeof(struct tdx_serv_cmd) -
                        sizeof(struct tpa_report_status);

        dev_info.size = dev_info_size;
        dev_info.data = report->dev_info_data;
        ret = ioctl(req->spdm_dev->fd, SPDM_SET_DEVICE_INFO, &dev_info);

        DPRINTF("req %p spdm_dev %p, dev_info_size 0x%x, dev_info_data %p\n",
                req, req->spdm_dev,
                dev_info_size, dev_info.data);
    }

    req->dev_req.result = report->status;

    /* Notify SPDM mananger device */
    ret = ioctl(req->spdm_dev->fd, SPDM_COMPLETE_REQUEST, &req->dev_req);
    if (!ret) {
        qemu_mutex_lock(&spdmmgr_request.mutex);
        QLIST_REMOVE(req, list);
        spdmmgr_request.req_num--;
        qemu_mutex_unlock(&spdmmgr_request.mutex);

        g_free(req);
    } else {
        DPRINTF("req %p, fail on SPDM_COMPLETE_REQUEST. ret %d.\n", req, ret);
    }

    /* The service request is done. */
    tdx_tpa_serv.status = TPA_SERV_REQ_DONE;

report_status_done:
    /* Fill response buffer */
    tpa_resp->version = 0;
    tpa_resp->command = TPA_CMD_REPORTSTATUS;
    resp->length += sizeof(struct tpa_resp_hdr);

    event->done = true;
    return TDX_RESP_SERV;
}

static int tdx_deinit_service(struct TdxService *tdx_service)
{
    if (!tdx_service)
        return -1;

    tdx_service->exit = 1;

    qemu_mutex_destroy(&tdx_service->mutex);
    qemu_sem_destroy(&tdx_service->sem);

    if (tdx_service->thread)
        g_free(tdx_service->thread);

    return 0;
}

static int tdx_services_deinit(void)
{
    struct SpdmDevice *spdm_dev;
    struct SpdmDevRequest *req;

    /* Common service */
    tdx_deinit_service(&tdx_dispatch_service);

    /* TPA-TD service  */
    if (is_tpa_td()) {
        tdx_deinit_service(&tdx_tpa_serv);
        tdx_deinit_service(&tdx_spdm_serv);

        QLIST_FOREACH(spdm_dev, &spdmmgr_listener.device_list, list) {
            close(spdm_dev->fd);
            g_free(spdm_dev->devpath);
            g_free(spdm_dev);
        }

        qemu_mutex_destroy(&spdmmgr_listener.mutex);
        g_free(spdmmgr_listener.thread);

        QLIST_FOREACH(req, &spdmmgr_request.req_list, list) {
            g_free(req);
        }

        qemu_mutex_destroy(&spdmmgr_request.mutex);
        qemu_sem_destroy(&spdmmgr_request.sem);
    }

    /* Normal-TD service  */

    return 0;
}

static void tdx_shutdown_service(void)
{
    char buf[128];
    FILE *pstr;
    int self_pid = getpid();

    sprintf(buf, "kill -9 %d", self_pid);
    pstr = popen(buf, "r");
    if(!pstr) {
        DPRINTF("Fail to shutdown %s!\n", TDX_SERVICE_NAME);
    }
    pclose(pstr);
    DPRINTF("Shutdown %s!\n", TDX_SERVICE_NAME);

    return;
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

static int tdx_serv_tpa(struct TdxEvent *event)
{
    struct tdx_serv_resp *resp = (void *)event->resp;
    struct tpa_cmd_hdr *tpa_cmd = (void *)(event->cmd +
                                  sizeof(struct tdx_serv_cmd));
    int ret = TDX_RESP_SERV;

    DPRINTF("cmd: %d\n", tpa_cmd->command);

    switch (tpa_cmd->command) {
    case TPA_CMD_SHUTDOWN:
        tdx_tpa_serv.status = TPA_SERV_SHUTDOWN;
        event->done = true;
        ret = TDX_NOT_RESP_SERV;

        /* Shutdown TPA, de-initialize TDX services.*/
        tdx_services_deinit();

        DPRINTF("shutdown TPA......\n");
        /* Sleep to output the log. */
        sleep(5);

        tdx_shutdown_service();
        break;
    case TPA_CMD_WAITFORREQUEST:
        if (tdx_tpa_serv.status == TPA_SERV_WAITFORREQUEST) {
            DPRINTF("TPA is waiting for one request.\n"
                    "Should not send another TPA_WAITFORREQUEST!\n");
            break;
        } else
            tdx_tpa_serv.status = TPA_SERV_WAITFORREQUEST;

        DPRINTF("tdx_tpa_serv.status: %d\n", tdx_tpa_serv.status);

        /* queue the event:
         * TDX service thread gets messages from
         * the queue to handle many requests.
         * Trigger TPA service to handle.
         */
        if (event->notify)
            tdx_queue_service(&tdx_tpa_serv, event);
        else
            tdx_serv_tpa_handle(event);

        /* Just send the signal to wake up the TPA service thread.
         * TPA service thread will wait for requests and
         * sends reponse to TPA after completing the request.
         * So at this point, no need to send reponse to TPA.
         */
        ret = TDX_NOT_RESP_SERV;

        break;
    case TPA_CMD_REPORTSTATUS:
        tdx_tpa_serv.status = TPA_SERV_REPORTSTATUS;
        ret = tdx_serv_tpa_report_status(event);
        break;
    default:
        resp->status = SERV_RESP_STS_UNSUPPORT;
        event->done = true;
        break;
    }

    return ret;
}

static int tdx_serv_spdm(struct TdxEvent *event)
{
    struct tdx_serv_resp *resp = (void *)event->resp;
    struct spdm_cmd_hdr *spdm_cmd = (void *)(event->cmd +
                                    sizeof(struct tdx_serv_cmd));

    DPRINTF("cmd: %d\n", spdm_cmd->command);
    switch (spdm_cmd->command) {
    case SPDM_CMD_PCIDOE:
        /* Wake up the service thread to handle this SPDM command.
         * Handle this SPDM command request with the lock of tdx service mutex,
         * so no need to lock at this point(otherwise double mutex lock).
         */
        if (event->notify)
            tdx_queue_service(&tdx_spdm_serv, event);
        else
            tdx_serv_spdm_handle(event);
        return TDX_NOT_RESP_SERV;
    default:
        event->done = true;
        resp->status = SERV_RESP_STS_UNSUPPORT;
        break;
    }

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

    if (is_tpa_td()) {
        if (qemu_uuid_is_equal(&cmd->guid, &query_guid)) {
            ret = tdx_serv_query(event);
        } else if (qemu_uuid_is_equal(&cmd->guid, &tpa_guid)) {
            ret = tdx_serv_tpa(event);
        } else if (qemu_uuid_is_equal(&cmd->guid, &spdm_guid)) {
            ret = tdx_serv_spdm(event);
        } else {
            resp->status = SERV_RESP_STS_UNSUPPORT;
            event->done = true;
        }
    } else {
        if (qemu_uuid_is_equal(&cmd->guid, &tdcm_guid)) {
            ret = tdx_serv_tdcm(event);
        } else {
            resp->status = SERV_RESP_STS_UNSUPPORT;
            event->done = true;
        }
    }

    return ret;
}

static void tdx_serv_fill_hob_list(struct TdxEvent *event,
                                   struct SpdmDevRequest *req)
{
    struct tdx_serv_resp *resp = (void *)event->resp;
    struct tpa_resp_hdr *tpa_resp = (void *)((uint64_t)resp +
                                    sizeof(struct tdx_serv_resp));
    uint8_t *hob_list = (void *)((uint64_t)tpa_resp +
                        sizeof(struct tpa_resp_hdr));
    TpaDeviceInformation *tpa_dev_info = (void *)hob_list;
    EFI_HOB_GENERIC_HEADER *end_hob;
    struct spdm_arch_sess_info *dev_info;
    uint32_t hdr_size, hob_len;

    DPRINTF("resp: 0x%lx, tpa_resp: 0x%lx, hob_list: 0x%lx, tpa_dev_info: 0x%lx\n",
            (uint64_t)resp, (uint64_t)tpa_resp, (uint64_t)hob_list, (uint64_t)tpa_dev_info);

    hdr_size = sizeof(struct tdx_serv_resp) +
               sizeof(struct tpa_resp_hdr);

    /* Fill TPA device information HOB. */
    hob_len = sizeof(*tpa_dev_info);
    tpa_dev_info->header.HobType = EFI_HOB_TYPE_GUID_EXTENSION;
    tpa_dev_info->header.HobLength = hob_len;
    tpa_dev_info->header.Reserved = 0;
    memcpy(&tpa_dev_info->guid, &tpa_dev_info_hob_guid, sizeof(QemuUUID));

    tpa_dev_info->StructVersion = 0x00010000;
    tpa_dev_info->TpaRequestID = req->id;

    dev_info = (struct spdm_arch_sess_info *)req->dev_req.arch_data;
    tpa_dev_info->DeviceID = dev_info->device_id;
    tpa_dev_info->IommuID = dev_info->iommu_id;
    tpa_dev_info->SpdmSessionIndex = dev_info->session_idx;

    /* TODO: Get from SPDM ? No need for start session. */
    memcpy(tpa_dev_info->TpaRequestNonce,
           req->spdm_dev->tpa_request_nonce, TPA_REQUEST_NONCE_LEN);

    /* Align on 8 bytes according to PI spec 4.5.2. */
    hob_len = QEMU_ALIGN_UP(hob_len, 8);

    DPRINTF("hob_len: 0x%x, tpa_resp->operation: %d, sizeof(operation): %ld\n",
            hob_len, tpa_resp->operation, sizeof(tpa_resp->operation));
    switch (tpa_resp->operation) {
    case SPDM_SESS_REQ_START_SESSION: {
        TpaSpdmPolicy *tpa_spdm_policy =
                (void *)((uint64_t)tpa_dev_info + hob_len);
        TpaTdispPolicy *tpa_tdisp_policy;
        uint32_t len;

        /* Fill TPA SPDM policy HOB. */
        len = sizeof(*tpa_spdm_policy);
        tpa_spdm_policy->header.HobType = EFI_HOB_TYPE_GUID_EXTENSION;
        tpa_spdm_policy->header.HobLength = len;
        tpa_spdm_policy->header.Reserved = 0;
        memcpy(&tpa_spdm_policy->guid,
               &tpa_spdm_policy_hob_guid, sizeof(QemuUUID));

        tpa_spdm_policy->StructVersion = 0x00010000;
        tpa_spdm_policy->SessionPolicy =
            req->dev_req.policy.session_policy;
        tpa_spdm_policy->MeasurementRequestAttributes =
            req->dev_req.policy.meas_req_attr;

        len = QEMU_ALIGN_UP(len, 8);
        hob_len += len;

        /* Fill TPA TDISP policy HOB. */
        tpa_tdisp_policy = (void *)((uint64_t)tpa_spdm_policy + len);

        DPRINTF("hob_len: 0x%x, tpa_spdm_policy: 0x%lx, tpa_tdisp_policy: 0x%lx\n",
                hob_len, (uint64_t)tpa_spdm_policy, (uint64_t)tpa_tdisp_policy);

        len = sizeof(*tpa_tdisp_policy);
        tpa_tdisp_policy->header.HobType = EFI_HOB_TYPE_GUID_EXTENSION;
        tpa_tdisp_policy->header.HobLength = len;
        tpa_tdisp_policy->header.Reserved = 0;
        memcpy(&tpa_tdisp_policy->guid,
               &tpa_tdisp_policy_hob_guid, sizeof(QemuUUID));

        tpa_tdisp_policy->StructVersion = 0x00010000;
        memset(tpa_tdisp_policy->TdispCapabilities, 0, 4);

        len = QEMU_ALIGN_UP(len, 8);
        hob_len += len;

        break;
    }
    case SPDM_SESS_REQ_END_SESSION:
    case SPDM_SESS_REQ_KEY_UPDATE:
    case SPDM_SESS_REQ_HEARTBEAT:
    case SPDM_MGR_REQ_RECOLLECT: {
        /* TODO: Check if need to perform runtime update.
         * Fill DEVICE_INFO_DATA HOB.
         */
#if 0
        uint8_t *dev_info_data = (void *)((uint64_t)tpa_dev_info +
                                 sizeof(*tpa_dev_info));
        struct spdm_dev_info dev_info;
        uint32_t len;
        int ret;

        ret = ioctl(req->spdm_dev->fd, SPDM_GET_DEVICE_INFO_SIZE, &dev_info.size);
        if (!ret) {
            DPRINTF("SPDM dev %p, fail to get device info size. ret %d\n",
                    req->spdm_dev, ret);
            break;
        }

        len = resp->length - hdr_size;
        if (dev_info.size > len) {
            DPRINTF("No enough response buffer 0x%x for DEV_INFO_DATA 0x%x.\n",
                    len, dev_info.size);

            /* Response buffer is too small. */
            resp->status = SERV_RESP_STS_BUF_SMALL;
        }

        dev_info.data = dev_info_data;
        ret = ioctl(req->spdm_dev->fd, SPDM_GET_DEVICE_INFO, &dev_info);
        if (!ret) {
            DPRINTF("SPDM dev %p, fail to get dev info data. ret %d\n",
                    req->spdm_dev, ret);
            resp->status = SERV_RESP_STS_DEV_ERR;
        } else {
            hob_len += sizeof(dev_info.size);
        }
#endif
        break;
    }
    default:
        DPRINTF("Invalid TPA request operation %d.\n", tpa_resp->operation);
        resp->status = SERV_RESP_STS_UNSUPPORT;
        break;
    }

    /* construct the end HOB  */
    end_hob = (void *)(hob_list + hob_len);
    DPRINTF("end_hob: 0x%lx, hob_len: 0x%x\n", (uint64_t)end_hob, hob_len);

    end_hob->HobType = EFI_HOB_TYPE_END_OF_HOB_LIST;
    end_hob->HobLength = sizeof(*end_hob);
    hob_len += sizeof(*end_hob);

    DPRINTF("end_hob: 0x%lx, hob_len: 0x%x\n", (uint64_t)end_hob, hob_len);

    resp->length = hdr_size + hob_len;
    return;
}

static void tdx_serv_tpa_handle(struct TdxEvent *event)
{
    struct tdx_serv_resp *resp = (void *)event->resp;
    struct tpa_resp_hdr *tpa_resp = (void *)((uint64_t)resp +
                                    sizeof(struct tdx_serv_resp));
    struct SpdmDevRequest *req = NULL;

    /* Get one SPDM request per command TPA_CMD_WAITFORREQUEST. */

wait_for_request:
    qemu_sem_wait(&spdmmgr_request.sem);

    qemu_mutex_lock(&spdmmgr_request.mutex);
    if (spdmmgr_request.req_num) {
        QLIST_FOREACH(req, &spdmmgr_request.req_list, list) {
            if (req->status == SPDM_DEV_REQ_DONE)
                continue;

            /* Only handle one request per TPA_CMD_WAITFORREQUEST. */
            break;
        }
    } else {
        DPRINTF("%s: No SPDM request!\n", __func__);
    }
    qemu_mutex_unlock(&spdmmgr_request.mutex);

    if (!req) {
        DPRINTF("No request! Waiting ...\n");
        goto wait_for_request;
    }

    /* Fill Service TPA response buffer. */

    tpa_resp->version = 0;
    tpa_resp->command = TPA_CMD_WAITFORREQUEST;
    tpa_resp->operation = req->dev_req.request;

    /* Fill HOB list */
    tdx_serv_fill_hob_list(event, req);
    event->done = true;

    dump_memory((uint64_t)resp, resp->length);
    req->status = SPDM_DEV_REQ_DONE;
    DPRINTF("req->id: 0x%llx,req->status: %d\n", req->id, req->status);

    return;
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

static void tdx_queue_request(struct SpdmDevRequest *request)
{
    qemu_mutex_lock(&spdmmgr_request.mutex);
    QLIST_INSERT_HEAD(&spdmmgr_request.req_list, request, list);
    spdmmgr_request.req_num++;
    qemu_mutex_unlock(&spdmmgr_request.mutex);

    qemu_sem_post(&spdmmgr_request.sem);

    DPRINTF("request num %u, queue request %p\n",
            spdmmgr_request.req_num, request);
}

static void tdx_serv_request_handler(void *opaque)
{
    struct SpdmDevice *spdm_dev = (struct SpdmDevice *)opaque;
    struct spdm_arch_sess_info *dev_info;
    struct SpdmDevRequest *req;
    int ret;

    if (!event_notifier_test_and_clear(&tdx_spdmmgr_notifier)) {
        fprintf(stderr, "Fail to read SPDM event notifier!\n");
        return;
    }
    /* Get one request every time. */
    req = g_malloc0(sizeof(struct SpdmDevRequest));
    if (!req) {
        fprintf(stderr, "Fail to malloc spdm request!\n");
        return;
    }

    ret = ioctl(spdm_dev->fd, SPDM_GET_REQUEST, &req->dev_req);
    if (ret < 0) {
        fprintf(stderr, "Fail to get spdm request!\n");
        return;
    }

    dev_info = (struct spdm_arch_sess_info *)req->dev_req.arch_data;
    spdm_dev->devid = dev_info->device_id;
    spdm_dev->iommu_id = dev_info->iommu_id;

    /* Fill it in TpaRequestID,
     * which is used to uniquely identify this request.
     * It is used in TDG.VP.VMCALL <Service.TPA.ReportStatus>.
     * Just using the address of this request.
     */
    req->id = (uint64_t)req;
    req->spdm_dev = spdm_dev;
    req->status = SPDM_DEV_REQ_PENDING;

    tdx_queue_request(req);

    return;
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

static void *tdx_tpa_serv_thread_fn(void *arg)
{
    struct TdxService *service = arg;
    struct TdxEvent *event;

wait_tpa_request:
    qemu_sem_wait(&service->sem);

    if ((service->status != TPA_SERV_WAITFORREQUEST) ||
        (service->event_num == 0))
        goto wait_tpa_request;

    /*
     * TPA only processes one command to repond per TPA_CMD_WAITFORREQUEST.
     * TPA will send another TPA_CMD_WAITFORREQUEST after
     * receiving the last response of TPA_CMD_WAITFORREQUEST.
     * So before the completion of last command,
     * another TPA_CMD_WAITFORREQUEST should not be received.
     */
    qemu_mutex_lock(&service->mutex);
    if (!QLIST_EMPTY(&service->event_list)) {
        event = QLIST_FIRST(&service->event_list);
        QLIST_REMOVE(event, list);
        service->event_num--;
    } else {
        qemu_mutex_unlock(&service->mutex);
        goto wait_tpa;
    }
    qemu_mutex_unlock(&service->mutex);

    tdx_serv_tpa_handle(event);

    /* copy response data back */
    if (address_space_write(
        &address_space_memory, event->resp_gpa,
        MEMTXATTRS_UNSPECIFIED, (void*)event->resp,
        ((struct tdx_serv_resp *)event->resp)->length) !=
            MEMTX_OK) {
        printf("%s: write resp buf failed\n", __func__);
    }
    /* Inject interrupt to notify TPA to get response. */
    async_run_on_cpu(event->cpu, tdx_inject_notification,
                    RUN_ON_CPU_HOST_PTR(event));

    DPRINTF("%s: event %p, inject interrupt to notify TPA.\n", __func__, event);
    service->status = TPA_SERV_REQ_DONE;

wait_tpa:
    if (!service->exit) {
        goto wait_tpa_request;
    }

    return NULL;
}

static int tdx_serv_spdm_handle(struct TdxEvent *event)
{
    struct tdx_serv_cmd *cmd = (void *)event->cmd;
    struct tdx_serv_resp *resp = (void *)event->resp;
    int serv_cmd_hdr_size = sizeof(struct tdx_serv_cmd);
    int serv_resp_hdr_size = sizeof(struct tdx_serv_resp);

    struct spdm_cmd_hdr *spdm_cmd = (void *)(event->cmd +
                                    serv_cmd_hdr_size);
    struct spdm_resp_hdr *spdm_resp = (void *)(event->resp +
                                      serv_resp_hdr_size);
    int spdm_cmd_hdr_size = sizeof(struct spdm_cmd_hdr);
    int spdm_resp_hdr_size = sizeof(struct spdm_resp_hdr);

    struct SpdmDevice *spdm_dev = NULL;
    struct spdm_message message = { 0 };
    uint32_t resp_size;
    int ret;

    /* The response GUID is filled by TD. */
    memcpy(&resp->guid, &cmd->guid, sizeof(QemuUUID));

    /* Get SPDM command requests from SPDM manager devices.
     * Including:
     * GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS ......
     */

    /* Go through the SPDM devices to check the device ID. */
    qemu_mutex_lock(&spdmmgr_listener.mutex);
    QLIST_FOREACH(spdm_dev, &spdmmgr_listener.device_list, list) {
        if (spdm_dev->devid == spdm_cmd->devid)
            break;
    }
    qemu_mutex_unlock(&spdmmgr_listener.mutex);

    if (!spdm_dev) {
        DPRINTF("No SPDM device found. devid 0x%x\n", spdm_cmd->devid);
        resp->status = SERV_RESP_STS_OUT_OF_RES;
        return TDX_NOT_RESP_SERV;
    }

    /* No need to parse the SPDM buffer,
     * just fill message size and address,
     * then forward to SPDM manager.
     * Currently, message.flags is not used.
     */
    message.req_size = cmd->length -
                       serv_cmd_hdr_size -
                       spdm_cmd_hdr_size;
    message.req_addr = (uint64_t)spdm_cmd +
                       spdm_cmd_hdr_size;

    message.resp_size = resp->length -
                        serv_resp_hdr_size -
                        spdm_resp_hdr_size;
    message.resp_addr = (uint64_t)spdm_resp +
                        spdm_resp_hdr_size;

    /* save the response size from TPA */
    resp_size = message.resp_size;

    spdm_resp->version = 0;
    spdm_resp->command = SPDM_CMD_PCIDOE;
    spdm_resp->devid = spdm_cmd->devid;
    resp->length = serv_resp_hdr_size +
                   sizeof(*spdm_resp);
    DPRINTF("resp->length: 0x%x\n", resp->length);

    ret = ioctl(spdm_dev->fd, SPDM_MSG_EXCHANGE, &message);
    if (ret) {
        DPRINTF("Fail on SPDM_MSG_EXCHANGE. ret %d\n", ret);
        resp->status = message.status;
    } else {
        /* Check if resp_size in the message
         * is greater than response buffer size.
         */
        if (message.resp_size <= resp_size)
            resp->length += message.resp_size;
        else
            resp->length += resp_size;

        DPRINTF("resp->length: 0x%x, ioctl SPDM resp_size: 0x%x\n",
                resp->length, message.resp_size);
        resp->status = SERV_RESP_STS_RETURN;
    }

    event->done = true;
    return TDX_RESP_SERV;
}

static void *tdx_spdm_serv_thread_fn(void *arg)
{
    struct TdxService *service = arg;
    struct TdxEvent *event;
    int ret;

wait_spdm_cmd:
    qemu_sem_wait(&service->sem);

    qemu_mutex_lock(&service->mutex);
    if (!QLIST_EMPTY(&service->event_list)) {
        event = QLIST_FIRST(&service->event_list);
        QLIST_REMOVE(event, list);
        service->event_num--;
    } else {
        qemu_mutex_unlock(&service->mutex);
        goto wait_spdm;
    }
    qemu_mutex_unlock(&service->mutex);

    ret = tdx_serv_spdm_handle(event);

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
        DPRINTF("%s: SPDM event %p is done,\n"
                " inject interrupt to notify TPA.\n",
                __func__, event);
    }

wait_spdm:
    if (!service->exit) {
        goto wait_spdm_cmd;
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

    /* TPA-TD service */
    if (is_tpa_td()) {
        ret = tdx_init_service(&tdx_tpa_serv);
        if (ret < 0) {
            fprintf(stderr, "kvm: Failed to initialize TPA service. %d\n", ret);
            return ret;
        }
        ret = tdx_init_service(&tdx_spdm_serv);
        if (ret < 0) {
            fprintf(stderr, "kvm: Failed to initialize SPDM service. %d\n", ret);
            return ret;
        }

        /* Get an eventfd for trigger. */
        ret = event_notifier_init(&tdx_spdmmgr_notifier, false);
        if (ret) {
            fprintf(stderr, "kvm: Failed to initialize trigger eventfd notifier.");
            return ret;
        }

        tdx_spdmmgr_eventfd = event_notifier_get_fd(&tdx_spdmmgr_notifier);
        DPRINTF("tdx_spdmmgr_eventfd %d\n", tdx_spdmmgr_eventfd);

        ret = tdx_spdmmgr_listener_init(&spdmmgr_listener);
        if (ret < 0) {
            fprintf(stderr, "kvm: Failed to initialize the SPDM uevent listener.");
            return ret;
        }
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
