/*
 * Common TDX service header for tdxio based device support
 * Authors:
 *  Jingqi Liu   <jingqi.liu@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef _TDXIO_H
#define _TDXIO_H

#include <poll.h>
#include <linux/kvm.h>
#include "qemu/uuid.h"

/* Status of Service Response */
#define SERV_RESP_STS_RETURN            0
#define SERV_RESP_STS_DEV_ERR           1
#define SERV_RESP_STS_TIMEOUT           2
#define SERV_RESP_STS_BUF_SMALL         3
#define SERV_RESP_STS_BAD_CMD_BUF_SZ    4
#define SERV_RESP_STS_BAD_RESP_BUF_SZ   5
#define SERV_RESP_STS_SERV_BUSY         6
#define SERV_RESP_STS_INVLD_PARAM       7
#define SERV_RESP_STS_OUT_OF_RES        8
#define SERV_RESP_STS_UNSUPPORT         0xFFFFFFFE
#define SERV_RESP_STS_RESERVE           0xFFFFFFFF

/* Service TPA Commands */
#define TPA_CMD_SHUTDOWN         0
#define TPA_CMD_WAITFORREQUEST   1
#define TPA_CMD_REPORTSTATUS     2

/* Service SPDM Command */
#define SPDM_CMD_PCIDOE          0

/* Status of TDX Query Service */
#define QUERY_SERV_SUPPORT       0
#define QUERY_SERV_UNSUPPORT     1

/* Status of TDX TPA Service */
#define TPA_SERV_READY           0
#define TPA_SERV_WAITFORREQUEST  1
#define TPA_SERV_REPORTSTATUS    2
#define TPA_SERV_SHUTDOWN        3
#define TPA_SERV_REQ_DONE        4

/* Whether the service needs response. */
#define TDX_RESP_SERV            0
#define TDX_NOT_RESP_SERV        1

#define TPA_REQUEST_NONCE_LEN    32

/* TerminationPolicy */
#define SPDM_TERMINATION_POLICY   1

#pragma pack(push, 1)


/* TDG.VP.VMCALL <Service> command header */
struct tdx_serv_cmd {
    QemuUUID guid;
    __u32 length;
    __u32 rsvd;
};

/* TDG.VP.VMCALL <Service> response header */
struct tdx_serv_resp {
    QemuUUID guid;
    __u32 length;
    __u32 status;
};

/* TDG.VP.VMCALL <Service.Query> command buffer */
struct query_cmd {
    __u8 version;
    __u8 command;
    __u16 reserved;
    QemuUUID guid;
};

/* TDG.VP.VMCALL <Service.Query> response buffer */
struct query_resp {
    __u8 version;
    __u8 command;
    __u8 status;
    __u8 reserved;
    QemuUUID guid;
};

/* TDG.VP.VMCALL <Service.TDCM> command header */
struct tdcm_cmd_hdr {
    __u8 version;
    __u8 command;
#define TDCM_CMD_GET_DEV_HANDLE 0
#define TDCM_CMD_TDISP          1
#define TDCM_CMD_MAP_DMA_GPA    2
#define TDCM_CMD_GET_DEV_INFO   3

    __u16 reserved;
};

/* TDG.VP.VMCALL <Service.TDCM> response header */
struct tdcm_resp_hdr {
    __u8 version;
    __u8 command;
    __u8 status;
#define TDCM_RESP_STS_OK   0
#define TDCM_RESP_STS_FAIL 1

    __u8 reserved;
};

/* TDG.VP.VMCALL <Service.TDCM.GetDeviceHandle> command */
struct tdcm_cmd_get_dev_handle {
    struct tdx_serv_cmd cmd;
    struct tdcm_cmd_hdr hdr;
    __u32 devid;
};

/* TDG.VP.VMCALL <Service.TDCM.GetDeviceHandle> response */
struct tdcm_resp_get_dev_handle {
    struct tdx_serv_resp resp;
    struct tdcm_resp_hdr hdr;
    __u64 dev_handle;
};

/* TDG.VP.VMCALL <Service.TDCM.DEVIF> command */
struct tdcm_cmd_devif {
    struct tdx_serv_cmd cmd;
    struct tdcm_cmd_hdr hdr;
    __u64 dev_handle;
    __u64 req_param;
    __u64 req_info;
};

/* TDG.VP.VMCALL <Service.TDCM.DEVIF> response */
struct tdcm_resp_devif {
    struct tdx_serv_resp resp;
    struct tdcm_resp_hdr hdr;
    __u64 dev_handle;
};

/* TDG.VP.VMCALL <Service.TDCM.GetDeviceInfo> command */
struct tdcm_cmd_get_dev_info {
    struct tdx_serv_cmd cmd;
    struct tdcm_cmd_hdr hdr;
    __u64 dev_handle;
    __u8 tpa_request_nonce[TPA_REQUEST_NONCE_LEN];
};

/* TDG.VP.VMCALL <Service.TDCM.GetDeviceInfo> response */
struct tdcm_resp_get_dev_info {
    struct tdx_serv_resp resp;
    struct tdcm_resp_hdr hdr;
    __u64 dev_handle;
    __u8 dev_info_data[0];
};

struct TdxEvent {
    CPUState *cpu;
    __u64 service;
    __u64 cmd;
    __u64 resp;
    __u64 notify;
    __u64 timeout;
    hwaddr resp_gpa;
    bool done;
    QLIST_ENTRY(TdxEvent) list;
};

typedef void *thread_func(void *);

struct TdxService {
    char name[20];
    QemuThread *thread;
    QemuSemaphore sem;
    QemuMutex mutex;
    QLIST_HEAD(, TdxEvent) event_list;
    thread_func *func;
    int event_num;
    __u32 exit;
    __u32 status;
};
#pragma pack(pop)

int tdx_services_init(void);
void tdx_handle_service(X86CPU *cpu, struct kvm_tdx_vmcall
                               *vmcall);

extern bool tdx_service_init;

#endif
