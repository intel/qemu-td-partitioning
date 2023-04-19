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
#include <linux/tdisp_mgr.h>
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

/* TDG.VP.VMCALL <Service.TPA> command header */
struct tpa_cmd_hdr {
    __u8 version;
    __u8 command;
    __u16 reserved;
};

/* TDG.VP.VMCALL <Service.Query> response buffer */
struct query_resp {
    __u8 version;
    __u8 command;
    __u8 status;
    __u8 reserved;
    QemuUUID guid;
};

/* TDG.VP.VMCALL <Service.TPA> response header */
struct tpa_resp_hdr {
    __u8 version;
    __u8 command;
    __u8 operation;
    __u8 reserved;
};

struct tpa_report_status {
    __u8 version;
    __u8 command;

    /* It's same as the "Operation" in command
     * TDG.VP.VMCALL <Service.TPA.WaitForRequest>
     */
    __u8 operation;

    /* It's the result of the request in last command
     * TDG.VP.VMCALL <Service.TPA.WaitForRequest>
     */
    __u8 status;

    __u64 tpa_req_id;
    __u8 dev_info_data[0];
};

/* TDG.VP.VMCALL <Service.SPDM> command header */
struct spdm_cmd_hdr {
    __u8 version;
    __u8 command;
    __u16 reserved;
    __u32 devid;
};

/* TDG.VP.VMCALL <Service.SPDM> response header */
struct spdm_resp_hdr {
    __u8 version;
    __u8 command;
    __u16 reserved;
    __u32 devid;
};

/* TDG.VP.VMCALL <Service.TDCM> command header */
struct tdcm_cmd_hdr {
    struct tdx_serv_cmd cmd;
    __u8 version;
    __u8 command;
#define TDCM_CMD_GET_DEV_CTX    0
#define TDCM_CMD_TDISP          1
#define TDCM_CMD_MAP_DMA_GPA    2
#define TDCM_CMD_GET_DEV_INFO   3
    __u16 reserved;
    __u32 devid;
};

/* TDG.VP.VMCALL <Service.TDCM> response header */
struct tdcm_resp_hdr {
    struct tdx_serv_resp resp;
    __u8 version;
    __u8 command;
    __u8 status;
#define TDCM_RESP_STS_OK   0
#define TDCM_RESP_STS_FAIL 1
    __u8 reserved;
};

/* TDG.VP.VMCALL <Service.TDCM.GetDeviceContext> command */
struct tdcm_cmd_get_dev_ctx {
    struct tdcm_cmd_hdr hdr;
};

/* TDG.VP.VMCALL <Service.TDCM.GetDeviceContext> response */
struct tdcm_resp_get_dev_ctx {
    struct tdcm_resp_hdr hdr;
    __u32 func_id;
    __u64 rsvd;
    __u64 nonce[4];
};

/* TDG.VP.VMCALL <Service.TDCM.TDISP> command */
struct tdcm_cmd_tdisp {
    struct tdcm_cmd_hdr hdr;
};

/* TDG.VP.VMCALL <Service.TDCM.DEVIF> response */
struct tdcm_resp_tdisp {
    struct tdcm_resp_hdr hdr;
};

/* TDG.VP.VMCALL <Service.TDCM.GetDeviceInfo> command */
struct tdcm_cmd_get_dev_info {
    struct tdcm_cmd_hdr hdr;
    __u8 tpa_request_nonce[TPA_REQUEST_NONCE_LEN];
};

/* TDG.VP.VMCALL <Service.TDCM.GetDeviceInfo> response */
struct tdcm_resp_get_dev_info {
    struct tdcm_resp_hdr hdr;
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

struct TdispMgr {
    int cfd;
    int index;
    __u32 devid;
    __u32 iommu_id;
    __u32 session_idx;
    __u64 handle;

#if 0
    /* It's included in the response buffer
     * in TDG.VP.VMCALL <Service.TDCM.GetDeviceInfo>.
     */
    __u8 *dev_info_data;
    __u32 dev_info_size;
#endif

    /* It's included in the command buffer
     * in TDG.VP.VMCALL<Service.TDVM.GetDeviceInfo>.
     */
    __u8 tpa_request_nonce[32];

    char *devpath;
    QLIST_ENTRY(TdispMgr) list;
};

struct TdispMgrRequest {
    struct tmgr_request treq;
    __u64 id;
    struct TdispMgr *tmgr;
#define TMGR_REQ_PENDING    0
#define TMGR_REQ_QUEUED     1
#define TMGR_REQ_DONE       2
    int status;
    QLIST_ENTRY(TdispMgrRequest) list;
};

struct TdispMgrListener {
    QemuThread *thread;
    QemuMutex mutex;
    int sk_fd;
    __u32 tmgr_num;
    QLIST_HEAD(, TdispMgr) tmgr_list;
    thread_func *func;
};

struct TdispMgrReqList {
    QemuSemaphore sem;
    QemuMutex mutex;
    QLIST_HEAD(, TdispMgrRequest) tmreq_list;
    __u32 tmreq_num;
};

#define EFI_HOB_TYPE_GUID_EXTENSION  0x0004
#define EFI_HOB_TYPE_END_OF_HOB_LIST 0xffff

typedef struct _EFI_HOB_GENERIC_HEADER{
    __u16 HobType;
    __u16 HobLength;
    __u32 Reserved;
} EFI_HOB_GENERIC_HEADER;

typedef struct {
    EFI_HOB_GENERIC_HEADER header;
    QemuUUID guid;

    /* The version of this structure. 0x00010000. */
    __u32 StructVersion;

    /* TpaRequestID: The ID for the TPA request.
     * It is used in TDG.VP.VMCALL <Service.TPA.ReportStatus>.
     */
    __u64 TpaRequestID;

    /* DeviceID: The ID for the device.
     * Byte 0 (Bit[0~2]): PCI Function Number;
     * Byte 0 (Bit[3~7]): PCI Device Number;
     * BYTE 1: PCI Bus Number;
     * BYTE 2, 3: PCI Segment Number.
     * It is used in TDG.VP.VMCALL<Service.SPDM>.
     */
    __u32 DeviceID;
    /* IommuID: The IOMMU hosting the stream.
     * It is used in TDCALL[TDG.SPDM.SETBINDING] and
     * TDCALL[TDG.STREAM.GETBINDING].
     */
    __u32 FunctionID;
    __u64 Reserved;
    __u32 IommuID;
    /* SpdmSessionIndex: SPDM session index of device connected to stream.
     * It is used in TDCALL[TDG.SPDM.SETBINDING] and
     * TDCALL[TDG.STREAM.GETBINDING].
     */
    __u32 SpdmSessionIndex;

    /* A nonce value to indicate the device info recollection.
     * It is included in DEVICE_INFO_DATA.
     * If the VMM performs Device Info Recollection operation,
     * VMM shall take the nonce from TD in TDG.VP.VMCALL<Service.TDVM.GetDeviceInfo>.
     * A TD may use this nonce to verify if the VMM performs the recollection.
     * For other operations, the nonce value could be all 0.
     */
    __u8 TpaRequestNonce[32];
} TpaDeviceInformation;

typedef struct {
    EFI_HOB_GENERIC_HEADER header;
    QemuUUID guid;

    /* StructVersion: The version of this SPDM_POLICY structure.
     * 0x00010000 for this structure definition.
     */
    __u32 StructVersion;
    __u8 SpdmVersionNumberEntryCount;
    __u16 SpdmVersionNumberEntry;
    /* MeasurementRequestAttributes:
     * The SPDM measurement request attributes used in GET_MEASUREMENT.
     * This field includes RawBitStreamRequested.
     * This field is only valid for SpdmVersion >= 1.2.
     * SignatureRequested is ignored,
     * because TPA shall always set for the last message.
     */
    __u8 MeasurementRequestAttributes;
    /* SessionPolicy: The SPDM session policy used in KEY_EXCHANGE.
     * This field includes TerminationPolicy.
     * This field is only valid for SpdmVersion >= 1.2.
     */
    __u8 SessionPolicy;
} TpaSpdmPolicy;

typedef struct {
    EFI_HOB_GENERIC_HEADER header;
    QemuUUID guid;

    __u32 StructVersion;
    __u8  TdispVersionNumCount;
    __u8  TdispVersionNum;
    __u8  TdispCapabilities[4];
} TpaTdispPolicy;

#pragma pack(pop)

int tdx_services_init(void);
void tdx_handle_service(X86CPU *cpu, struct kvm_tdx_vmcall
                               *vmcall);

extern bool tdx_service_init;

#endif
