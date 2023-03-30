/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SPDM_H
#define _UAPI_LINUX_SPDM_H

#include <linux/ioctl.h>

#pragma pack(push, 1)

struct spdm_session_policy {
    __u8 meas_req_attr;
    __u8 session_policy;
};

struct spdm_arch_sess_info {
        __u32 device_id;
        __u32 iommu_id;
        __u32 session_idx;
};

struct spdm_request {
    __u8 request;
    __u8 result;

    struct spdm_session_policy policy;

    /* Used to store archtecture related data */
    __u64 arch_data[8];
};

struct spdm_dev_info {
    __u32 size;
    __u8 *data;
};

enum SPDM_MESSAGE_STATUS {
    SPDM_MSG_STATUS_SUCCESS             = 0,
    SPDM_MSG_STATUS_DEVICE_ERROR        = 1,
    SPDM_MSG_STATUS_TIMEOUT             = 2,
    SPDM_MSG_STATUS_RESP_BUF_SMALL      = 3,
    SPDM_MSG_STATUS_BAD_COM_BUF_SIZE    = 4,
    SPDM_MSG_STATUS_BAD_RESP_BUF_SIZE   = 5,
    SPDM_MSG_STATUS_SERVICE_BUSY        = 6,
    SPDM_MSG_STATUS_INVALID_PARAM       = 7,
    SPDM_MSG_STATUS_OUT_OF_RESOURCE     = 8,
};

struct spdm_message {
    __u32 flags;
    __u32 status;
    __u32 req_size;
    __u32 resp_size;

    __u64 req_addr;
    __u64 resp_addr;
};

struct spdm_eventfd {
    /*
     * fd <  0:
     * spdm manager will put current eventfd_ctx.
     * fd >= 0:
     * spdm manager will try to get the eventfd_ctx of fd.
     */
    __s32 fd;
};
#pragma pack(pop)

#define SPDM_MAGIC 0xB8

#define SPDM_BASE   0X0
#define SPDM_USER_BASE  0x80

/* Common IOCTLs for both userspace agent and spdm user interfaces */

/**
 * SPDM_GET_API_VERSION
 *
 * Report the version of the driver API.
 * Return: Driver API version.
 */
#define SPDM_GET_API_VERSION        _IO(SPDM_MAGIC, SPDM_BASE + 0)

#define SPDM_API_VERSION        0

/* Usersapce Agent APIs */

/**
 * SPDM_MSG_EXCHANGE
 *
 * Message exchange for normal SPDM messages.
 * Return: 0 on success, -errno on failure.
 */
#define SPDM_MSG_EXCHANGE       _IO(SPDM_MAGIC, SPDM_USER_BASE + 0)

/**
 * SPDM_SET_EVENTFD
 *
 * Userspace agents provide eventfd to spdm manager.
 * Return: 0 on success, -errno on failure.
 */
#define SPDM_SET_EVENTFD        _IO(SPDM_MAGIC, SPDM_USER_BASE + 1)

/**
 * SPDM_GET_REQUEST
 *
 * Get requests to userspace agent.
 * Return: 0 on success, -ENOENT if no pending request.
 */

enum spdm_request_type {
    /* session related request */
    SPDM_REQ_NOOP               = 0x0,
    SPDM_REQ_START              = SPDM_REQ_NOOP,
    SPDM_SESS_REQ_START_SESSION = 0x1,
    SPDM_SESS_REQ_START         = SPDM_SESS_REQ_START_SESSION,
    SPDM_SESS_REQ_END_SESSION   = 0x2,
    SPDM_SESS_REQ_KEY_UPDATE    = 0x3,
    SPDM_SESS_REQ_HEARTBEAT     = 0x4,
    SPDM_SESS_REQ_END       = SPDM_SESS_REQ_HEARTBEAT,
    /* Device attestation request */
    SPDM_MGR_REQ_RECOLLECT      = 0x5,
    SPDM_REQ_TYPE_NUM,
};

enum spdm_req_result {
    SPDM_REQ_RET_SUCCESS        = 0x0,
    SPDM_REQ_RET_INVALID        = 0x1,
    SPDM_REQ_RET_UNSUPPORTED    = 0x2,
    SPDM_REQ_RET_OOR            = 0x3,
    SPDM_REQ_RET_MOD_ERR        = 0x4,
    SPDM_REQ_RET_DEV_ERR        = 0x5,
    SPDM_REQ_RET_MESSAGE_ERR    = 0x6,
    SPDM_REQ_RET_AGENT_ERR      = 0x7,
    /* Errno for SPDM manager */
    SPDM_REQ_RET_SW_INIT_ERR    = 0xa0,
    SPDM_REQ_RET_SW_COMP_ERR    = 0xa1,
    SPDM_REQ_RET_SW_NO_MATCH    = 0xa2,
};

#define SPDM_GET_REQUEST        _IO(SPDM_MAGIC, SPDM_USER_BASE + 2)

/**
 *
 * SPDM_COMPLETE_REQUEST
 *
 * Notify that userspace agent has completed a request.
 * Return: 0 on success, -errno on failure.
 */
#define SPDM_COMPLETE_REQUEST       _IO(SPDM_MAGIC, SPDM_USER_BASE + 3)

/**
 *
 * SPDM_SET_DEVICE_INFO
 *
 * Userspace agent sets agent relavant Device Information
 * to SPDM manager.
 *
 */
#define SPDM_SET_DEVICE_INFO        _IO(SPDM_MAGIC, SPDM_USER_BASE + 4)

/* User APIs */

/**
 * SPDM_SEC_MSG_EXCHANGE
 *
 * Message exchange with device
 */
#define SPDM_SEC_MSG_EXCHANGE       _IO(SPDM_MAGIC, SPDM_BASE + 1)

/**
 * SPDM_GET_DEVICE_INFO_SIZE
 *
 * Get Device Information data size
 */
#define SPDM_GET_DEVICE_INFO_SIZE   _IO(SPDM_MAGIC, SPDM_BASE + 2)

/**
 * SPDM_GET_DEVICE_INFO
 *
 * Get Device Information data
 */
#define SPDM_GET_DEVICE_INFO        _IO(SPDM_MAGIC, SPDM_BASE + 3)

#endif /* _UAPI_LINUX_SPDM_H */
