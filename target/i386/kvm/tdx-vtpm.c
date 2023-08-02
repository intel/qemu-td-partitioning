#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "io/channel-socket.h"
#include "hw/i386/x86.h"
#include "kvm_i386.h"
#include "tdx.h"
#include "tdx-vmcall-service.h"
#include "tdx-vtpm.h"

#include "trace.h"

QIOChannelSocket* tdx_vtpm_setup_communication(const char *local_addr)
{
    QIOChannelSocket* ioc;
    SocketAddress *addr;
    Error *local_err;

    addr = socket_parse(local_addr, &local_err);
    if (!addr)
        return NULL;

    ioc = qio_channel_socket_new();
    if (!ioc) {
        goto free_addr;
    }

    addr->u.q_unix.abstract = true;
    if (qio_channel_socket_dgram_sync(ioc, addr, NULL, &local_err)) {
        goto free_ioc;
    }

    qio_channel_set_blocking(QIO_CHANNEL(ioc), false, NULL);

    g_free(addr);
    return ioc;

 free_ioc:
    object_unref(ioc);
 free_addr:
    g_free(addr);
    return NULL;
}

int tdx_vtpm_init_base(TdxVtpm *base, TdxGuest *tdx,
                       const char* local_addr,
                       IOHandler *read, void *read_opaque)
{
    QIOChannelSocket *ioc;

    ioc = tdx_vtpm_setup_communication(local_addr);
    if (!ioc) {
        error_report("Failed to setup communication:%s",
                     local_addr);
        return -1;
    }
    qemu_set_fd_handler(ioc->fd, read, NULL, read_opaque);

    base->ioc = ioc;
    base->tdx = tdx;

    return 0;
}

int tdx_vtpm_init_base2(TdxVtpm *base, QIOChannelSocket *ioc, TdxGuest *tdx)
{
    base->ioc = ioc;
    base->tdx = tdx;

    return 0;
}


TdxVtpmTransProtocolHead
tdx_vtpm_init_trans_protocol_head(uint8_t type)
{
    TdxVtpmTransProtocolHead head;

    head.version = 0;
    head.type = type;
    head.length = 0;
    head.reserved[0] = 0;
    head.reserved[1] = 0;

    return head;
}

TdxVtpmCommHead tdx_vtpm_init_comm_head(uint8_t type)
{
    TdxVtpmCommHead head;

    head.version = 0;
    head.command = type;

    return head;
}

int tdx_vtpm_trans_send(QIOChannelSocket *socket_ioc,
                        struct UnixSocketAddress *addr,
                        TdxVtpmTransProtocolHead *head,
                        struct iovec *iovec, int iovec_count)
{
    ssize_t ret;
    TdxVtpmTransProtocolHead *new_pack;
    uint32_t length = sizeof(*new_pack);
    QIOChannel *ioc;
    Error *local_err;
    uint8_t *p;

    for (int i = 0; i < iovec_count; ++i) {
        length += iovec[i].iov_len;
    }

    new_pack = g_try_malloc(length);
    if (!new_pack)
        return -1;

    p = (uint8_t*)(new_pack + 1);
    for (int i = 0; i < iovec_count; ++i) {
        memcpy(p, iovec[i].iov_base, iovec[i].iov_len);
        p += iovec[i].iov_len;
    }

    *new_pack = *head;
    new_pack->length = length;

    ioc = QIO_CHANNEL(socket_ioc);
    /*TODO: Remove datagram supporting after STREAM support is done. */
    if (socket_ioc->unix_datagram) {
        qio_channel_socket_set_dgram_send_address(socket_ioc, addr);
    }
    ret = qio_channel_write_all(ioc, (const char*)new_pack, length, &local_err);

    g_free(new_pack);

    return ret;
}

void tdx_guest_init_vtpm(TdxGuest *tdx)
{
    TdxVmcallService *vms = &tdx->vmcall_service;
    TdxVmcallServiceType vtpm;
    TdxVtpm *instance;
    bool is_server;
    int size;
    int ret;

    is_server = !g_strcmp0(vms->vtpm_type, "server");
    if (is_server) {
        size =  sizeof(TdxVtpmServer);
    } else {
        size = sizeof(TdxVtpmClient);
    }

    instance = g_try_malloc0(size);
    if (!instance) {
        error_report("Failed to create vtpm %s instance.",
                     vms->vtpm_type);
        return;
    }

    if (is_server) {
        ret = tdx_vtpm_init_server(instance, vms, tdx, &vtpm);
    } else {
        ret = tdx_vtpm_init_client(instance, vms, tdx, &vtpm);
    }

    if (ret) {
        error_report("Failed to init vtpm %s instance.",
                     vms->vtpm_type);
        goto free;
    }

    vtpm.opaque = instance;
    tdx_vmcall_service_register_type(tdx, &vtpm);

    return;
 free:
    g_free(instance);
}

int socket_recv_buffer_init(SocketRecvBuffer *srb, int init_size)
{
    if (!srb)
        return -1;

    srb->buf = g_try_malloc(init_size);
    if (!srb->buf)
        return -1;

    srb->size = init_size;
    srb->used_size = 0;
    srb->update_buf = false;
    return 0;
}

int socket_recv_buffer_next(SocketRecvBuffer *srb,
                            void **data, int *size)
{
    TdxVtpmTransProtocolHead *head;

    if (!srb)
        return -1;

    if (!srb->buf)
        return -1;

    if (!srb->used_size)
        return 1;

    head = srb->buf;
    if (srb->update_buf) {
        int remain_size;

        remain_size = srb->used_size - head->length;
        memcpy(srb->buf, srb->buf + head->length, remain_size);
        srb->used_size = remain_size;
        srb->update_buf = false;
    }

    if (srb->used_size <= sizeof(*head))
        return 1;

    if (head->length > srb->size) {
        srb->buf = g_realloc(srb->buf,
                             head->length);
        if (!srb->buf) {
            error_report("No enough memory, data dropped");
            return -1;
        }
        srb->size = head->length;
        return 1;
    }

    if (head->length > srb->used_size) {
        return 1;
    }

    *data = srb->buf;
    *size = head->length;
    srb->update_buf = true;
    return 0;
}

void* socket_recv_buffer_get_buf(SocketRecvBuffer *srb)
{
    return srb->buf + srb->used_size;
}

int socket_recv_buffer_get_free_size(SocketRecvBuffer *srb)
{
    return srb->size - srb->used_size;
}

void socket_recv_buffer_update_used_size(SocketRecvBuffer *srb, int new_used_size)
{
    srb->used_size += new_used_size;
}
