#ifndef QEMU_I386_TDX_H
#define QEMU_I386_TDX_H

#ifndef CONFIG_USER_ONLY
#include CONFIG_DEVICES /* CONFIG_TDX */
#endif

#include <linux/kvm.h>
#include "exec/confidential-guest-support.h"
#include "hw/i386/tdvf.h"
#include "io/channel-socket.h"
#include "sysemu/kvm.h"
#include "qemu/uuid.h"

#define TYPE_TDX_GUEST "tdx-guest"
#define TDX_GUEST(obj)  OBJECT_CHECK(TdxGuest, (obj), TYPE_TDX_GUEST)
#define TDX_PHYS_ADDR_BITS  52

#define TDG_VP_VMCALL_MAP_GPA                           0x10001ULL
#define TDG_VP_VMCALL_GET_QUOTE                         0x10002ULL
#define TDG_VP_VMCALL_REPORT_FATAL_ERROR                0x10003ULL
#define TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT      0x10004ULL
#define TDG_VP_VMCALL_SERVICE                           0x10005ULL

#define TDG_VP_VMCALL_SUCCESS           0x0000000000000000ULL
#define TDG_VP_VMCALL_RETRY             0x0000000000000001ULL
#define TDG_VP_VMCALL_INVALID_OPERAND   0x8000000000000000ULL
#define TDG_VP_VMCALL_ALIGN_ERROR       0x8000000000000002ULL

#define TDX_GET_QUOTE_STRUCTURE_VERSION 1ULL

#define TDX_VP_GET_QUOTE_SUCCESS                0ULL
#define TDX_VP_GET_QUOTE_IN_FLIGHT              (-1ULL)
#define TDX_VP_GET_QUOTE_ERROR                  0x8000000000000000ULL
#define TDX_VP_GET_QUOTE_QGS_UNAVAILABLE        0x8000000000000001ULL

typedef struct TdxGuestClass {
    ConfidentialGuestSupportClass parent_class;
} TdxGuestClass;

enum TdxRamType{
    TDX_RAM_UNACCEPTED,
    TDX_RAM_ADDED,
};

typedef struct TdxRamEntry {
    uint64_t address;
    uint64_t length;
    uint32_t type;
} TdxRamEntry;

typedef struct TdxVmServiceDataHead {
    QemuUUID guid;
    uint32_t length;
    union {
        uint32_t reserved;
        uint32_t status;
    } u;
} __attribute__((__packed__)) TdxVmServiceDataHead;

typedef struct TdxVmcallSerivceDataCache {
    hwaddr addr;

    TdxVmServiceDataHead head;
    void *data_buf;
    uint32_t data_buf_len;
    uint32_t data_len;
} TdxVmcallSerivceDataCache;

struct TdxVmcallServiceItem;
typedef void (*TdxVmcallServiceHandler)(struct TdxVmcallServiceItem *vsi,
                                        void* opaque);

typedef struct TdxVmcallServiceType {
    QemuUUID from;
    TdxVmcallServiceHandler to;
    int vsi_size;
    void *opaque;
} TdxVmcallServiceType;

struct TdxVmcallServiceItem;
typedef void TdxVmcallServiceTimerCB(struct TdxVmcallServiceItem *vsi,
                                      void *opaque);
typedef struct TdxVmcallServiceItem {
    uint32_t ref_count;

    /* Memory allocated in cache need to free if tdx object's
     * lifecycle shorter
     */
    TdxVmcallSerivceDataCache command;
    TdxVmcallSerivceDataCache response;

    uint32_t apic_id;
    uint64_t notify_vector;
    uint64_t timeout;

    QEMUTimer timer;
    TdxVmcallServiceTimerCB *timer_cb;
    void *timer_opaque;
    bool timer_enable;
    QemuSemaphore wait;

} TdxVmcallServiceItem;

typedef struct TdxVmcallService {

    TdxVmcallServiceType *dispatch_table;
    int dispatch_table_count;

    char *vtpm_type;
    char *vtpm_path;
    char *vtpm_userid;
} TdxVmcallService;

/* For migration */
typedef struct tdx_get_quote_state TdxGetQuoteState;
struct tdx_get_quote_task;

typedef struct TdxGuest {
    ConfidentialGuestSupport parent_obj;

    QemuMutex lock;

    bool initialized;
    uint64_t attributes;    /* TD attributes */
    uint8_t mrconfigid[48];     /* sha348 digest */
    uint8_t mrowner[48];        /* sha348 digest */
    uint8_t mrownerconfig[48];  /* sha348 digest */
    bool tpa_td;

    TdxFirmware tdvf;
    MemoryRegion *tdvf_region;

    uint32_t nr_ram_entries;
    TdxRamEntry *ram_entries;

    /* runtime state */
    uint32_t event_notify_apic_id;
    uint8_t event_notify_interrupt;

    /* GetQuote */
    int32_t quote_generation_num;
    char *quote_generation_str;
    SocketAddress *quote_generation;

    /* For migration. */
    QLIST_HEAD(, tdx_get_quote_task) get_quote_task_list;
    TdxGetQuoteState *get_quote_state;

    TdxVmcallService vmcall_service;

    uint32_t vsockport;
    uint32_t migtd_pid;
    uint64_t migtd_attr;
    uint8_t migtd_hash[48];  /* sha348 digest */
} TdxGuest;

#ifdef CONFIG_TDX
bool is_tdx_vm(void);
#else
#define is_tdx_vm() 0
#endif /* CONFIG_TDX */

int tdx_kvm_init(MachineState *ms, Error **errp);
void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret);
int tdx_pre_create_vcpu(CPUState *cpu);
void tdx_set_tdvf_region(MemoryRegion *tdvf_region);
int tdx_parse_tdvf(void *flash_ptr, int size);
void tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit);
void tdx_apply_xfam_dependencies(CPUState *cpu);
void tdx_check_minus_features(CPUState *cpu);
bool tdx_debug_enabled(void);
hwaddr tdx_remove_stolen_bit(hwaddr gpa);
bool tdx_premig_is_done(void);

/*interface to vmcall service handler*/
void tdx_vmcall_service_set_response_state(TdxVmcallServiceItem *vsi,int state);

void* tdx_vmcall_service_rsp_buf(TdxVmcallServiceItem *vsi);
int tdx_vmcall_service_rsp_size(TdxVmcallServiceItem *vsi);
void tdx_vmcall_service_set_rsp_size(TdxVmcallServiceItem *vsi, int size);

void* tdx_vmcall_service_cmd_buf(TdxVmcallServiceItem *vsi);
int tdx_vmcall_service_cmd_size(TdxVmcallServiceItem *vsi);

void tdx_vmcall_service_set_timeout_handler(TdxVmcallServiceItem *vsi,
                                            TdxVmcallServiceTimerCB *cb,
                                            void *opaque);
void tdx_vmcall_service_complete_request(TdxVmcallServiceItem *vsi);
void tdx_vmcall_service_item_ref(TdxVmcallServiceItem *vsi);
void tdx_vmcall_service_item_unref(TdxVmcallServiceItem *vsi);
TdxVmcallServiceType* tdx_vmcall_service_find_handler(QemuUUID *guid,
                                                      TdxVmcallService *vmc);
void tdx_vmcall_service_register_type(TdxGuest *tdx,
                                      TdxVmcallServiceType* type);
void tdx_guest_init_vtpm(TdxGuest *tdx);
void tdx_guest_init_service_query(TdxGuest *tdx);

#endif /* QEMU_I386_TDX_H */
