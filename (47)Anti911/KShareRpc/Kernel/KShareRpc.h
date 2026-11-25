/* ============================================================================
 * KShareRpc.h —— 内核接入层的共用定义（Ring0 专用）
 *
 * 这一层**故意只做三件事**：
 *   1) 建一个分页文件支撑的共享段（PAGE_EXECUTE_READWRITE、SEC_COMMIT）
 *   2) 把这段映射进指定 PID 的用户空间，拿到那个用户态基址
 *   3) 把段对象的句柄开给控制器进程，让它能 MapViewOfFile 同一块物理页
 *
 * 为什么不做第四件事（在内核里挂起线程、改上下文）？
 *   那需要 ZwSuspendThread / ZwGetContextThread / ZwSetContextThread 一类
 *   未文档化或随版本变化的导出，而且必须在测试签名环境里才能验证。
 *   本项目把"劫持"留在 Ring3（可 100% 实测），内核只负责"把地基铺进目标"，
 *   这样每一层的结论都有实测支撑，不会出现"文档写着能跑、其实没跑过"。
 * ==========================================================================*/
#ifndef KSHARERPC_H
#define KSHARERPC_H

/* ntifs.h 而不是 ntddk.h：KeStackAttachProcess / KAPC_STATE 这一组
 * "把当前线程借到别的进程地址空间"的 API 声明在 ntifs.h 里。 */
#include <ntifs.h>

#define KSR_DEVICE_NAME     L"\\Device\\KShareRpc"
#define KSR_SYMBOLIC_NAME   L"\\??\\KShareRpc"
#define KSR_POOL_TAG        'rKSk'          /* 池标签，蓝屏/池泄漏时能在 !pool 里认出来 */

/* CTL_CODE 里的 Function 从 0x800 起，和 Anti911 的老驱动保持同一习惯，
 * 这样两个驱动并存时不会撞号。 */
#define KSR_CTL_BASE        0x800

#define KSR_CTL_CREATE_SECTION  CTL_CODE(FILE_DEVICE_UNKNOWN, KSR_CTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KSR_CTL_MAP_INTO        CTL_CODE(FILE_DEVICE_UNKNOWN, KSR_CTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KSR_CTL_GET_HANDLE      CTL_CODE(FILE_DEVICE_UNKNOWN, KSR_CTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KSR_CTL_RELEASE         CTL_CODE(FILE_DEVICE_UNKNOWN, KSR_CTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- 建段 ---- */
typedef struct _KSR_CREATE_IN
{
    ULONG  Size;                 /* 段大小（字节），建议 4KB 对齐 */
} KSR_CREATE_IN;

typedef struct _KSR_CREATE_OUT
{
    NTSTATUS Status;             /* 内核回填：这一步成功没有 */
    ULONG    SectionSize;        /* 实际段大小 */
} KSR_CREATE_OUT;

/* ---- 映射进目标 ---- */
typedef struct _KSR_MAP_IN
{
    ULONG Pid;                   /* 目标进程 ID */
    ULONG Size;                  /* 想映射多大，0 表示整段 */
} KSR_MAP_IN;

typedef struct _KSR_MAP_OUT
{
    NTSTATUS Status;
    ULONG    Reserved;
    ULONGLONG BaseAddress;       /* 目标进程里的用户态基址（映射失败则为 0） */
} KSR_MAP_OUT;

/* ---- 取句柄 ---- */
typedef struct _KSR_HANDLE_OUT
{
    NTSTATUS Status;
    ULONG    Reserved;
    ULONGLONG UserHandle;        /* 控制器进程里可用的段句柄（HANDLE 值） */
} KSR_HANDLE_OUT;

#endif /* KSHARERPC_H */
