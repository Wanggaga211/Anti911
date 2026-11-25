/* ============================================================================
 * KShareRpc.c —— 内核接入层（建段 / 映射进目标 / 给出句柄）
 *
 * 对照 Anti911 的老驱动：那边是"每一发注入都要在目标里新开一块 RWX、
 * 排一条 APC、再轮询标志位"。这里换掉的正是这个模型：
 *   段只建一次（同一块物理页），映射只做一次，之后控制器和目标侧 agent
 *   读写的是同一块页 —— 不再有 IOCTL 往返，也不再需要句柄传递语义。
 * ==========================================================================*/
#include "KShareRpc.h"

#define KSR_MAX_VIEWS 16

typedef struct _KSR_VIEW
{
    BOOLEAN Used;
    ULONG   Pid;
    PVOID   Base;               /* 目标进程里的用户态基址 */
    ULONG   Size;
} KSR_VIEW;

static PDEVICE_OBJECT  g_Device          = NULL;
static HANDLE          g_SectionHandle   = NULL;   /* OBJ_KERNEL_HANDLE 的内核句柄 */
static PVOID           g_SectionObject   = NULL;   /* 段对象，用来给用户开句柄 */
static ULONG           g_SectionSize     = 0;
static KSR_VIEW        g_Views[KSR_MAX_VIEWS];
static KSPIN_LOCK      g_ViewsLock;

/* ----------------------------------------------------------------------------
 * 建段：ZwCreateSection 走的是"分页文件支撑"（不落盘、不占文件）。
 *   OBJ_KERNEL_HANDLE 让这个句柄在内核里创建、不属于任何进程，
 *   所以后面 KeStackAttachProcess 切到别的进程之后它依然有效。
 * --------------------------------------------------------------------------*/
static NTSTATUS KsrCreateSection(ULONG Size)
{
    NTSTATUS         st;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER    maxSize;

    if (g_SectionHandle)
        return STATUS_ALREADY_REGISTERED;          /* 只建一次，重入直接拒绝 */

    Size = (Size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (Size == 0 || Size > 64 * 1024 * 1024)
        return STATUS_INVALID_PARAMETER;

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    maxSize.QuadPart = (LONGLONG)Size;

    /* PAGE_EXECUTE_READWRITE：这块页既要放数据也要放 stub 代码。
     * SEC_COMMIT：立刻提交物理页，避免访问时再触发缺页（教学场景更好预测）。 */
    st = ZwCreateSection(&g_SectionHandle, SECTION_ALL_ACCESS, &oa, &maxSize,
                         PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(st))
    {
        g_SectionHandle = NULL;
        return st;
    }

    /* 拿对象指针：后面 ObOpenObjectByPointer 才能给用户进程开句柄 */
    st = ObReferenceObjectByHandle(g_SectionHandle, SECTION_ALL_ACCESS, NULL,
                                   KernelMode, &g_SectionObject, NULL);
    if (!NT_SUCCESS(st))
    {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return st;
    }

    g_SectionSize = Size;
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------------------
 * 映射进目标进程。
 *
 * 三个关键动作：
 *   PsLookupProcessByProcessId  —— 用 PID 拿到 EPROCESS（带引用计数）
 *   KeStackAttachProcess        —— 把当前线程"借"到目标进程的地址空间
 *   ZwMapViewOfSection          —— 在**当前**地址空间里建一段视图
 *
 * 注意 ProcessHandle 传 NULL：因为此刻当前地址空间已经是目标进程了。
 * 也正因为 Attach 了，拿到的 BaseAddress 是**目标进程里**的地址，
 * 不是内核地址、也不是控制器里的地址。
 * --------------------------------------------------------------------------*/
static NTSTATUS KsrMapInto(ULONG Pid, ULONG Size, PVOID* OutBase, ULONG* OutSize)
{
    NTSTATUS    st;
    PEPROCESS   Process = NULL;
    KAPC_STATE  ApcState;
    PVOID       Base = NULL;
    SIZE_T      ViewSize;

    if (!g_SectionHandle)
        return STATUS_UNSUCCESSFUL;
    if (Size == 0 || Size > g_SectionSize)
        Size = g_SectionSize;

    st = PsLookupProcessByProcessId(ULongToHandle(Pid), &Process);
    if (!NT_SUCCESS(st))
        return st;

    ViewSize = Size;

    KeStackAttachProcess(Process, &ApcState);

    /* 这里如果失败（比如目标进程已经退出、或者地址空间里没有空位），
     * 必须先把 Attach 撤掉再返回，否则当前线程会一直挂在别人的地址空间里。 */
    st = ZwMapViewOfSection(g_SectionHandle, NULL, &Base, 0, Size, NULL,
                            &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);

    if (!NT_SUCCESS(st))
        return st;

    *OutBase = Base;
    *OutSize = (ULONG)ViewSize;
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------------------
 * 把段的句柄开给"当前发起 IOCTL 的那个进程"。
 * ObOpenObjectByPointer 出来的句柄属于当前进程，所以 UserHandle 直接可用。
 * --------------------------------------------------------------------------*/
static NTSTATUS KsrGiveHandle(PVOID* OutUserHandle)
{
    NTSTATUS st;

    if (!g_SectionObject)
        return STATUS_UNSUCCESSFUL;

    /* 第 3 个参数是 PassedAccessState（访问检查用的中间态），这里不做访问检查，
     * 直接给 NULL；HandleAttributes 传 0 表示"开一个普通用户句柄"（不是内核句柄）。 */
    st = ObOpenObjectByPointer(g_SectionObject, 0, NULL, SECTION_ALL_ACCESS,
                               NULL, UserMode, (HANDLE*)OutUserHandle);
    return st;
}

/* ----------------------------------------------------------------------------
 * 记一笔"我在哪个进程里映射过哪一段"，卸载时要按 PID 回去逐个撤视图。
 * 不记就会留下"目标退出前一直挂着的映射"，属于内核里最典型的泄漏。
 * --------------------------------------------------------------------------*/
static VOID KsrRememberView(ULONG Pid, PVOID Base, ULONG Size)
{
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&g_ViewsLock);

    for (int i = 0; i < KSR_MAX_VIEWS; i++)
    {
        if (!g_Views[i].Used)
        {
            g_Views[i].Used = TRUE;
            g_Views[i].Pid  = Pid;
            g_Views[i].Base = Base;
            g_Views[i].Size = Size;
            break;
        }
    }
    KeReleaseSpinLock(&g_ViewsLock, irql);
}

static VOID KsrUnmapAllViews(VOID)
{
    for (int i = 0; i < KSR_MAX_VIEWS; i++)
    {
        if (!g_Views[i].Used)
            continue;

        PEPROCESS  Process = NULL;
        KAPC_STATE ApcState;

        if (NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(g_Views[i].Pid), &Process)))
        {
            KeStackAttachProcess(Process, &ApcState);
            ZwUnmapViewOfSection(NULL, g_Views[i].Base);
            KeUnstackDetachProcess(&ApcState);
            ObDereferenceObject(Process);
        }
        /* 进程已经退出的话，视图跟着地址空间一起没了，这里不需要再做什么 */

        g_Views[i].Used = FALSE;
        g_Views[i].Pid  = 0;
        g_Views[i].Base = NULL;
        g_Views[i].Size = 0;
    }
}

/* ----------------------------------------------------------------------------
 * IOCTL 分发：METHOD_BUFFERED 意味着内核已经把输入/输出缓冲拷进
 * SystemBuffer，我们不需要 ProbeForRead/Write —— 这是相对 METHOD_NEITHER
 * 更省事也更安全的写法（老驱动用 NEITHER 是为了性能，这里不追求那点开销）。
 * --------------------------------------------------------------------------*/
static NTSTATUS KsrIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS           st    = STATUS_INVALID_DEVICE_REQUEST;
    PVOID              buf   = Irp->AssociatedIrp.SystemBuffer;
    ULONG              inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG              outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG              code   = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (code)
    {
    case KSR_CTL_CREATE_SECTION:
    {
        if (inLen < sizeof(KSR_CREATE_IN) || outLen < sizeof(KSR_CREATE_OUT))
        {
            st = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        KSR_CREATE_IN*  in  = (KSR_CREATE_IN*)buf;
        KSR_CREATE_OUT* out = (KSR_CREATE_OUT*)buf;

        st = KsrCreateSection(in->Size);
        out->Status      = st;
        out->SectionSize = g_SectionSize;
        Irp->IoStatus.Information = sizeof(KSR_CREATE_OUT);
        break;
    }
    case KSR_CTL_MAP_INTO:
    {
        if (inLen < sizeof(KSR_MAP_IN) || outLen < sizeof(KSR_MAP_OUT))
        {
            st = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        KSR_MAP_IN*  in  = (KSR_MAP_IN*)buf;
        KSR_MAP_OUT* out = (KSR_MAP_OUT*)buf;

        PVOID base = NULL;
        ULONG size = 0;
        st = KsrMapInto(in->Pid, in->Size, &base, &size);
        out->Status      = st;
        out->BaseAddress = (ULONGLONG)(ULONG_PTR)base;
        if (NT_SUCCESS(st))
            KsrRememberView(in->Pid, base, size);

        Irp->IoStatus.Information = sizeof(KSR_MAP_OUT);
        break;
    }
    case KSR_CTL_GET_HANDLE:
    {
        if (outLen < sizeof(KSR_HANDLE_OUT))
        {
            st = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        KSR_HANDLE_OUT* out = (KSR_HANDLE_OUT*)buf;

        PVOID h = NULL;
        st = KsrGiveHandle(&h);
        out->Status     = st;
        out->UserHandle = (ULONGLONG)(ULONG_PTR)h;

        Irp->IoStatus.Information = sizeof(KSR_HANDLE_OUT);
        break;
    }
    case KSR_CTL_RELEASE:
    {
        KsrUnmapAllViews();
        if (g_SectionObject)
        {
            ObDereferenceObject(g_SectionObject);
            g_SectionObject = NULL;
        }
        if (g_SectionHandle)
        {
            ZwClose(g_SectionHandle);
            g_SectionHandle = NULL;
        }
        g_SectionSize = 0;
        st = STATUS_SUCCESS;
        break;
    }
    default:
        break;
    }

    Irp->IoStatus.Status = st;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

static NTSTATUS KsrDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static VOID KsrUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symName;

    UNREFERENCED_PARAMETER(DriverObject);

    /* 卸载顺序必须和创建顺序反过来：先撤视图、再关段、最后删设备 */
    KsrUnmapAllViews();

    if (g_SectionObject)
    {
        ObDereferenceObject(g_SectionObject);
        g_SectionObject = NULL;
    }
    if (g_SectionHandle)
    {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
    }

    RtlInitUnicodeString(&symName, KSR_SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&symName);         /* 要的是 UNICODE_STRING，不是宽字符数组 */
    if (g_Device)
    {
        IoDeleteDevice(g_Device);
        g_Device = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS        st;
    UNICODE_STRING  devName;
    UNICODE_STRING  symName;
    PDEVICE_OBJECT  device = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&devName, KSR_DEVICE_NAME);
    RtlInitUnicodeString(&symName, KSR_SYMBOLIC_NAME);

    st = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                        0, FALSE, &device);
    if (!NT_SUCCESS(st))
        return st;

    /* 缓冲方式 + 非独占：控制端可以随时打开、随时关 */
    device->Flags |= DO_BUFFERED_IO;
    device->Flags &= ~DO_DEVICE_INITIALIZING;

    st = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(st))
    {
        IoDeleteDevice(device);
        return st;
    }

    g_Device = device;
    KeInitializeSpinLock(&g_ViewsLock);

    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = KsrDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KsrIoControl;
    DriverObject->DriverUnload = KsrUnload;

    DbgPrint("[KShareRpc] loaded, section layer ready\n");
    return STATUS_SUCCESS;
}
