# Kernel —— 内核接入层（建段 / 映射 / 给句柄）

这一层**故意只做三件事**，不做第四件：

| 做 | 不做 |
|---|---|
| 1. 建一个分页文件支撑的共享段（`PAGE_EXECUTE_READWRITE`、`SEC_COMMIT`） | 4. 在内核里挂起线程、改上下文 |
| 2. 把这段映射进指定 PID 的用户空间，返回那个用户态基址 | |
| 3. 把段对象的句柄开给控制器进程，让它 `MapViewOfFile` 同一块物理页 | |

### 为什么不做第 4 件事

在内核里改目标线程上下文需要 `ZwSuspendThread / ZwGetContextThread / ZwSetContextThread`
一类导出，它们的**导出状态随 Windows 版本变化**，而且必须在**测试签名环境**里才能验证。
本工程的立场是把"劫持"留在 Ring3（那一层 100% 实测过），内核只负责"把地基铺进目标"。
这样每一层都能给出实测证据，不会出现"文档写着能跑、其实没跑过"。

**当前状态（如实）**：本机编译 + 链接通过，产出 `KShareRpc.sys`（7168 字节，
`dumpbin /headers` 确认 `8664 machine (x64)` / `subsystem (Native)` / `entry point 0x1400018E0`）。
**没有加载、没有运行过**——加载需要测试签名或关闭驱动签名强制，这必须在专用 VM 里做。

---

## 1. 编译

```bat
cd /d "<本目录>"
build_kernel.bat
```

脚本里的关键项，逐条说明为什么必须有：

| 选项 | 作用 / 不加会怎样 |
|---|---|
| `/kernel` | 按内核模式编译（关掉用户态那套异常/SEH 假设） |
| `/GS-` | 内核里不使用用户态栈 cookie（WDK 工程默认也是关的） |
| `/D_AMD64_` | **不加会 `#error "No Target Architecture"`**（`ntdef.h` 靠它选架构分支），实测踩过 |
| `/I...\km` `/I...\km\crt` `/I...\shared` | 内核头文件、内核 CRT、共享头文件（`CTL_CODE`/`UNICODE_STRING` 等在 shared 里） |
| `/utf-8 /wd4819` | 源码是 UTF-8 带 BOM；`/wd4819` 屏蔽 MSVC 对全角标点的误报 |
| `link /DRIVER /SUBSYSTEM:NATIVE` | 驱动是"原生子系统"镜像，不是控制台程序 |
| `/ENTRY:DriverEntry` | 链接器默认不认识 `DriverEntry`，必须显式指定 |
| `ntoskrnl.lib hal.lib` + `/LIBPATH:...\km\x64` | 内核导出与 HAL 导出；路径必须是 **km** 目录，不是 um |
| `/NODEFAULTLIB` | 不链用户态 CRT，避免把 `mainCRTStartup` 之类的东东拖进来 |

### 编译期踩过的三个坑（都是真实的编译错误）

1. **`KAPC_STATE` / `KeStackAttachProcess` 声明在 `ntifs.h`，不在 `ntddk.h`**
   → 头文件改成 `#include <ntifs.h>`（`ntifs.h` 里已经包含了 `ntddk.h` 的基础部分）。
2. **`ObOpenObjectByPointer` 第 3 个参数是 `PACCESS_STATE`，不是 `OBJECT_ATTRIBUTES*`**
   → 原来误传 `&oa`，改成传 `NULL`（本层不做访问检查）。
3. **`IoDeleteSymbolicLink` 要的是 `PUNICODE_STRING`，不是 `WCHAR[]`**
   → 用 `RtlInitUnicodeString` 现场构造一个 `UNICODE_STRING` 再传。

---

## 2. IOCTL 协议

设备名 `\Device\KShareRpc`，符号链接 `\??\KShareRpc`（用户态看到的是 `\\.\KShareRpc`）。
所有控制码都是 `METHOD_BUFFERED`（内核把输入/输出拷进 `SystemBuffer`，
所以**不需要** `ProbeForRead/Write`；老驱动用 `METHOD_NEITHER` 是为了省那次拷贝，本层不追求）。

| 控制码 | Function | 输入 | 输出 | 作用 |
|---|---|---|---|---|
| `KSR_CTL_CREATE_SECTION` | `0x800` | `KSR_CREATE_IN{ ULONG Size; }` | `KSR_CREATE_OUT{ NTSTATUS Status; ULONG SectionSize; }` | 建段（只建一次，重复调用返回 `STATUS_ALREADY_REGISTERED`） |
| `KSR_CTL_MAP_INTO` | `0x801` | `KSR_MAP_IN{ ULONG Pid; ULONG Size; }` | `KSR_MAP_OUT{ NTSTATUS Status; ULONG Reserved; ULONGLONG BaseAddress; }` | 把段映射进 `Pid` 的用户空间，返回**目标进程视角**的基址 |
| `KSR_CTL_GET_HANDLE` | `0x802` | 无 | `KSR_HANDLE_OUT{ NTSTATUS Status; ULONG Reserved; ULONGLONG UserHandle; }` | 给**当前调用进程**开一个段句柄 |
| `KSR_CTL_RELEASE` | `0x803` | 无 | 无 | 撤所有视图、关段、清状态（卸载时也会自动做） |

`CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800+n, METHOD_BUFFERED, FILE_ANY_ACCESS)`
→ 实际数值是 `0x0022_0000 | (0x800+n) << 2`，用户态直接用宏算，别手写数字。

`BaseAddress` 为什么重要：**同一个物理页，在两个进程里的虚拟地址不同**。
控制器要知道"目标进程里这块页在哪"，才能把 `RIP` 指到那个地址（跨进程劫持的关键一步）。

---

## 3. 用户态怎么接（下一步要写的代码）

```c
HANDLE hDev = CreateFileW(L"\\\\.\\KShareRpc", GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, 0, NULL);

KSR_CREATE_IN  ci = { 64 * 1024 };
KSR_CREATE_OUT co = { 0 };
DeviceIoControl(hDev, KSR_CTL_CREATE_SECTION, &ci, sizeof(ci), &co, sizeof(co), &ret, NULL);

KSR_MAP_IN  mi = { targetPid, 64 * 1024 };
KSR_MAP_OUT mo = { 0 };
DeviceIoControl(hDev, KSR_CTL_MAP_INTO, &mi, sizeof(mi), &mo, sizeof(mo), &ret, NULL);
/* mo.BaseAddress = 目标进程里这块页的地址 */

KSR_HANDLE_OUT ho = { 0 };
DeviceIoControl(hDev, KSR_CTL_GET_HANDLE, NULL, 0, &ho, sizeof(ho), &ret, NULL);
/* (HANDLE)ho.UserHandle 是"我自己进程里"的段句柄 */
void* localView = MapViewOfFile((HANDLE)ho.UserHandle, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
/* localView 和 mo.BaseAddress 指向同一块物理页 */
```

三个容易忽略的点：

- `GET_HANDLE` 出来的句柄**属于调用它的那个进程**（`ObOpenObjectByPointer(..., UserMode, ...)`），
  所以能直接 `MapViewOfFile`；但它**不是内核句柄**，不要试图在别的进程里用。
- 用完 `CloseHandle`（用户态关），内核侧的 `g_SectionHandle` 是另一份（`OBJ_KERNEL_HANDLE`），
  由 `RELEASE` 或卸载时关。
- `MapViewOfFile` 的最后两个参数给 0 表示"整段"；要给具体大小就填 `Size`。

---

## 4. 关键实现点（读代码时看这几处）

### 4.1 为什么用 `OBJ_KERNEL_HANDLE`

```c
InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
ZwCreateSection(&g_SectionHandle, SECTION_ALL_ACCESS, &oa, &maxSize,
                PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
```

- 没有这个标志，`ZwCreateSection` 会把句柄建在**当前进程的句柄表**里。驱动是"谁的线程在跑就在谁的进程里"，
  于是这个句柄会跟着某个用户进程生死，而且 `KeStackAttachProcess` 切走之后**可能就失效了**。
- 加了 `OBJ_KERNEL_HANDLE`，句柄进内核句柄表、不属于任何进程，**切到哪个进程都有效**。

### 4.2 `KeStackAttachProcess` + `ProcessHandle = NULL`

```c
KeStackAttachProcess(Process, &ApcState);
st = ZwMapViewOfSection(g_SectionHandle, NULL, &Base, 0, Size, NULL,
                        &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
KeUnstackDetachProcess(&ApcState);
```

- `KeStackAttachProcess` 的语义是"**把当前线程临时借给目标进程**"——之后这段代码虽然是内核代码，
  但访问用户态地址时用的是**目标进程的地址空间**。
- 正因为已经 Attach 了，`ZwMapViewOfSection` 的 `ProcessHandle` 传 `NULL` 就是"映射到当前地址空间"，
  拿到的 `Base` 是**目标进程里**的地址。
- **失败也必须 Detach**（代码里在 `ZwMapViewOfSection` 之后无条件 `KeUnstackDetachProcess`），
  否则当前线程会一直挂在别人的地址空间里，后面所有用户态访问都会出错——这是内核里最危险的一类遗漏。

### 4.3 卸载顺序必须反过来

```c
KsrUnmapAllViews();          /* 1. 先把每个进程里的视图撤掉 */
ObDereferenceObject(...);    /* 2. 放掉段对象引用 */
ZwClose(g_SectionHandle);    /* 3. 关段句柄 */
IoDeleteSymbolicLink(...);   /* 4. 删符号链接 */
IoDeleteDevice(...);         /* 5. 删设备 */
```

- 顺序反了会怎样：设备删了但段还在，用户态进程仍持有句柄 → 段泄漏；
  或者视图没撤就关段 → 目标进程里留下"指向已释放段的映射"，一访问就 AV。
- `KSR_MAX_VIEWS = 16` 是硬上限：映射超过 16 次会静默丢弃记录（本层只做教学，够用）。
  真实实现要用链表 + 每项独立引用计数。

### 4.4 `KsrUnmapAllViews` 里为什么要重新 `PsLookupProcessByProcessId`

- 不能缓存 `PEPROCESS` 指针：进程随时可能退出，缓存指针会变成悬空引用。
  每次按 PID 重新查、拿到临时引用、用完 `ObDereferenceObject`，是安全的写法。
- 进程已退出时，视图随地址空间一起消失，不需要（也不能）再撤。

---

## 5. 未验证 / 已知局限（写简历时必须照这张表说）

| 项 | 状态 |
|---|---|
| 编译 + 链接 | **已验证**（本机 WDK 10.0.22000 + VS2019） |
| `DriverEntry` 实际执行、`DbgPrint` 输出 | **未验证**（未加载） |
| IOCTL 四路的实际返回 | **未验证**（未加载） |
| 映射进别的进程、跨进程共享同一块页 | **未验证**（未加载） |
| 卸载清理（视图/句柄/设备/符号链接） | **未验证**（未加载） |
| 多进程视图 > 16 的行为 | 未测试（代码里是静默丢弃） |
| `SEC_COMMIT` 立刻提交物理页的开销 | 未测（教学场景选了可预测性优先） |

### 想验证的话（只在专用 VM 里做）

```bat
bcdedit /set testsigning on            rem 需要重启；只在测试机做
sc create KShareRpc type= kernel binPath= C:\path\KShareRpc.sys
sc start KShareRpc
rem 用 DbgView 看 DbgPrint 输出
sc stop KShareRpc
sc delete KShareRpc
```

- 别在你自己日常用的机器上加载未签名驱动：一旦蓝屏，正在写的代码可能全丢。
- 这段命令只是"怎么验"的说明，本工程**没有在任何机器上执行过**。
