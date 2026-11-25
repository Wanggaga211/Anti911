# KShareRpc —— 共享内存 / syscall 直连 / 调用链劫持（教学用最小实现）

这个子工程把你 `(47)Anti911` 里那套"每注入一次就要在目标里新开一块 RWX、排队一条 APC、轮询完成标志"的
内核注入，换成一个**能讲、能跑、能量数据**的三层模型：

```
        [3] 调用链劫持  <- 核心：借用目标已有的线程，不新建线程、不挂 APC
              |  执行
        [2] syscall 直连 <- 辅助：载荷自己进内核，绕开用户态 inline hook
              |  取号 / 调用
        [1] 共享内存    <- 地基：参数、载荷、现场、回执全放这一块
```

三层不是三个并列的招数，是一条链：**缺 [1] 没地方放载荷；缺 [2] 载荷一调 API 就被看见；
缺 [3] 还只是"通信 + 调用"，没有一个真正的执行体。** 这也是面试时说清"你为什么这么设计"的骨架。

---

## 1. 目录

```
KShareRpc\
├─ ShareRpcLab\                 用户态三层演示器（VS2019 x64，可反复跑）
│   ├─ ShareRpcLayout.h         Ring3/Ring0 共用布局：段头、信箱、魔数、偏移
│   ├─ KsrLab.h                 公共声明：日志、计时、SSN 解析、stub 偏移常量、导出符号
│   ├─ Layer1_SharedMem.c       第一层：建段 + 映射 + 信箱协议 + 2000 次往返计时
│   ├─ Layer2_DirectSyscall.c   第二层：SSN 解析 + 假 EDR hook + 直连 syscall 对比
│   ├─ Layer3_ChainHijack.c     第三层：停点挑选 + 上下文劫持 + 无损返回
│   ├─ NtStub.asm               x64：KsrNtStub（直连）+ KsrHijackStub（可整块搬迁的劫持桩）
│   ├─ ShareRpcLab.c            入口：all / 1 / 2 / 3 / selftest
│   ├─ build.bat                构建（纯 ASCII + CRLF）
│   └─ run_all.log              最近一次实测日志（UTF-8，可直接读）
├─ Kernel\                      内核接入层（建段 / 映射进目标 / 给出句柄）
│   ├─ KShareRpc.h              IOCTL 码与入参出参结构
│   ├─ KShareRpc.c              DriverEntry / IOCTL 分发 / 卸载清理
│   ├─ build_kernel.bat         用 VS2019 + WDK 10.0.22000 编译成 .sys
│   ├─ KShareRpc.sys            本机编译产出的驱动镜像（**未加载、未运行**）
│   └─ README.md                能做到什么、做不到什么、加载前提
└─ Doc\
    ├─ 01-三层原理.md            每层"解决什么问题 / 怎么做的 / 坑在哪"
    ├─ 02-源码逐行讲解.md        逐文件、逐函数、逐条汇编
    └─ 03-面试问答.md            20 问，含实测数字与踩过的坑
```

---

## 2. 怎么编译、怎么跑

```bat
rem 用户态三层演示器
cd /d "<本目录>\ShareRpcLab"
build.bat
ShareRpcLab.exe all          rem 或 1 / 2 / 3 / selftest

rem 内核接入层（只编译，不加载）
cd /d "<本目录>\Kernel"
build_kernel.bat
```

控制台要看到正常中文，用这个方式起：

```bat
chcp 65001 >nul && ShareRpcLab.exe all > run_all.log 2>&1
```

> 为什么 `.bat` 里一个中文都不能写：`cmd.exe` 按 OEM 代码页解析批处理，
> 非 ASCII 字节会把整行切碎成 `'器' is not recognized` 这种错误。
> 同理，`.c` 文件里的中文必须存成 **UTF-8 带 BOM**，否则 MSVC 按 GBK 读会报 C4819 甚至乱码。

---

## 3. 实测结果（本机 Win10/11 x64，VS2019 v142）

### 3.1 第一层：共享内存

| 项目 | 实测 |
|---|---|
| 段名 | `Local\KShareRpcLab_l1_<pid>`（`Local\` = 只在当前会话可见） |
| 视图 | 64KB，页对齐 |
| 往返 2000 次，平均时延 | **227 / 233 / 262 / 297 / 298 ns**（5 次采样）；全流程跑到过 202 ns，负载高时到 777 ns |
| 数据一致 | 2000 次全部命中期望值，`bad == 0` |
| 拷贝次数 | 0（控制器写 `Payload[32]`，agent 直接在原地址上算校验和） |

时延会随机器负载波动，所以文档里给区间而不是一个"好看"的单点数字——**面试时被追问"你怎么量的"，
答"QPC 计时、预热 200 次排除首次缺页、2000 次取平均、多轮采样看波动"才是站得住的**。

### 3.2 第二层：syscall 直连

```
[L2] NtQueryInformationProcess 的 SSN = 0x19（从 ntdll 机器码里读出来的）
[L2] 打补丁前的原始字节: 4C 8B D1 B8 19 00 00 00 F6 04 25 08 03 FE 7F 01
[L2] 装 hook 之后的字节:   48 B8 A0 1C 6E BD F7 7F 00 00 FF E0
[L2] 路A ntdll 调用 : status=0x00000000, hook 命中 +1
[L2] 路B 直连调用 : status=0x00000000, hook 命中 +0
[L2] 两路返回一致: PebBase=... Pid=... —— 确实是同一个内核服务
[L2] 装 hook 后重新解析 SSN: 失败，imm32 已被 jmp 覆盖 —— 所以载荷里必须“先取号，后干活”
[L2] ntdll 12 字节已按字节比对恢复，进程回到干净状态
[L2] 直连 NtAllocateVirtualMemory 成功: ... (4000 字节已可写)
```

四个可验证结论：

1. 走 ntdll 的调用**必然**踩 hook（命中 +1），直连 syscall **必然不踩**（+0）；
2. 两条路拿到**完全相同**的 `PEB` 地址和 PID，说明落的是同一个内核服务；
3. 被 hook 之后 `mov eax, imm32` 里的 SSN 已经被 jmp 覆盖，**再解析就解析不出来了**
   → 所以真实载荷必须"先取号、后干活"，取号不能放在 hook 之后；
4. 直连 syscall 真能干活：直接 `NtAllocateVirtualMemory` 拿到 RW 内存并写入 8 字节。

### 3.3 第三层：调用链劫持

```
[L3] stub 块已落在共享内存: ...0200, 2032 字节（代码与现场同处一段）
[L3] 第 1 轮: 停点 RIP=... RSP=... -> 改成 stub=...，栈不动
[L3] 第 1 轮: 载荷在 TID=37488 上执行，恢复后跳回 ...
[L3] 第 2 轮 / 第 3 轮: 同上
[L3] 劫持后 50ms 内该线程又自旋了 2296240 次 —— 原调用链完好
[L3] 校验通过: 载荷跑在 worker 老线程上（3 次执行，0 个新线程、0 个 APC）
```

三个可验证结论：

1. 载荷执行的 TID **就是**那条老线程的 TID（不是新线程），进程内线程数不变；
2. 三次劫持后线程仍在原循环里正常自旋（50ms 内 **229 万~454 万次**，多轮采样 2.29M / 3.60M / 4.54M，
   随机器负载波动），**说明寄存器/栈/返回点还原住了**；
3. 整个过程只有 `SuspendThread / GetThreadContext / SetThreadContext / ResumeThread` 四个用户态 API，
   没有 `CreateRemoteThread`、没有 `QueueUserAPC`、没有新栈。

---

## 4. 验证边界（必须先看这一节再往简历上写）

| 能力 | 状态 |
|---|---|
| 第一层 共享内存往返、零拷贝、数据一致 | **已实测通过**（可复现，`ShareRpcLab.exe 1`） |
| 第二层 SSN 解析、hook 命中对比、直连 syscall 实配实写 | **已实测通过**（`ShareRpcLab.exe 2`） |
| 第三层 同进程内借用已有线程、无损返回 | **已实测通过**（`ShareRpcLab.exe 3`） |
| 跨进程劫持（真正打到别的 PID 里） | **未实现**：本机 demo 全在自己进程里跑，因为跨进程要先有"把 stub 块放进目标地址空间"的手段——那正是 Kernel 层要做的第一件事 |
| 内核层 `KShareRpc.sys` | **编译+链接通过**（本机 WDK 10.0.22000），**未加载、未运行**：加载需要测试签名或关闭驱动签名强制，只能在专用 VM 里做 |
| 内核里直接改目标线程上下文 | **不做，也不声称做过**。原因见 `Kernel\README.md`：相关 API 导出状态随版本变化，本机无法验证 |

写简历时请严格按这张表：**"已实测"的就写数字，"编译通过但未加载"的就写编译通过**。
把没跑过的东西写成跑过，是面试里最容易翻车的地方。

---

## 5. 和老代码（Anti911 APC 注入）的对照

| 环节 | 老实现 `KAnti911` | 本工程 |
|---|---|---|
| 通信 | `DeviceIoControl` + `MY_CTL_CODE`（`METHOD_NEITHER`）+ `OPERATE_TYPE` 二次分发 | 同一块物理页的信箱，**零 IOCTL、零句柄传递** |
| 载荷落点 | 每次 `ZwAllocateVirtualMemory` 在目标里新开一块 RWX `INJECT_BUFFER` | stub 块**预置**在共享段里，整块零拷贝共享 |
| 触发执行 | `KeInitializeApc` + `KeInsertQueueApc`，再补一个 `KernelApcKernelCallback` 调 `KeTestAlertThread` | **不排 APC**，改一条已有线程的"下一步" |
| 完成判定 | 内核 `KeDelayExecutionThread` 轮询 `Complete == 0xC0371E7E` | 载荷在同一线程上同步跑完，回调式记账，无轮询 |
| 痕迹 | 新 RWX 区 + APC 对象 + `UserApcPending` + 线程告警 | 无新内存、无 APC 对象；代价是"短暂的挂起/恢复"和 8 字节栈覆盖 |

一句话概括这次升级：**把"新增执行体"换成"借用执行体"，把"每次新建内存"换成"一次建段共享"。**

---

## 6. 已知局限（主动写出来比被问出来强）

1. **8 字节栈覆盖**：stub 收尾用 `mov rsp,[ctx+RSP]` + `push [ctx+RIP]` + `ret` 回跳，
   会在 `原RSP - 8` 处留下 8 字节。选纯自旋停点时那块区域是未使用的红区，实测无影响，
   但**不能宣称"绝对无损"**。
2. **RWX 段**：为了把 stub 放进去，段是 `PAGE_EXECUTE_READWRITE`。真实工程应拆成 RW 数据段 + RX 代码段，
   否则 W^X 策略和 EDR 都会盯上你。
3. **只做 x64**：`CONTEXT` 偏移、stub 编码、syscall 约定全是 x64 的，x86 完全不适用。
4. **停点必须"干净"**：本 demo 刻意只借纯用户态自旋线程。停在内核系统调用里的线程不能这么还原
   （保存的 `RAX` 是服务号，返回值会被内核覆盖），这条在 `Layer3_ChainHijack.c` 头部有完整说明。
5. **不是隐身衣**：直连 syscall 只绕用户态 hook；内核回调、ETW、内核 hook 照样看得见。

---

## 7. 这套东西怎么用于面试

**一句话版本**：把一个"每发都要新开 RWX + 排 APC + 轮询标志"的内核注入，重构成
"共享段做地基、直连 syscall 做调用、借用已有线程做执行"的三层模型，并对每层给出可复现的实测数据。

三个最容易被追问、也最能体现你真跑过的细节：

1. **`NtQueryInformationProcess` 的桩不是 12 字节整齐结构**。本机实测前 12 字节是
   `4C 8B D1 B8 19 00 00 00 F6 04 25 08 03 FE 7F 01`，第 9 字节起是
   `test byte ptr [7FFE0308h], 1`（syscall / int 2Eh 的分派判断）。按 12 字节硬切会把一条指令剪成两半，
   trampoline 一执行就 `0xC0000005`（我实测崩在 trampoline+8，访存地址 `0xFFFFFFFFFCB84808`）。
   **inline hook 偷指令必须落在指令边界**——这条比任何书本结论都硬。
2. **`call` 之后不能拿 `r11` 当基址**。x64 调用约定里 `r11` 是易失寄存器，被调函数可以随便改；
   我的 stub 第一版用 `r11` 存块基址，payload 一返回 `fxrstor [r11+...]` 就 AV（崩在 `block+0x25`）。
   改用 `r14`（callee-saved）才对。
3. **共享内存里那份 `CONTEXT` 是双身份的**：它既是内核的上下文缓冲，又是 stub 的"还原源"。
   如果在 stub 还没跑完时用 `GetThreadContext` 直写这份内存，就把原始现场覆盖成了"stub 内部的现场"，
   `ret` 会跳到垃圾地址（我实测跳到 `0x212`）。**先用局部缓冲读、确认停点合法，再落库**。

---

## 8. 下一步（如果要把这套东西做完整）

- [ ] 把 Kernel 层接上：`KSR_CTL_CREATE_SECTION` → `KSR_CTL_MAP_INTO(pid)` → `KSR_CTL_GET_HANDLE`，
      控制器用返回的句柄 `NtMapViewOfSection` 映射同一块页，就得到**跨进程**的同一块内存；
- [ ] 跨进程劫持：控制器 `OpenThread` 目标线程 → 同一套 `HijackOnce`，但 stub 块已经在目标地址空间里了；
- [ ] 把 RWX 拆成 RW + RX；
- [ ] 在测试签名 VM 里验证内核层加载与卸载（`sc create` / `sc start` / `sc stop`，看 `DbgPrint` 输出）。
