# Anti911 内核实验手册（Win7 SP1 x64）

> 目标：把 KAnti911 驱动 + 两个客户端 + 靶子程序完整跑通，看到「内核读写用户态内存」「隐藏进程」的真实效果。

---

## 1. 为什么必须是 Win7 SP1 x64

驱动里有一批 **硬编码的 EPROCESS 结构偏移**，全部是 Win7 时代的值：

| 字段 | x64 硬编码值 | 代码位置 |
|---|---|---|
| `ActiveProcessLinks` | `0x188` | `ProcessHelper.c:380`、`ProcessHelper.c:164` |
| `UniqueProcessId` | `0x180` | `ProcessHelper.c:425` |
| `ImageFileName` | `0x2e0` | `ProcessHelper.c:163`、`ProcessHelper.c:164` |
| `_OBJECT_HEADER.Body` | `0x30` | `ProcessHandle.c:320` |

Win10 20H2 之后这几个字段分别跑到 `0x448 / 0x440 / 0x5a8` 附近，Win11 26300 又不完全一样。用错偏移的后果不是报错，是**把垃圾数据当链表指针解引用 → 蓝屏 0x50 / 0x1A**。

所以在 Win7 上跑，不是"图省事"，是**唯一能让这四个文件不经修改就正确工作**的环境。

另外三个环境限制（宿主机 Win11 上已实测确认）：

- `KAnti911.sys` **未签名**（`Get-AuthenticodeSignature` 结果 `NotSigned`）→ Win11 直接拒绝加载，错误 577
- 你的机器 **HVCI（内存完整性）处于开启状态** → 即使开测试签名也会被拒
- Secure Boot 未关闭 → 测试签名无法生效

Win7 虚拟机里这三条都不存在，只要 `testsigning on` 就能加载。

---

## 2. 准备镜像

需要 **Windows 7 SP1 x64 简体中文** 的 ISO，常见 MSDN 原版：

```
cn_windows_7_ultimate_with_sp1_x64_dvd_u_677408.iso
SHA1: 2CE0B2DB34D76ED3F697CE148CB7594432405E23
大小: 3.19 GB
```

下载后校验（PowerShell）：

```powershell
Get-FileHash "路径\cn_windows_7_ultimate_with_sp1_x64_dvd_u_677408.iso" -Algorithm SHA1
```

> 注意：必须是 **x64**。x86 的 `KAnti911.sys` 在 x64 系统上加载会报 127/193。

---

## 3. 建虚拟机（VMware Workstation 17）

| 项目 | 设置 | 原因 |
|---|---|---|
| 硬件兼容性 | **Workstation 12.x** | 17 默认的虚拟硬件太新，Win7 安装阶段可能蓝屏 `0x0000005D` |
| 客户机系统 | Windows 7 x64 | — |
| 磁盘 | **SATA**，40 GB，单文件 | 避免 SCSI 驱动缺失 |
| 内存 / CPU | 2–4 GB / 2 核 | 够用，别开 3D 加速 |
| 网络 | **NAT + E1000**（不要 vmxnet3） | Win7 内置 E1000 驱动，vmxnet3 要装 Tools 才有 |
| 固件 | BIOS（不要 UEFI） | Win7 对 UEFI 支持差 |

如果安装时仍然蓝屏 `0x5D`，关闭虚拟机后编辑 `.vmx` 文件，追加：

```
cpuid.broadwell = FALSE
cpuid.skylake = FALSE
cpuid.coffeelake = FALSE
```

---

## 4. Win7 装完必做的两个补丁

不装这两个，**VMware Tools 装不上**（Tools 12.x 的安装包是 SHA-2 签名的，Win7 原生只认 SHA-1）：

1. **KB4490628** —— 服务堆栈更新（先装）
2. **KB4474419** —— SHA-2 代码签名支持（后装）

两个都从 Microsoft Update Catalog 下载 `.msu` 双击安装，装完重启，再挂载 VMware Tools 安装。

> 装不上 Tools 也能做实验（键盘鼠标能用），只是没有剪贴板共享和自适应分辨率。实在装不上，把 Tools 换成 10.3.x 老版本。

---

## 5. 打开测试签名（核心一步）

虚拟机里以**管理员**运行 cmd：

```bat
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
```

重启后判断是否成功：**桌面右下角出现「测试模式 Windows 7 内部版本 7601」水印**。没有水印 = 没生效，重做。

备选方案（不改启动配置，每次重启都要做）：开机狂按 **F8** → 选「禁用驱动程序签名强制」。

---

## 6. 布置文件

在虚拟机里建英文目录 `C:\Anti911\`（**不要用中文路径**，`sc create` 的 binPath 带中文容易出问题），从宿主机复制 **x64\Debug** 下的 5 个文件：

```
C:\Users\24855\Desktop\简历项目\(47)Anti911\(47)Anti911\x64\Debug\
    KAnti911.sys            (43 KB)
    Anti911.exe
    进程内存管理器.exe
    Test.exe
    InjectDll64.dll
```

再把本目录下的 `load_driver.bat` / `unload_driver.bat` 一起拷进去。

---

## 7. 加载驱动

右键 `load_driver.bat` → **以管理员身份运行**。它做四件事：清旧服务 → `sc create` → `sc start` → `sc query`。

手动等价命令：

```bat
sc create KAnti911 type= kernel start= demand error= normal binPath= "C:\Anti911\KAnti911.sys"
sc start KAnti911
sc query KAnti911
```

成功标志：

```
STATE              : 4  RUNNING
```

### 失败排错表

| 错误码 | 含义 | 处理 |
|---|---|---|
| **577** | 映像签名无法验证 | `testsigning` 没生效，回第 5 步；确认有水印 |
| **1275** | 驱动被策略阻止 | 同上，或改用 F8「禁用驱动签名强制」 |
| **127** | 找不到指定文件 | binPath 写错，或 `.sys` 没在 `C:\Anti911\` |
| **193** | 不是有效的 Win32 程序 | 你拷了 **x86** 的 sys 到 x64 系统 |
| **1058** | 服务被禁用 | `sc config KAnti911 start= demand` |
| **1** | 拒绝访问 | 没用管理员权限 |

卸载用 `unload_driver.bat`（`sc stop` + `sc delete`）。

---

## 8. 打开内核日志（否则看不到任何 DbgPrint）

Win7 默认把 `DbgPrint` 过滤掉了。管理员 cmd：

```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v DEFAULT /t REG_DWORD /d 0xFFFFFFFF /f
```

重启后运行 **DebugView**（Sysinternals 出品，管理员身份）→ 菜单 `Capture` → 勾上 **Capture Kernel**。

驱动加载/卸载时的 `DriverUnload()` 等输出会出现在这里。**这一步不是必须的，但排错时是唯一的信息来源。**

---

## 9. 功能验证（按这个顺序做）

### 9.1 内存读写闭环 —— 最有说服力的一项

1. 运行 `Test.exe`，记下它打印的 **PID** 和三个地址（栈 `v1` / 常量区 `__v1` / 堆 `v2`），不要按键，让它停住。
2. 运行 `进程内存管理器.exe`。
3. 在顶部 PID 输入框填入 Test.exe 的 PID → 点 **确定** → 列表会枚举出该进程的所有内存区域（地址 / 范围 / 类型 / 状态 / 保护）。
4. 找到存放字符串的那块区域（栈或堆，通常是 `PAGE_READWRITE`），**右键** → 「写操作」。
5. 地址填 `Test.exe` 打印的那个地址，数据填新的字符串（比如 `Hacked`）。
6. 回车执行。
7. 切回 `Test.exe`，按任意键 → 它重新打印的三个变量里，你改的那个变成了 `Hacked`。

**这一步的原理**（面试会问）：客户端 `DeviceIoControl` 把 `{OperateType, ProcessIdentity, BaseAddress, RegionSize, BufferData}` 发给驱动 → `IoControlRoutine` 取 `Type3InputBuffer` → `CommunicatNeitherControl` 做 `ProbeForRead/ProbeForWrite` 校验 → 按 `OperateType` 查 `__ServiceArray[]` 跳到 `PsWriteProcessMemory` → `SafeCopyMemoryR32R0` 用 **MDL 把这个物理页映射进内核地址空间**，直接 memcpy，再用 `VirtualProtect` 还原。

顺便可以试：右键 → 「PAGE_NOACCESS」，再让 Test.exe 读那块内存 → 进程直接崩溃（0xC0000005）。这就是改页面保护的效果。

### 9.2 枚举进程句柄

运行 `Anti911.exe`（`_tmain` 里只调了 `EnumProcessHandles()`）。它会找到 `explorer.exe`，然后把这个进程所有句柄的 `Handle / Object / 句柄名 / 对象名` 打出来，**每 10 条暂停一次**，按两次回车继续。

这一项走 `ProcessHandle.c` 的 `Offset = 0x30`（`_OBJECT_HEADER.Body`）——又一处只对 Win7 成立的硬编码。

### 9.3 隐藏进程

`Anti911.exe` 里 `HideProcess()` 是注释掉的，把 `_tmain` 第 17 行改成：

```cpp
//EnumProcessHandles();
HideProcess();
```

重新编译（VS 打开 `Anti911.sln`，选 x64 + Debug），把新 exe 拷进虚拟机。

效果：先开任务管理器 → 跑改过的 `Anti911.exe`（目标写死是 `taskmgr.exe`）→ **任务管理器从进程列表里消失**（窗口还在）。

原理是 `RemoveEntryList` 把 `ActiveProcessLinks` 从双向链表上摘下来。注意：这会触发 **PatchGuard（蓝屏 0x109）**，Win7 x64 上通常能撑几分钟到几小时，**看完效果就重启**，别常开。

### 9.4 进程保护

同理取消注释 `ProtectProcess()`。它保护 `explorer.exe` 和 `taskmgr.exe`：之后用任务管理器结束它们会失败（返回拒绝访问）。按回车解除。

---

## 10. 蓝屏了怎么办

| Bug Check | 原因 | 恢复 |
|---|---|---|
| `0x50` / `0x1A` | 偏移错、链表走飞 | 安全模式 → `sc delete KAnti911` |
| `0x109` | PatchGuard 检测到结构篡改（隐藏进程后） | 重启即可，不用删驱动 |
| `0x3B` / `0x7E` | 驱动里有空指针/异常没兜住 | 重启 → 安全模式卸载 |

虚拟机里随便蓝，**别在物理机上试**。恢复手段：VM 启动时按 F8 进安全模式 → 跑 `unload_driver.bat`。

---

## 11. 面试怎么讲（三句话版）

1. **架构**：WDM 驱动创建设备 `\Device\KAnti911` 并注册 `IRP_MJ_DEVICE_CONTROL` 派发例程，用户态通过 `CreateFile("\\.\KAnti911")` + `DeviceIoControl` 通信，`METHOD_NEITHER` 下自己做 `ProbeForRead/Write` 校验。
2. **能力**：进程枚举/隐藏（摘 `ActiveProcessLinks`）、进程保护、句柄枚举（走 `_OBJECT_HEADER`）、跨进程内存读写（MDL 映射物理页）、APC 注入。
3. **关键取舍**：跨进程读写没用 `KeStackAttachProcess`，而是用 MDL 把目标物理页映射到内核空间直接访问 —— 好处是不切 CR3 更快，代价是要自己处理页保护还原和 `MmIsAddressValid` 校验。

---

## 附：文件清单

| 文件 | 说明 |
|---|---|
| `load_driver.bat` | 一键 `sc create` + `sc start`，带错误码解释 |
| `unload_driver.bat` | `sc stop` + `sc delete` |
| `Anti911实验手册.md` | 本文件 |
