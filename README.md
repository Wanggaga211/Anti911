# Anti911 —— Win7 x64 内核进程隐藏与驱动实验

> **用途声明**：本项目仅用于 **Windows 7 SP1 x64 虚拟机** 中的授权实验环境，用于学习内核态进程管理、驱动与用户态通信、以及检测对抗的基本原理。请勿在任何未授权的设备上使用。

## 这是什么

一个「用户态控制端 + 内核驱动」的双端实验项目：

- **用户态** `Anti911.exe` 负责界面与命令组织，通过 `DeviceIoControl` 向驱动下发控制码；
- **内核态** `KAnti911.sys` 在 Ring0 完成进程枚举、进程链表摘除（隐藏）、目标进程内存读写、内核 Inline Hook 与 APC 注入。

驱动里用到的 `EPROCESS` 偏移全部按 Win7 SP1 x64 **硬编码**（`ActiveProcessLinks 0x188`、`UniqueProcessId 0x180`、`ImageFileName 0x2e0`、`_OBJECT_HEADER.Body 0x30`）。这不是偷懒，而是刻意的实验设定：偏移随系统版本变化，换个版本直接解引用就会蓝屏 `0x50 / 0x1A`，所以这份代码只在 Win7 上成立。

## 目录结构

```
(47)Anti911/                 ← 仓库根
├── Anti911实验手册.md       环境搭建、镜像校验、加载与实验步骤（建议先读）
├── load_driver.bat          加载驱动
├── unload_driver.bat        卸载驱动
├── 操作说明.txt             实测操作记录
├── (47)Anti911/             解决方案目录
│   ├── Anti911.sln          VS 解决方案（v142 / VS2019）
│   ├── Anti911/             用户态控制端（Application，Unicode，v142）
│   └── KAnti911/            内核驱动工程（WDM，WindowsKernelModeDriver10.0）
└── 进程内存管理器/           配套的进程内存查看工具
```

## 技术点

| 模块 | 文件 | 作用 |
|---|---|---|
| 驱动入口与分发 | `DriverEntry.c`、`IoControlRoutine.c` | 创建设备对象、注册 IOCTL 分发 |
| 进程枚举 / 隐藏 | `ProcessHelper.c`、`ProcessHandle.c` | 按偏移遍历 `ActiveProcessLinks` 并摘链 |
| 进程内存读写 | `ProcessMemory.c`、`MemoryHelper.c` | 内核态读写目标进程地址空间 |
| 内核 Inline Hook | `InlineHook.c`、`HookHelper.c`、`KiFastCall.c` | 指令改写与跳转 |
| APC 注入 | `ApcInject.c`、`InjectHelper.c` | 向目标线程插入 APC 执行载荷 |
| 辅助 | `FakeService.c`、`CallbackHelper.c`、`PeHelper.c`、`ObjectHelper.c` | 服务伪装、回调注册、PE 与对象解析 |

## 环境要求

| 项 | 要求 |
|---|---|
| 操作系统 | Windows 7 SP1 x64（虚拟机） |
| 驱动签名 | 驱动未签名，需在虚拟机内 `bcdedit /set testsigning on` 并重启 |
| 编译环境 | 用户态：VS2019（v142）；驱动：**WDK for VS2019**（`WindowsKernelModeDriver10.0`） |

**不要在 Win10/11 宿主机上尝试**：一是 EPROCESS 偏移已经变了，二是 HVCI（内存完整性）和 Secure Boot 会直接拒绝加载未签名驱动（错误 577）。实验手册里有完整的规避说明。

## 实验内容

1. 搭建 Win7 SP1 x64 虚拟机，开启测试签名；
2. 安装/加载 `KAnti911.sys`，用 `load_driver.bat` 走通通信；
3. 运行控制端，验证进程隐藏、内存读写；
4. 用 `进程内存管理器` 与任务管理器对照，观察隐藏前后差异。

完整步骤、镜像 SHA1 校验、错误排查都写在 `Anti911实验手册.md` 里。

## 免责声明

本项目为个人学习与课程实验产物，所有实验均在自建虚拟机中完成。作者不对任何非授权使用承担责任；若你 fork 本项目，请同样只在隔离的、自己拥有的环境中运行。
