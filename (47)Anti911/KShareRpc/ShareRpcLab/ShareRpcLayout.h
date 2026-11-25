#pragma once
/* ============================================================================
 * ShareRpcLayout.h  —— 共享内存段的布局与协议
 *
 * 这个头文件是「Ring3 教学器」和「Ring0 驱动」唯一共用的文件。
 * 规则：里面只能出现两边都认得的类型和常量（u32/u64 + 固定偏移），
 *       不许出现 CRT 头文件、不许出现 HANDLE/CONTEXT 这类只属于某一侧的
 *       结构，否则驱动编译不过。
 *
 * 内存视图（64 KB 一段）：
 *   0x0000  KSR_HEADER   段头：魔数/版本/序号/统计
 *   0x0200  stub 块      可执行的载荷 + FXSAVE 区 + CONTEXT 副本
 *   0x1000  KSR_MAILBOX  命令信箱（请求/应答，零拷贝传参）
 *   0x2000  日志区       给演示看的文本
 * ==========================================================================*/

#ifdef KSR_KERNEL
#include <fltKernel.h>
typedef ULONG   ksr_u32;
typedef ULONG64 ksr_u64;
#else
#include <stdint.h>
typedef uint32_t ksr_u32;
typedef uint64_t ksr_u64;
#endif

#define KSR_MAGIC           0x4B535252u     /* 'KSRR'，用来判断这段内存是不是我们的 */
#define KSR_VERSION         1u
#define KSR_SECTION_SIZE    (64u * 1024u)   /* 一段 64 KB，够教学用 */

#define KSR_OFF_HEADER      0x0000u
#define KSR_OFF_STUB        0x0200u         /* stub 块：代码 + 槽位 + FXSAVE + CONTEXT */
#define KSR_OFF_MAILBOX     0x1000u
#define KSR_OFF_LOG         0x2000u

#define KSR_STUB_MAX        0x0E00u         /* stub 块上限，必须 <= MAILBOX-STUB */

/* 段头状态机 */
#define KSR_STATE_EMPTY     0u
#define KSR_STATE_READY     1u
#define KSR_STATE_BUSY      2u
#define KSR_STATE_FAULT     3u

/* 信箱命令 */
#define KSR_CMD_NONE        0u
#define KSR_CMD_PING        1u              /* 只回一个固定值，测往返时延 */
#define KSR_CMD_CHECKSUM    2u              /* 让 agent 对 Payload[] 求和，验证零拷贝 */

/* ------------------------------------------------------------------------- */
typedef struct _KSR_HEADER
{
    ksr_u32 Magic;          /* 必须等于 KSR_MAGIC */
    ksr_u32 Version;        /* 必须等于 KSR_VERSION */
    ksr_u32 HeaderSize;     /* sizeof(KSR_HEADER)，防止两侧结构体不一致 */
    ksr_u32 State;

    ksr_u32 Seq;            /* 当前请求序号（控制器自增） */
    ksr_u32 AckSeq;         /* agent 已处理到的序号 */
    ksr_u32 AgentPid;
    ksr_u32 AgentTid;

    ksr_u32 LastStatus;     /* 最近一次命令的 NTSTATUS */
    ksr_u32 HijackRounds;   /* 调用链劫持轮数 */
    ksr_u32 HostOsBuild;    /* 留给驱动填版本号，便于排查布局不一致 */
    ksr_u32 Reserved0;

    ksr_u64 StubBase;       /* stub 块在本进程内的虚拟地址（目标侧视角） */
    ksr_u64 StubSize;       /* 实际拷入的字节数 */
    ksr_u64 ContextVa;      /* CONTEXT 副本地址 */
    ksr_u64 HijackCount;    /* 载荷被执行的总次数 */
    ksr_u64 DirectCallCount;/* 直连 syscall 次数 */
    ksr_u64 SpinCount;      /* 被劫持线程的自旋计数（证明它还在正常跑） */
    ksr_u64 RttTotalNs;
    ksr_u64 RttSamples;
    ksr_u64 Reserved1[6];
} KSR_HEADER;

/* ------------------------------------------------------------------------- */
typedef struct _KSR_MAILBOX
{
    ksr_u32 Cmd;            /* KSR_CMD_xxx */
    ksr_u32 Done;           /* agent 处理完置 1，控制器清 0 */
    ksr_u32 Seq;            /* 与请求序号配对 */
    ksr_u32 Status;

    ksr_u64 Arg0;
    ksr_u64 Arg1;
    ksr_u64 Result0;
    ksr_u64 Result1;

    ksr_u64 Payload[32];    /* 256 字节：请求参数直接放这儿，不做拷贝 */
} KSR_MAILBOX;
