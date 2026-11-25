/* ============================================================================
 * Layer3_ChainHijack.c —— 第三层：调用链劫持（核心）
 *
 * 要解决什么问题？
 *   前两层解决了"内存"和"调用"，但还差最后一件事：让目标进程里的代码跑起来。
 *   常规做法要么建远程线程（CreateRemoteThread / NtCreateThreadEx，会触发内核
 *   线程创建回调），要么往线程里塞 APC（会留下 APC 对象、UserApcPending 标记）。
 *   两者都是"新增"了一个执行体，天生带痕迹。
 *
 *   调用链劫持的思路是"借用"：目标里本来就有一条正在跑的调用链（某个线程停在
 *   某条指令上），我们把它的"下一步"改成我们的 stub，stub 跑完把寄存器、
 *   栈指针、返回地址原样还原，再跳回它原本要执行的指令。
 *   整个过程没有新线程、没有新栈、没有 APC —— 从内核视角看，这条线程一直在
 *   正常跑它自己的代码，只是中间多绕了几条指令。
 *
 * 关键细节（面试常问）：为什么演示里挑一个"纯用户态自旋"的线程当停点？
 *   如果线程停在内核里（比如正卡在 NtWaitForSingleObject），它的保存上下文里
 *   RAX 其实是 syscall 的服务号，而真正的返回值由内核在返回时覆盖。
 *   我们把 RAX 按快照还原，就把这次系统调用的返回值改坏了。
 *   自旋线程不涉及 syscall，整份上下文都是"活"的，还原才严格无损。
 * ==========================================================================*/
#include "KsrLab.h"
#include <stddef.h>

/* CONTEXT 的字段偏移是硬编码在 NtStub.asm 里的，这里编译期对齐校验，
 * 一旦哪天结构变了，编译直接失败，而不是运行时崩在别人进程里。 */
typedef char ksr_assert_ctx_rax [(offsetof(CONTEXT, Rax) == 0x78) ? 1 : -1];
typedef char ksr_assert_ctx_rsp [(offsetof(CONTEXT, Rsp) == 0x98) ? 1 : -1];
typedef char ksr_assert_ctx_rip [(offsetof(CONTEXT, Rip) == 0xF8) ? 1 : -1];
typedef char ksr_assert_ctx_efl [(offsetof(CONTEXT, EFlags) == 0x44) ? 1 : -1];
typedef char ksr_assert_ctx_r11 [(offsetof(CONTEXT, R11)   == 0xD0) ? 1 : -1];
typedef char ksr_assert_ctx_r14 [(offsetof(CONTEXT, R14)   == 0xE8) ? 1 : -1];

typedef struct _KS_TBI
{
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    struct { PVOID UniqueProcess; PVOID UniqueThread; } ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} KS_TBI;

#define KSR_HIJACK_ROUNDS 3

static volatile LONG   g_hijackStop  = 0;
static volatile LONG64 g_spinCount   = 0;
static volatile LONG   g_bodyRuns    = 0;
static volatile LONG   g_bodyDone    = 0;
static volatile LONG64 g_bodyTid     = 0;
static void*           g_sharedBase  = NULL;

/* --------------------------------------------------------------------------
 * 载荷：由 stub 通过 `call qword ptr [rip+slot]` 调进来。
 * 运行环境是"被劫持的那条线程"，栈也是它的栈。
 * 这里故意混用第二层的直连 syscall，证明三层是可以叠在一起的。
 * --------------------------------------------------------------------------*/
static void HijackBody(CONTEXT* ctx)
{
    InterlockedIncrement(&g_bodyRuns);

    /* 第二层联动：不查 TEB、不走 kernel32，直接 syscall 问"我是谁" */
    uint32_t ssn = 0;
    KS_TBI tbi = { 0 };
    if (KsrResolveSsn("NtQueryInformationThread", &ssn))
    {
        NTSTATUS st = (NTSTATUS)KsrNtStub(ssn,
                                          (uint64_t)(uintptr_t)(-2),   /* 伪句柄: 当前线程 */
                                          0,
                                          (uint64_t)(uintptr_t)&tbi,
                                          (uint64_t)sizeof(tbi),
                                          0, 0);
        if (NT_SUCCESS(st))
            InterlockedExchange64(&g_bodyTid, (LONG64)(uintptr_t)tbi.ClientId.UniqueThread);
    }

    KSR_HEADER* hdr = (KSR_HEADER*)g_sharedBase;
    if (hdr)
    {
        InterlockedIncrement64((volatile LONG64*)&hdr->HijackCount);
        InterlockedIncrement64((volatile LONG64*)&hdr->DirectCallCount);
        hdr->AgentTid = (ksr_u32)(uintptr_t)tbi.ClientId.UniqueThread;
        /* 把"停在哪条指令"记下来，方便和 worker 自己的代码段对照 */
        if (ctx) hdr->Reserved1[0] = (ksr_u64)ctx->Rip;
    }

    InterlockedIncrement(&g_bodyDone);     /* 载荷跑完的记号，控制器按它判断收尾 */
}

/* 纯用户态自旋：不发任何 syscall，上下文才是"活"的 */
static DWORD WINAPI WorkerProc(LPVOID param)
{
    (void)param;
    while (g_hijackStop == 0)
    {
        InterlockedIncrement64(&g_spinCount);
        _mm_pause();
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * 挑停点：不是"随便挂起一个线程就改 RIP"。
 *   必须确认它停在我们认识的**用户态代码**里（这里就是自旋循环），
 *   两个理由：
 *   1) 停在内核里的线程，保存上下文里的 RAX 是服务号、返回值会被内核覆盖，
 *      按快照还原就把那次系统调用改坏了；
 *   2) 停在我们自己 stub 里的线程更不能碰 —— 那块内存同时也是 stub 的
 *      "还原源"，往里写一次读取结果就把原始现场覆盖了（我们真踩过：
 *      线程被挂起在 stub 内，GetThreadContext 覆盖了 ctx，stub 收尾时
 *      ret 跳到了 0x212 这个垃圾地址）。
 *   所以 probe 用**局部缓冲**，确认 RIP 落在本模块里之后，才由调用方
 *   把内容写进共享块。
 * 返回 1 时线程**仍处于挂起状态**，由调用方接着改上下文再放行。
 * --------------------------------------------------------------------------*/
static int WaitForSpinStop(HANDLE hWorker, CONTEXT* probe)
{
    HMODULE hSelf = GetModuleHandleA(NULL);

    for (int attempt = 0; attempt < 500; attempt++)
    {
        if (SuspendThread(hWorker) == (DWORD)-1)
            return 0;

        probe->ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hWorker, probe))
        {
            ResumeThread(hWorker);
            return 0;
        }

        HMODULE hMod = NULL;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)(uintptr_t)probe->Rip, &hMod) &&
            hMod == hSelf)
            return 1;                       /* 停在自己的代码里，可以用 */

        ResumeThread(hWorker);              /* 停点不合格（可能还在 stub 里），重来 */
        Sleep(1);
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * 一次劫持：挂起 -> 取上下文 -> 改 RIP -> 放行 -> 等载荷跑完
 * --------------------------------------------------------------------------*/
static int HijackOnce(HANDLE hWorker, char* block, CONTEXT* ctxShared, int round)
{
    CONTEXT probe;                         /* 局部缓冲：先读这里，确认合法再落库 */
    if (!WaitForSpinStop(hWorker, &probe))
    {
        KsrLog("[L3] 第 %d 轮: 500 次尝试都没抓到合适的停点", round);
        return 0;
    }

    DWORD64 origRip = probe.Rip;
    DWORD64 origRsp = probe.Rsp;

    /* 现场落进共享块：stub 结尾要靠这份副本把寄存器/栈/返回点原样还回去 */
    memcpy(ctxShared, &probe, sizeof(CONTEXT));

    /* 把"下一步"指向共享内存里的 stub 入口；栈保持原样，stub 就在原栈上跑，
     * 这样它内部的 call/ret 天然合法，也不用去动别人栈里的内容。 */
    ctxShared->Rip = (DWORD64)(uintptr_t)block;
    ctxShared->ContextFlags = CONTEXT_FULL;

    if (!SetThreadContext(hWorker, ctxShared))
    {
        KsrLog("[L3] 第 %d 轮: SetThreadContext 失败 %lu", round, GetLastError());
        ResumeThread(hWorker);
        return 0;
    }

    /* 关键顺序：SetThreadContext 已经把"入口=RIP"交给了内核，
     * 这里立刻把副本里的 RIP 改回原值 —— stub 结尾要靠它跳回去。
     * 线程此刻仍然挂着，改内存和放行谁先谁后必须自己控好。 */
    ctxShared->Rip = origRip;

    KsrLog("[L3] 第 %d 轮: 停点 RIP=%p RSP=%p -> 改成 stub=%p，栈不动",
           round, (void*)(uintptr_t)origRip, (void*)(uintptr_t)origRsp, block);

    LONG before = g_bodyDone;
    ResumeThread(hWorker);

    /* 等载荷**跑完**（不是刚开始跑）—— 这时候 TID 已经查完，线程也已经
     * 沿着 stub 收尾、回到原来的自旋循环，下一轮才不会挂在 stub 内部。 */
    DWORD t0 = GetTickCount();
    while (g_bodyDone == before)
    {
        _mm_pause();
        if (GetTickCount() - t0 > 200)
        {
            KsrLog("[L3] 第 %d 轮: 等载荷执行超时", round);
            return 0;
        }
    }

    KsrLog("[L3] 第 %d 轮: 载荷在 TID=%llu 上执行，恢复后跳回 %p",
           round, (unsigned long long)g_bodyTid, (void*)(uintptr_t)ctxShared->Rip);

    return 1;
}

int KsrDemo3(void)
{
    KsrBanner("第三层：调用链劫持（核心）");

    HANDLE hMap = NULL;
    void*  base = KsrShareCreate(&hMap, "l3");
    if (!base) return 0;

    int ok = 1;
    KSR_HEADER* hdr = (KSR_HEADER*)base;

    /* ---- 1) 把 stub 块整体搬进共享内存（代码 + 槽位 + FXSAVE + CONTEXT）---- */
    char*  block    = (char*)base + KSR_OFF_STUB;
    size_t stubSize = (size_t)(KsrHijackStubEnd - KsrHijackStub);
    if (stubSize > KSR_STUB_MAX || KSR_OFF_STUB + stubSize > KSR_OFF_MAILBOX)
    {
        KsrLog("[L3] stub 块太大: %llu 字节", (unsigned long long)stubSize);
        KsrShareDestroy(hMap, base);
        return 0;
    }

    /* 用编译期常量核对汇编块的内部布局：
     * asm 用 ORG 钉死偏移，C 这边用同样的数字，任何一边改了另一边的断言就会炸。 */
    if ((size_t)(KsrHijackBodySlot - KsrHijackStub) != KSR_STUB_OFF_SLOT ||
        (size_t)(KsrHijackFxArea   - KsrHijackStub) != KSR_STUB_OFF_FX   ||
        (size_t)(KsrHijackCtx      - KsrHijackStub) != KSR_STUB_OFF_CTX  ||
        stubSize != KSR_STUB_SIZE)
    {
        KsrLog("[L3] stub 块布局与 C 侧常量不一致 (slot=%llu fx=%llu ctx=%llu size=%llu)",
               (unsigned long long)(KsrHijackBodySlot - KsrHijackStub),
               (unsigned long long)(KsrHijackFxArea   - KsrHijackStub),
               (unsigned long long)(KsrHijackCtx      - KsrHijackStub),
               (unsigned long long)stubSize);
        KsrShareDestroy(hMap, base);
        return 0;
    }

    memcpy(block, KsrHijackStub, stubSize);

    /* 用例：载荷指针（唯一需要运行时填的槽，其余全靠 RIP 相对寻址，
     * 所以整块拷到别的进程里也能直接跑） */
    size_t slotOff = (size_t)(KsrHijackBodySlot - KsrHijackStub);
    *(void**)(block + slotOff) = (void*)HijackBody;

    CONTEXT* ctx = (CONTEXT*)(block + (size_t)(KsrHijackCtx - KsrHijackStub));

    hdr->StubBase  = (ksr_u64)(uintptr_t)block;
    hdr->StubSize  = stubSize;
    hdr->ContextVa = (ksr_u64)(uintptr_t)ctx;
    KsrLog("[L3] stub 块已落在共享内存: %p, %llu 字节（代码与现场同处一段）",
           block, (unsigned long long)stubSize);

    {
        char hx[3 * 41] = { 0 };
        for (int i = 0; i < 40; i++)
            sprintf_s(hx + i * 3, 4, "%02X ", (unsigned)(unsigned char)block[i]);
        KsrLog("[L3] stub 前 40 字节: %s", hx);
    }

    if (getenv("KSR_DRY"))
    {
        KsrLog("[L3] KSR_DRY=1：只检查布局与机器码，不执行劫持");
        KsrShareDestroy(hMap, base);
        return 1;
    }

    /* ---- 2) 起一条纯自旋线程当"被借用的调用链" ---- */
    g_hijackStop = 0;
    g_spinCount  = 0;
    g_bodyRuns   = 0;
    g_bodyDone   = 0;
    g_sharedBase = base;

    HANDLE hWorker = CreateThread(NULL, 0, WorkerProc, NULL, 0, NULL);
    if (!hWorker)
    {
        KsrLog("[L3] 起 worker 失败");
        KsrShareDestroy(hMap, base);
        return 0;
    }
    DWORD workerTid = GetThreadId(hWorker);
    Sleep(30);
    KsrLog("[L3] 被借用的线程 TID=%lu，创建后线程总数不变（本轮不再 CreateThread）", workerTid);

    /* ---- 3) 连续劫持三轮 ---- */
    for (int r = 1; r <= KSR_HIJACK_ROUNDS; r++)
    {
        if (!HijackOnce(hWorker, block, ctx, r))
        {
            ok = 0;
            break;
        }
    }

    /* ---- 4) 证明线程没被弄坏：它还在正常自旋 ---- */
    LONG64 s0 = g_spinCount;
    Sleep(50);
    LONG64 s1 = g_spinCount;
    KsrLog("[L3] 劫持后 50ms 内该线程又自旋了 %lld 次 —— 原调用链完好",
           (long long)(s1 - s0));
    if (s1 == s0) ok = 0;

    if (g_bodyTid != (LONG64)workerTid)
    {
        KsrLog("[L3] 异常: 载荷 TID(%llu) != worker TID(%lu)，说明有新执行体",
               (unsigned long long)g_bodyTid, workerTid);
        ok = 0;
    }
    else
    {
        KsrLog("[L3] 校验通过: 载荷跑在 worker 老线程上（%llu 次执行，0 个新线程、0 个 APC）",
               (unsigned long long)g_bodyRuns);
    }

    hdr->HijackRounds = KSR_HIJACK_ROUNDS;
    hdr->SpinCount    = (ksr_u64)g_spinCount;
    hdr->State        = ok ? KSR_STATE_READY : KSR_STATE_FAULT;

    /* ---- 5) 收尾 ---- */
    g_hijackStop = 1;
    WaitForSingleObject(hWorker, 2000);
    CloseHandle(hWorker);
    KsrShareDestroy(hMap, base);

    KsrLog("[L3] 结论: %s", ok ? "借用已有线程执行载荷并无损返回，三层闭环"
                               : "存在失败项，见上面的日志");
    return ok;
}
