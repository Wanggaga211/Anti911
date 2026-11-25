/* ============================================================================
 * Layer2_DirectSyscall.c —— 第二层：syscall 直连（辅助）
 *
 * 要解决什么问题？
 *   Ring3 调一个 Nt* 函数，正常路线是 kernel32 -> ntdll -> syscall 指令 -> 内核。
 *   安全软件要监控你，最省事的位置就是 ntdll 里那几条指令的开头（inline hook：
 *   把前 12 字节改成 jmp 到它自己的函数）。于是"调用"这件事本身就被它看见了。
 *
 * 直连 syscall 就是绕开这一层：
 *   自己找到服务号 SSN（就是 ntdll 里 `mov eax, imm32` 那个 immediat），
 *   自己写一条 `mov r10, rcx; mov eax, ssn; syscall; ret`，
 *   从自己的代码里直接进内核 —— ntdll 的入口一次都没被经过。
 *
 * 注意边界：这只能绕"用户态的 hook"。内核里的回调、ETW、内核 hook 依然看得见，
 *          它不是什么隐身衣，只是把"调用路径"换成了一条更短、没人蹲守的路。
 * ==========================================================================*/
#include "KsrLab.h"

/* ------------------------------------------------------------------------- */
/* SSN 解析                                                                   */
/* ------------------------------------------------------------------------- */
BOOL KsrResolveSsn(const char* funcName, uint32_t* ssn)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll || !ssn) return FALSE;

    uint8_t* p = (uint8_t*)GetProcAddress(ntdll, funcName);
    if (!p) return FALSE;

    /* 有的函数在 ntdll 里只是个转发桩：jmp 到真正的实现，要跟几跳 */
    for (int hop = 0; hop < 8; hop++)
    {
        if (p[0] == 0xE9)                       /* jmp rel32 */
        {
            p = p + 5 + *(int32_t*)(p + 1);
            continue;
        }
        if (p[0] == 0xEB)                       /* jmp rel8  */
        {
            p = p + 2 + *(int8_t*)(p + 1);
            continue;
        }

        /* 48 B8 = mov rax, imm64：这是被 inline hook 过后的典型痕迹。
         * 此时原来的 `mov eax, imm32` 已经没了，SSN 也就读不到了。 */
        if (p[0] == 0x48 && p[1] == 0xB8)
            return FALSE;

        /* 标准桩：4C 8B D1        mov r10, rcx
         *          B8 xx xx xx xx  mov eax, ssn
         *          0F 05            syscall
         *          C3               ret      */
        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
        {
            *ssn = *(uint32_t*)(p + 4);
            return TRUE;
        }

        /* 少数版本会在 mov r10, rcx 之后先夹一条别的指令，这里只做兜底：
         * 在前 32 字节内找 `B8 imm32 0F 05` 的组合 */
        for (int i = 0; i < 24; i++)
        {
            if (p[i] == 0xB8 && p[i + 5] == 0x0F && p[i + 6] == 0x05)
            {
                *ssn = *(uint32_t*)(p + i + 1);
                return TRUE;
            }
        }
        return FALSE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------------- */
/* 演示：在 ntdll 上装一个"假 EDR"的 inline hook，对比两条路径                */
/* ------------------------------------------------------------------------- */
typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)
    (HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct _KS_PBI
{
    PVOID     Reserved1;
    PVOID     PebBaseAddress;
    PVOID     Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID     Reserved3;
} KS_PBI;

static BYTE*  g_hookTarget = NULL;
static BYTE   g_hookOrig[12];
static LONG   g_hookHit = 0;
static uint32_t g_hookSsn = 0;

/* 崩溃定位用：记录被捕获的异常码和访存地址 */
static DWORD     g_excCode = 0;
static ULONG_PTR g_excAddr = 0;
static ULONG_PTR g_excPc   = 0;
static ULONG_PTR g_excInfo0 = 0;
static int RecordFilter(DWORD code, PEXCEPTION_POINTERS ep)
{
    g_excCode = code;
    g_excPc   = (ULONG_PTR)(ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : 0);
    g_excInfo0 = (ep && ep->ExceptionRecord && ep->ExceptionRecord->NumberParameters >= 1)
                 ? ep->ExceptionRecord->ExceptionInformation[0] : 0;
    g_excAddr = (ep && ep->ExceptionRecord && ep->ExceptionRecord->NumberParameters >= 2)
                ? ep->ExceptionRecord->ExceptionInformation[1] : 0;
    return EXCEPTION_EXECUTE_HANDLER;
}

/* hook 函数：记录一次命中，然后"代替"原函数完成调用。
 *
 * 这里故意不复刻原函数的机器码（不做 trampoline），原因见日志和文档：
 * Win10/11 的 Nt* 桩并不是"mov r10,rcx / mov eax,ssn / syscall / ret"这 12 个
 * 字节，第 9 字节开始是一条 `test byte ptr [7FFE0308h],1` 的分派判断（决定走
 * syscall 还是 int 2Eh）。按 12 字节硬切会把一条指令从中间剪断，拷进
 * trampoline 一执行就是 AV。
 * 既然我们知道它本质就是"eax=ssn; syscall"，那就直接补一条同样的系统调用，
 * 语义完全等价，而且不依赖指令长度。 */
static NTSTATUS NTAPI FakeEdrHook(HANDLE proc, ULONG cls, PVOID buf, ULONG len, PULONG ret)
{
    InterlockedIncrement(&g_hookHit);
    return (NTSTATUS)KsrNtStub(g_hookSsn,
                               (uint64_t)(uintptr_t)proc,
                               (uint64_t)cls,
                               (uint64_t)(uintptr_t)buf,
                               (uint64_t)len,
                               (uint64_t)(uintptr_t)ret,
                               0);
}

static BOOL HookInstall(BYTE* target, void* hookFn)
{
    g_hookTarget = target;
    memcpy(g_hookOrig, target, 12);

    /* 入口打补丁：48 B8 <hook> FF E0  =  mov rax, hook ; jmp rax
     * 注意这 12 字节很可能把原函数的一条指令切成两半，被切掉的尾巴会变成
     * 不可达的"死字节"。所以 patch 长度必须 >= 我们写进去的 12 字节，
     * 恢复时也按同样长度原样写回。 */
    DWORD old = 0, tmp = 0;
    if (!VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;

    BYTE patch[12];
    patch[0] = 0x48; patch[1] = 0xB8;
    *(void**)(patch + 2) = hookFn;
    patch[10] = 0xFF; patch[11] = 0xE0;
    memcpy(target, patch, 12);

    VirtualProtect(target, 16, old, &tmp);
    FlushInstructionCache(GetCurrentProcess(), target, 12);
    return TRUE;
}

static BOOL HookRestore(void)
{
    if (!g_hookTarget) return FALSE;
    DWORD old = 0, tmp = 0;
    VirtualProtect(g_hookTarget, 16, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_hookTarget, g_hookOrig, 12);            /* 把原始 12 字节放回去 */
    VirtualProtect(g_hookTarget, 16, old, &tmp);
    FlushInstructionCache(GetCurrentProcess(), g_hookTarget, 12);
    return memcmp(g_hookTarget, g_hookOrig, 12) == 0;
}

int KsrDemo2(void)
{
    KsrBanner("第二层：syscall 直连（辅助）");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* pQip = (BYTE*)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!pQip)
    {
        KsrLog("[L2] 找不到 NtQueryInformationProcess");
        return 0;
    }

    /* 先解析一次 SSN —— 必须在装 hook 之前，因为 hook 会把 imm32 抹掉 */
    uint32_t ssn = 0;
    if (!KsrResolveSsn("NtQueryInformationProcess", &ssn))
    {
        KsrLog("[L2] SSN 解析失败");
        return 0;
    }
    KsrLog("[L2] NtQueryInformationProcess 的 SSN = 0x%X（从 ntdll 机器码里读出来的）", ssn);

    /* 装"假 EDR" */
    KsrLog("[L2] 打补丁前的原始字节: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
           pQip[0], pQip[1], pQip[2], pQip[3], pQip[4], pQip[5], pQip[6], pQip[7],
           pQip[8], pQip[9], pQip[10], pQip[11], pQip[12], pQip[13], pQip[14], pQip[15]);

    if (!HookInstall(pQip, (void*)FakeEdrHook))
        return 0;

    g_hookSsn = ssn;                 /* hook 内部要用它"代替"原函数 */
    KsrLog("[L2] 已在 ntdll!NtQueryInformationProcess 头部装上 12 字节 jmp（模拟 EDR hook）");

    KS_PBI a = { 0 }, b = { 0 };
    int bad = 0;

    KsrLog("[L2] 装 hook 之后的字节:   %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
           pQip[0], pQip[1], pQip[2], pQip[3], pQip[4], pQip[5],
           pQip[6], pQip[7], pQip[8], pQip[9], pQip[10], pQip[11]);
    KsrLog("[L2] hook 入口=%p（命中后自己补一条 syscall，语义等价）", (void*)FakeEdrHook);

    /* --- 路 A：走 ntdll（正常路线，会踩到 hook） --- */
    LONG c0 = g_hookHit;
    g_excCode = 0; g_excAddr = 0; g_excPc = 0; g_excInfo0 = 0;
    NTSTATUS stA = 0;
    __try
    {
        stA = ((PFN_NtQueryInformationProcess)pQip)(GetCurrentProcess(), 0, &a, sizeof(a), NULL);
    }
    __except (RecordFilter(GetExceptionCode(), GetExceptionInformation()))
    {
        KsrLog("[L2] 路A 触发异常: code=0x%08X, 指令地址=%p, type=%llu, 访存地址=%p",
               g_excCode, (void*)g_excPc, (unsigned long long)g_excInfo0, (void*)g_excAddr);
        stA = (NTSTATUS)0xC0000000;
    }
    LONG c1 = g_hookHit;
    KsrLog("[L2] 路A ntdll 调用 : status=0x%08X, hook 命中 +%ld", (unsigned)stA, (long)(c1 - c0));
    if (c1 - c0 != 1) bad++;

    /* --- 路 B：直连 syscall（不经过 ntdll） --- */
    NTSTATUS stB = (NTSTATUS)KsrNtStub(ssn,
                                       (uint64_t)(uintptr_t)GetCurrentProcess(),
                                       0,
                                       (uint64_t)(uintptr_t)&b,
                                       (uint64_t)sizeof(b),
                                       0, 0);
    LONG c2 = g_hookHit;
    KsrLog("[L2] 路B 直连调用 : status=0x%08X, hook 命中 +%ld", (unsigned)stB, (long)(c2 - c1));
    if (c2 - c1 != 0) bad++;

    /* 两条路必须给出一样的答案，才叫"同一条内核路径" */
    if (stA == stB && memcmp(&a, &b, sizeof(a)) == 0)
        KsrLog("[L2] 两路返回一致: PebBase=%p, Pid=%llu —— 确实是同一个内核服务",
               a.PebBaseAddress, (unsigned long long)a.UniqueProcessId);
    else
    {
        KsrLog("[L2] 两路结果不一致");
        bad++;
    }

    /* --- 附带教学点：被 hook 之后再解析 SSN 会失败 --- */
    uint32_t ssn2 = 0;
    BOOL ok2 = KsrResolveSsn("NtQueryInformationProcess", &ssn2);
    KsrLog("[L2] 装 hook 后重新解析 SSN: %s —— 所以载荷里必须“先取号，后干活”",
           ok2 ? "居然成功了(版本差异?)" : "失败，imm32 已被 jmp 覆盖");

    /* --- 收尾：把 ntdll 恢复原状 --- */
    if (!HookRestore())
    {
        KsrLog("[L2] ntdll 恢复失败！");
        bad++;
    }
    else
    {
        KsrLog("[L2] ntdll 12 字节已按字节比对恢复，进程回到干净状态");
    }

    /* --- 顺手证明直连 syscall 能真干活：分配 + 释放 --- */
    uint32_t ssnAlloc = 0, ssnFree = 0;
    if (KsrResolveSsn("NtAllocateVirtualMemory", &ssnAlloc) &&
        KsrResolveSsn("NtFreeVirtualMemory", &ssnFree))
    {
        PVOID  base = NULL;
        SIZE_T size = 4096;
        NTSTATUS st = (NTSTATUS)KsrNtStub(ssnAlloc,
                                         (uint64_t)(uintptr_t)GetCurrentProcess(),
                                         (uint64_t)(uintptr_t)&base,
                                         0,
                                         (uint64_t)(uintptr_t)&size,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);

        if (NT_SUCCESS(st) && base)
        {
            *(volatile uint64_t*)base = 0x1122334455667788ull;   /* 真写一下才叫可用 */
            KsrLog("[L2] 直连 NtAllocateVirtualMemory 成功: %p (4000 字节已可写)", base);

            SIZE_T freeSize = 0;
            NTSTATUS stf = (NTSTATUS)KsrNtStub(ssnFree,
                                              (uint64_t)(uintptr_t)GetCurrentProcess(),
                                              (uint64_t)(uintptr_t)&base,
                                              (uint64_t)(uintptr_t)&freeSize,
                                              MEM_RELEASE, 0, 0);
            if (!NT_SUCCESS(stf)) { KsrLog("[L2] 直连释放失败 0x%08X", (unsigned)stf); bad++; }
        }
        else
        {
            KsrLog("[L2] 直连分配失败 0x%08X", (unsigned)st);
            bad++;
        }
    }
    else
    {
        bad++;
    }

    KsrLog("[L2] 结论: 用户态 hook 只蹲在 ntdll 门口，直连 syscall 从旁边直接进门；%s",
           bad == 0 ? "本轮全部校验通过" : "本轮有失败项");

    return (bad == 0);
}
