/* ============================================================================
 * Layer1_SharedMem.c —— 第一层：共享内存（地基）
 *
 * 要解决什么问题？
 *   驱动/控制端和"目标进程里的 agent"原本只能通过 DeviceIoControl 说话：
 *   每次都要建 IRP、切换内核栈、拷 buffer。慢、留痕、还被安全软件盯着。
 *   共享内存是更底层的办法：把同一块物理页同时映射进两边地址空间，
 *   双方各自读写自己的虚拟地址，看到的是同一块物理内存 —— 不用任何 API 通信。
 *
 * 这一层不涉及任何"执行"，它只提供：一块双方都认得的、带协议的内存。
 * 后面两层（直连 syscall、调用链劫持）都靠这块内存放参数、放载荷、放现场。
 * ==========================================================================*/
#include "KsrLab.h"

#define KSR_PING_ROUNDS 2000

static volatile LONG g_agentStop = 0;

/* --------------------------------------------------------------------------
 * 建段 + 映射 + 初始化段头
 * 返回值：本进程内的视图片基址；失败返回 NULL
 * --------------------------------------------------------------------------*/
void* KsrShareCreate(HANDLE* phMap, const char* tag)
{
    char name[128];
    sprintf_s(name, sizeof(name), "Local\\KShareRpcLab_%s_%lu",
              tag, (unsigned long)GetCurrentProcessId());

    /* PAGE_EXECUTE_READWRITE：因为第三层要把可执行的 stub 直接放进来。
     * 真实工程里应拆成两块：一块 RW 放数据，一块 RX 放代码。 */
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                     PAGE_EXECUTE_READWRITE,
                                     (DWORD)((ULONGLONG)KSR_SECTION_SIZE >> 32),
                                     (DWORD)(KSR_SECTION_SIZE & 0xFFFFFFFF),
                                     name);
    if (!hMap)
    {
        KsrLog("[L1] CreateFileMapping 失败, err=%lu", GetLastError());
        return NULL;
    }

    void* base = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
    if (!base)
    {
        KsrLog("[L1] MapViewOfFile 失败, err=%lu", GetLastError());
        CloseHandle(hMap);
        return NULL;
    }

    /* 段头初始化：这一步就是"协议握手"，缺一个字段后面全错 */
    KSR_HEADER* hdr = (KSR_HEADER*)base;
    hdr->Magic      = KSR_MAGIC;
    hdr->Version    = KSR_VERSION;
    hdr->HeaderSize = (ksr_u32)sizeof(KSR_HEADER);
    hdr->State      = KSR_STATE_READY;

    if (phMap) *phMap = hMap;
    KsrLog("[L1] 段已建立: %s", name);
    KsrLog("[L1] 映视图基址 = %p, 大小 = %u KB", base, KSR_SECTION_SIZE / 1024);
    return base;
}

void KsrShareDestroy(HANDLE hMap, void* base)
{
    if (base) UnmapViewOfFile(base);
    if (hMap) CloseHandle(hMap);
}

/* --------------------------------------------------------------------------
 * 模拟"目标进程里的 agent"：一个线程守着信箱
 * 真实工程里，这个线程由第一次 bootstrap 注入（你现在的 APC 注入）带进去，
 * 之后所有交互都走这段共享内存，不再需要 IOCTL。
 * --------------------------------------------------------------------------*/
static DWORD WINAPI AgentProc(LPVOID param)
{
    void* base = param;
    KSR_HEADER*  hdr = (KSR_HEADER*)base;
    volatile KSR_MAILBOX* mb = (volatile KSR_MAILBOX*)((char*)base + KSR_OFF_MAILBOX);

    hdr->AgentPid = GetCurrentProcessId();
    hdr->AgentTid = GetCurrentThreadId();

    uint32_t lastSeq = 0;
    while (g_agentStop == 0)
    {
        uint32_t seq = mb->Seq;
        if (seq != lastSeq)
        {
            lastSeq = seq;
            if (mb->Cmd == KSR_CMD_CHECKSUM)
            {
                /* 注意：这里读的就是控制器写的那 256 字节，一个字节都没拷 */
                uint64_t sum = mb->Arg0;
                for (int i = 0; i < 32; i++)
                    sum += mb->Payload[i] * (uint64_t)(i + 1);
                mb->Result0 = sum;
            }
            else if (mb->Cmd == KSR_CMD_PING)
            {
                mb->Result0 = mb->Arg0 ^ 0x5A5A5A5A5A5A5A5Aull;
            }
            mb->Status = 0;
            _ReadWriteBarrier();          /* 保证 Result0 先落地，再置 Done */
            mb->Done   = 1;
            hdr->AckSeq = seq;
        }
        _mm_pause();                      /* 别把核心烧穿，也别退化成 Sleep 让时延虚高 */
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * 演示：往返 2000 次，统计时延，并校验数据一致性
 * --------------------------------------------------------------------------*/
int KsrDemo1(void)
{
    KsrBanner("第一层：共享内存（地基）");

    HANDLE hMap = NULL;
    void*  base = KsrShareCreate(&hMap, "l1");
    if (!base) return 0;

    KSR_HEADER*  hdr = (KSR_HEADER*)base;
    volatile KSR_MAILBOX* mb = (volatile KSR_MAILBOX*)((char*)base + KSR_OFF_MAILBOX);

    if (hdr->Magic != KSR_MAGIC || hdr->HeaderSize != sizeof(KSR_HEADER))
    {
        KsrLog("[L1] 段头校验失败，布局不一致");
        KsrShareDestroy(hMap, base);
        return 0;
    }

    g_agentStop = 0;
    HANDLE hAgent = CreateThread(NULL, 0, AgentProc, base, 0, NULL);
    if (!hAgent)
    {
        KsrLog("[L1] 起 agent 线程失败");
        KsrShareDestroy(hMap, base);
        return 0;
    }
    Sleep(20);

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);

    uint64_t totalNs = 0, samples = 0;
    int bad = 0;

    /* 预热 200 次，别把首次缺页算进平均值 */
    for (int warm = 0; warm < 200; warm++)
    {
        mb->Cmd = KSR_CMD_PING; mb->Arg0 = 0x1000 + warm; mb->Done = 0;
        _ReadWriteBarrier(); mb->Seq = (uint32_t)(warm + 1);
        while (mb->Done == 0) { _mm_pause(); if ((warm % 64) == 0) Sleep(0); }
    }

    for (int i = 0; i < KSR_PING_ROUNDS; i++)
    {
        /* 控制器只写 Payload 和 Seq，不做任何拷贝 */
        for (int k = 0; k < 32; k++)
            mb->Payload[k] = (uint64_t)(i * 32 + k);

        mb->Cmd  = KSR_CMD_CHECKSUM;
        mb->Arg0 = 0xA5A5A5A500000000ull | (uint64_t)i;
        mb->Done = 0;
        _ReadWriteBarrier();

        QueryPerformanceCounter(&t0);
        mb->Seq = (uint32_t)(i + 1000);

        int guard = 0;
        while (mb->Done == 0)
        {
            _mm_pause();
            if (++guard > 200000000) break;      /* 约 200ms 级超时 */
        }
        QueryPerformanceCounter(&t1);

        if (mb->Done == 0)
        {
            KsrLog("[L1] 第 %d 次超时（agent 没被调度到）", i);
            bad++;
            break;
        }

        uint64_t expect = mb->Arg0;
        for (int k = 0; k < 32; k++)
            expect += (uint64_t)(i * 32 + k) * (uint64_t)(k + 1);

        if (mb->Result0 != expect)
        {
            if (bad < 3)
                KsrLog("[L1] 第 %d 次校验不符: got %llx, want %llx",
                       i, (unsigned long long)mb->Result0, (unsigned long long)expect);
            bad++;
        }

        totalNs += (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000000000ull / freq.QuadPart);
        samples++;
    }

    if (samples)
        KsrLog("[L1] %llu 次往返，平均 %llu ns/次（%.2f us）",
               (unsigned long long)samples,
               (unsigned long long)(totalNs / samples),
               (double)totalNs / (double)samples / 1000.0);

    hdr->RttTotalNs = totalNs;
    hdr->RttSamples = samples;
    hdr->State      = (bad == 0) ? KSR_STATE_READY : KSR_STATE_FAULT;

    KsrLog("[L1] 结论: 同一块物理页，控制器写 / agent 读，%s",
           bad == 0 ? "数据一致、全程零拷贝" : "存在不一致，检查内存序");

    InterlockedExchange(&g_agentStop, 1);
    WaitForSingleObject(hAgent, 2000);
    CloseHandle(hAgent);
    KsrShareDestroy(hMap, base);

    return (bad == 0);
}
