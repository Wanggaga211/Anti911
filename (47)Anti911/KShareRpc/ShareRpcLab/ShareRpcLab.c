/* ============================================================================
 * ShareRpcLab.c —— 三层教学器的入口与公共设施
 *
 * 用法：
 *   ShareRpcLab.exe all        跑三层（推荐）
 *   ShareRpcLab.exe 1|2|3      只跑某一层
 *   ShareRpcLab.exe selftest   同 all，但退出码 0/1 可以被脚本判定
 * ==========================================================================*/
#include "KsrLab.h"
#include <stdarg.h>

static LARGE_INTEGER g_freq  = { 0 };
static LARGE_INTEGER g_start = { 0 };

double KsrNowMs(void)
{
    if (g_freq.QuadPart == 0) return 0.0;
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)(t.QuadPart - g_start.QuadPart) * 1000.0 / (double)g_freq.QuadPart;
}

void KsrLog(const char* fmt, ...)
{
    va_list ap;
    printf("[%9.3f ms] ", KsrNowMs());
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

void KsrBanner(const char* title)
{
    printf("\n");
    printf("==============================================================\n");
    printf("  %s\n", title);
    printf("==============================================================\n");
    fflush(stdout);
}

static void PrintMap(void)
{
    printf("\n");
    printf("  三层不是三个并列的招数，而是从下到上叠起来的一条链：\n");
    printf("\n");
    printf("     [3] 调用链劫持  <- 核心：借用目标已有线程，不新建、不挂 APC\n");
    printf("            |  执行\n");
    printf("     [2] syscall 直连 <- 辅助：载荷自己进内核，绕过用户态 hook\n");
    printf("            |  取号/调用\n");
    printf("     [1] 共享内存    <- 地基：参数、载荷、现场、回执全放这一块\n");
    printf("\n");
    printf("  缺了 [1]，[2][3] 没地方放载荷；缺了 [2]，[3] 的载荷一调 API 就被看见；\n");
    printf("  缺了 [3]，[1][2] 只能算通信和调用，还没有真正的“执行体”。\n");
    printf("\n");
    fflush(stdout);
}

int main(int argc, char** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    QueryPerformanceFrequency(&g_freq);
    QueryPerformanceCounter(&g_start);

    const char* mode = (argc > 1) ? argv[1] : "all";

    printf("KShareRpc 教学器 —— 共享内存 / syscall 直连 / 调用链劫持\n");
    printf("PID=%lu  64-bit=%d  仅在你自己拥有和授权的进程上运行\n",
           (unsigned long)GetCurrentProcessId(),
           (int)(sizeof(void*) == 8));

    if (sizeof(void*) != 8)
    {
        printf("本教学器只实现了 x64 版本（x86 的 CONTEXT/stub 布局完全不同）\n");
        return 1;
    }

    int pass = 0, fail = 0;
    int run1 = 0, run2 = 0, run3 = 0;

    if (strcmp(mode, "all") == 0 || strcmp(mode, "selftest") == 0)
    {
        PrintMap();
        run1 = run2 = run3 = 1;
    }
    else if (strcmp(mode, "1") == 0) run1 = 1;
    else if (strcmp(mode, "2") == 0) run2 = 1;
    else if (strcmp(mode, "3") == 0) run3 = 1;
    else
    {
        printf("用法: ShareRpcLab.exe [all|1|2|3|selftest]\n");
        return 2;
    }

    if (run1) { if (KsrDemo1()) pass++; else fail++; }
    if (run2) { if (KsrDemo2()) pass++; else fail++; }
    if (run3) { if (KsrDemo3()) pass++; else fail++; }

    printf("\n--------------------------------------------------------------\n");
    printf("  结果: 通过 %d 项, 失败 %d 项\n", pass, fail);
    printf("--------------------------------------------------------------\n");
    fflush(stdout);

    return (fail == 0) ? 0 : 1;
}
