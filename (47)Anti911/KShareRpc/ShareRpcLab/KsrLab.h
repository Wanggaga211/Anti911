#pragma once
/* ============================================================================
 * KsrLab.h —— 教学器内部的统一声明
 * ==========================================================================*/
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>
#include "ShareRpcLayout.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* stub 块内固定偏移（与 NtStub.asm 里的 OFF_* 一一对应，运行时会核对） */
#define KSR_STUB_OFF_SLOT  0x100
#define KSR_STUB_OFF_FX    0x110
#define KSR_STUB_OFF_CTX   0x320
#define KSR_STUB_SIZE      0x7F0

/* ---------------- 通用 ---------------- */
void  KsrLog(const char* fmt, ...);
double KsrNowMs(void);
void  KsrBanner(const char* title);

/* ---------------- 第一层：共享内存地基 ---------------- */
void* KsrShareCreate(HANDLE* phMap, const char* tag);   /* 返回视图片基址（已清零+初始化段头） */
void  KsrShareDestroy(HANDLE hMap, void* base);
int   KsrDemo1(void);

/* ---------------- 第二层：syscall 直连 ---------------- */
BOOL     KsrResolveSsn(const char* funcName, uint32_t* ssn);
uint64_t KsrNtStub(uint32_t ssn,
                   uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5, uint64_t a6);
int      KsrDemo2(void);

/* ---------------- 第三层：调用链劫持 ---------------- */
int  KsrDemo3(void);

/* ---------------- 来自 NtStub.asm 的符号 ---------------- */
extern char KsrHijackStub[];      /* stub 入口（也是拷贝到共享内存的起点） */
extern char KsrHijackStubEnd[];   /* 块尾：StubEnd - Stub = 需要拷贝的字节数 */
extern char KsrHijackBodySlot[];  /* 8 字节槽：载荷函数指针，运行时填入 */
extern char KsrHijackFxArea[];    /* 512 字节 FXSAVE 区 */
extern char KsrHijackCtx[];       /* sizeof(CONTEXT) 的上下文副本 */

#ifdef __cplusplus
}
#endif
