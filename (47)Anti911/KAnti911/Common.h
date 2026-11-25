#pragma once
#include <fltKernel.h>


#define MAX_PATH 260

#define ALIGN_SIZE(ViewSize, Align) (ViewSize+Align-1)/Align*Align



#define CloseWriteProtect() \
		_asm{cli}\
		_asm{mov eax, cr0}\
		_asm{and eax, ~0x10000}\
		_asm{mov cr0, eax}
#define OpenWriteProtect() \
		_asm{mov eax, cr0}\
		_asm{or eax, 0x10000}\
		_asm{mov cr0, eax}\
		_asm{sti}