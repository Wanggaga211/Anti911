// Test.cpp : target process for the Anti911 memory-write experiment.
//
// Flow:
//   1) print BEFORE  (PID + address + content)
//   2) pause -> use the memory manager to modify one variable
//   3) print AFTER   (same address, content may have changed)
//
// All strings are narrow (ANSI), so this builds under either character-set setting.
//

#include "stdafx.h"
#include <iostream>
#include <windows.h>
using namespace std;


char* __v1 = "Const HelloWorld";
int _tmain()
{
	char v1[20] = "Stack HelloWorld";
	char* v2 = (char*)malloc(sizeof(char) * 20);
	memcpy(v2, "Heap HelloWorld", 20);

	// ===== BEFORE: report coordinates and current content =====
	printf("===== BEFORE =====\r\n");
	printf("PID: %d\r\n", GetCurrentProcessId());
	printf("[Stack]  addr=%p  data=%s\r\n", v1, v1);
	printf("[Const]  addr=%p  data=%s\r\n", __v1, __v1);
	printf("[Heap]   addr=%p  data=%s\r\n", v2, v2);

	// ===== PAUSE: go modify one variable in the memory manager =====
	printf("Now use the memory manager to modify, then press any key...\r\n");
	_gettchar();

	// ===== AFTER: same variables, same addresses, content may have changed =====
	printf("===== AFTER =====\r\n");
	printf("[Stack]  addr=%p  data=%s\r\n", v1, v1);
	printf("[Const]  addr=%p  data=%s\r\n", __v1, __v1);
	printf("[Heap]   addr=%p  data=%s\r\n", v2, v2);

	printf("Input AnyKey To Exit\r\n");
	_gettchar();
	_gettchar();

	if (v2 != NULL)
	{
		free(v2);
		v2 = NULL;
	}

	return 0;
}
