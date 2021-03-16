#define _NO_CRT_STDIO_INLINE
#define _SECURE_CRT_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "msvcrt.lib")

__declspec(dllimport) void COFF_API_Print(char* string);

int main()
{
	char moduleName[300];
	GetModuleFileNameA(NULL, moduleName, 300);
	MessageBoxA(NULL, moduleName, "Injected object file", NULL);
	COFF_API_Print(moduleName);
	return 123;
}