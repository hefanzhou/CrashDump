#pragma once
#ifdef DLL_EXPORTS
#define DLL_API __declspec(dllexport)
#else
#define DLL_API __declspec(dllimport)
#endif

#include <tchar.h>
#include <time.h> 
#include<Windows.h>
#include <DbgHelp.h>  
#include <iostream>  
#include <vector>  


// 添加对dbghelp.lib的编译依赖  
//  
#pragma comment(lib, "dbghelp.lib")  

using namespace std;

const int MAX_ADDRESS_LENGTH = 32;
const int MAX_NAME_LENGTH = 1024;

// 崩溃信息  
//   
struct CrashInfo
{
	CHAR ErrorCode[MAX_ADDRESS_LENGTH];
	CHAR Address[MAX_ADDRESS_LENGTH];
	CHAR Flags[MAX_ADDRESS_LENGTH];
};

// CallStack信息  
//   
struct CallStackInfo
{
	CHAR ModuleName[MAX_NAME_LENGTH];
	CHAR MethodName[MAX_NAME_LENGTH];
	CHAR FileName[MAX_NAME_LENGTH];
	CHAR LineNumber[MAX_NAME_LENGTH];
};

// 安全拷贝字符串函数  
//  
void SafeStrCpy(char* szDest, size_t nMaxDestSize, const char* szSrc)
{
	if (nMaxDestSize <= 0) return;
	if (strlen(szSrc) < nMaxDestSize)
	{
		strcpy_s(szDest, nMaxDestSize, szSrc);
	}
	else
	{
		strncpy_s(szDest, nMaxDestSize, szSrc, nMaxDestSize);
		szDest[nMaxDestSize - 1] = '\0';
	}
}

// 得到程序崩溃信息  
//  
CrashInfo GetCrashInfo(const EXCEPTION_RECORD *pRecord)
{
	CrashInfo crashinfo;
	SafeStrCpy(crashinfo.Address, MAX_ADDRESS_LENGTH, "N/A");
	SafeStrCpy(crashinfo.ErrorCode, MAX_ADDRESS_LENGTH, "N/A");
	SafeStrCpy(crashinfo.Flags, MAX_ADDRESS_LENGTH, "N/A");

	sprintf_s(crashinfo.Address, "%08X", pRecord->ExceptionAddress);
	sprintf_s(crashinfo.ErrorCode, "%08X", pRecord->ExceptionCode);
	sprintf_s(crashinfo.Flags, "%08X", pRecord->ExceptionFlags);

	return crashinfo;
}

// 得到CallStack信息  
//  
vector<CallStackInfo> GetCallStack(const CONTEXT *pContext)
{
	HANDLE hProcess = GetCurrentProcess();

	SymInitialize(hProcess, NULL, TRUE);

	vector<CallStackInfo> arrCallStackInfo;

	CONTEXT c = *pContext;

	STACKFRAME64 sf;
	memset(&sf, 0, sizeof(STACKFRAME64));
	DWORD dwImageType = IMAGE_FILE_MACHINE_I386;

	// 不同的CPU类型，具体信息可查询MSDN  
	//  
#ifdef _M_IX86  
	sf.AddrPC.Offset = c.Eip;
	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrStack.Offset = c.Esp;
	sf.AddrStack.Mode = AddrModeFlat;
	sf.AddrFrame.Offset = c.Ebp;
	sf.AddrFrame.Mode = AddrModeFlat;
#elif _M_X64  
	dwImageType = IMAGE_FILE_MACHINE_AMD64;
	sf.AddrPC.Offset = c.Rip;
	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrFrame.Offset = c.Rsp;
	sf.AddrFrame.Mode = AddrModeFlat;
	sf.AddrStack.Offset = c.Rsp;
	sf.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64  
	dwImageType = IMAGE_FILE_MACHINE_IA64;
	sf.AddrPC.Offset = c.StIIP;
	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrFrame.Offset = c.IntSp;
	sf.AddrFrame.Mode = AddrModeFlat;
	sf.AddrBStore.Offset = c.RsBSP;
	sf.AddrBStore.Mode = AddrModeFlat;
	sf.AddrStack.Offset = c.IntSp;
	sf.AddrStack.Mode = AddrModeFlat;
#else  
#error "Platform not supported!"  
#endif  

	HANDLE hThread = GetCurrentThread();

	while (true)
	{
		// 该函数是实现这个功能的最重要的一个函数  
		// 函数的用法以及参数和返回值的具体解释可以查询MSDN  
		//  
		if (!StackWalk64(dwImageType, hProcess, hThread, &sf, &c, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
		{
			break;
		}

		if (sf.AddrFrame.Offset == 0)
		{
			break;
		}

		CallStackInfo callstackinfo;
		SafeStrCpy(callstackinfo.MethodName, MAX_NAME_LENGTH, "N/A");
		SafeStrCpy(callstackinfo.FileName, MAX_NAME_LENGTH, "N/A");
		SafeStrCpy(callstackinfo.ModuleName, MAX_NAME_LENGTH, "N/A");
		SafeStrCpy(callstackinfo.LineNumber, MAX_NAME_LENGTH, "N/A");

		BYTE symbolBuffer[sizeof(IMAGEHLP_SYMBOL64)+MAX_NAME_LENGTH];
		IMAGEHLP_SYMBOL64 *pSymbol = (IMAGEHLP_SYMBOL64*)symbolBuffer;
		memset(pSymbol, 0, sizeof(IMAGEHLP_SYMBOL64)+MAX_NAME_LENGTH);

		pSymbol->SizeOfStruct = sizeof(symbolBuffer);
		pSymbol->MaxNameLength = MAX_NAME_LENGTH;

		DWORD symDisplacement = 0;

		// 得到函数名  
		//  
		if (SymGetSymFromAddr64(hProcess, sf.AddrPC.Offset, NULL, pSymbol))
		{
			SafeStrCpy(callstackinfo.MethodName, MAX_NAME_LENGTH, pSymbol->Name);
		}

		IMAGEHLP_LINE64 lineInfo;
		memset(&lineInfo, 0, sizeof(IMAGEHLP_LINE64));

		lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

		DWORD dwLineDisplacement;

		// 得到文件名和所在的代码行  
		//  
		if (SymGetLineFromAddr64(hProcess, sf.AddrPC.Offset, &dwLineDisplacement, &lineInfo))
		{
			SafeStrCpy(callstackinfo.FileName, MAX_NAME_LENGTH, lineInfo.FileName);
			sprintf_s(callstackinfo.LineNumber, "%d", lineInfo.LineNumber);
		}

		IMAGEHLP_MODULE64 moduleInfo;
		memset(&moduleInfo, 0, sizeof(IMAGEHLP_MODULE64));

		moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

		// 得到模块名  
		//  
		if (SymGetModuleInfo64(hProcess, sf.AddrPC.Offset, &moduleInfo))
		{
			SafeStrCpy(callstackinfo.ModuleName, MAX_NAME_LENGTH, moduleInfo.ModuleName);
		}

		arrCallStackInfo.push_back(callstackinfo);
	}

	SymCleanup(hProcess);

	return arrCallStackInfo;
}

void DumpCrashInfo(CrashInfo crashinfo, vector<CallStackInfo> arrCallStackInfo)
{
	time_t t = time(0);
	char file_name[64];
	struct tm nt;
	localtime_s(&nt, &t);
	sprintf_s(file_name, "%d%d%d%d%d.crashdump", nt.tm_year+1900, nt.tm_mon+1, nt.tm_mday, nt.tm_hour, nt.tm_min, nt.tm_min);
	FILE *pFile;
	if (fopen_s(&pFile, file_name, "w") != 0) return;

	fprintf(pFile, "ErrorCode:%s\n", crashinfo.ErrorCode);
	fprintf(pFile, "Address:%s\n", crashinfo.Address);
	fprintf(pFile, "Flags:%s\n", crashinfo.Flags);

	//CallStack  
	fprintf(pFile, "CallStack\n");
	for (vector<CallStackInfo>::iterator i = arrCallStackInfo.begin(); i != arrCallStackInfo.end(); ++i)
	{
		CallStackInfo callstackinfo = (*i);
		fprintf(pFile, "%s::%s(File:%s@line:%s)\n", 
			callstackinfo.ModuleName,
			callstackinfo.MethodName,
			callstackinfo.FileName,
			callstackinfo.LineNumber);
	}


	fflush(pFile);
	fclose(pFile);
	FatalAppExit(-1, _T("*** Unhandled Exception! ***"));
}

// 处理Unhandled Exception的回调函数  
//  
LONG ApplicationCrashHandler(EXCEPTION_POINTERS *pException)
{
	// 确保有足够的栈空间  
	//  
#ifdef _M_IX86  
	if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW)
	{
		static char TempStack[1024 * 128];
		__asm mov eax, offset TempStack[1024 * 128];
		__asm mov esp, eax;
	}
#endif    

	CrashInfo crashinfo = GetCrashInfo(pException->ExceptionRecord);
	vector<CallStackInfo> arrCallStackInfo = GetCallStack(pException->ContextRecord);
	DumpCrashInfo(crashinfo, arrCallStackInfo);

	return EXCEPTION_EXECUTE_HANDLER;
}


extern "C"
{
	DLL_API void TestMakeItCrash()
	{
		int *p = nullptr;
		*p = 1;
	}

	DLL_API void RegisterCrashHandle()
	{
		SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)ApplicationCrashHandler);
	}
}