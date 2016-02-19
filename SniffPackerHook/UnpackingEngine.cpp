#include "UnpackingEngine.h"
#include "Logger.h"

#include <fstream>
#include <sstream>
#include <assert.h>
#include <algorithm>
#include <ntstatus.h>

bool disableLogging= false;

void loopme()
{
	__asm
	{
		start:
			nop
			nop
			nop
			jmp start
	}
}

UnpackingEngine* UnpackingEngine::instance = NULL;

UnpackingEngine::UnpackingEngine(void)
{
    this->hooks = new HookingEngine();
    this->lock = new SyncLock();
    this->bypassHooks = false;
	this->nestedHook= false;
	Logger::getInstance();
}


UnpackingEngine::~UnpackingEngine(void)
{
    delete this->hooks;
    delete this->lock;
}

void UnpackingEngine::initialize()
{
    auto sg = this->lock->enterWithScopeGuard();

    HOOK_GET_ORIG(this, "ntdll.dll", NtProtectVirtualMemory);
    HOOK_GET_ORIG(this, "ntdll.dll", NtWriteVirtualMemory);
    HOOK_GET_ORIG(this, "ntdll.dll", NtCreateThread);
    HOOK_GET_ORIG(this, "ntdll.dll", NtMapViewOfSection);
    HOOK_GET_ORIG(this, "ntdll.dll", NtResumeThread);
    HOOK_GET_ORIG(this, "ntdll.dll", NtDelayExecution);
    HOOK_GET_ORIG(this, "ntdll.dll", NtAllocateVirtualMemory);
	HOOK_GET_ORIG(this, "ntdll.dll", NtFreeVirtualMemory);
    HOOK_GET_ORIG(this, "Kernel32.dll", CreateProcessInternalW);

	Logger::getInstance()->write(LOG_INFO, "Finding original function addresses...");
	Logger::getInstance()->write(LOG_INFO, "NtProtectVirtualMemory= %08x", this->origNtProtectVirtualMemory);
	Logger::getInstance()->write(LOG_INFO, "NtWriteVirtualMemory= %08x", this->origNtWriteVirtualMemory);
	Logger::getInstance()->write(LOG_INFO, "NtCreateThread= %08x", this->origNtCreateThread);
	Logger::getInstance()->write(LOG_INFO, "NtMapViewOfSection= %08x", this->origNtMapViewOfSection);
	Logger::getInstance()->write(LOG_INFO, "NtResumeThread= %08x", this->origNtResumeThread);
	Logger::getInstance()->write(LOG_INFO, "NtDelayExecution= %08x", this->origNtDelayExecution);
	Logger::getInstance()->write(LOG_INFO, "NtAllocateVirtualMemory= %08x", this->origNtAllocateVirtualMemory);
	Logger::getInstance()->write(LOG_INFO, "NtFreeVirtualMemory= %08x", this->origNtFreeVirtualMemory);
	Logger::getInstance()->write(LOG_INFO, "CreateProcessInternalW= %08x", this->origCreateProcessInternalW);
    Logger::getInstance()->write(LOG_INFO, "Finished finding original function addresses... DONE");

    this->hooks->doTransaction([=](){
		HOOK_SET(this, this->hooks, NtProtectVirtualMemory);
        HOOK_SET(this, this->hooks, NtMapViewOfSection);
        HOOK_SET(this, this->hooks, NtAllocateVirtualMemory);
		HOOK_SET(this, this->hooks, NtFreeVirtualMemory);

        HOOK_SET(this, this->hooks, NtWriteVirtualMemory);
        HOOK_SET(this, this->hooks, NtCreateThread);
        HOOK_SET(this, this->hooks, NtResumeThread);
        HOOK_SET(this, this->hooks, NtDelayExecution);
        HOOK_SET(this, this->hooks, CreateProcessInternalW);
    });

    Logger::getInstance()->write(LOG_INFO, "Placing hooks... DONE");
    Logger::getInstance()->write(LOG_INFO, "Hooks ready!");
}

void UnpackingEngine::uninitialize()
{
    auto sg = this->lock->enterWithScopeGuard();
    Logger::getInstance()->uninitialize();
}



/*
#define PAGE_NOACCESS          0x01     // winnt
#define PAGE_READONLY          0x02     // winnt
#define PAGE_READWRITE         0x04     // winnt
#define PAGE_WRITECOPY         0x08     // winnt
#define PAGE_EXECUTE           0x10     // winnt
#define PAGE_EXECUTE_READ      0x20     // winnt
#define PAGE_EXECUTE_READWRITE 0x40     // winnt
#define PAGE_EXECUTE_WRITECOPY 0x80     // winnt
#define PAGE_GUARD            0x100     // winnt
#define PAGE_NOCACHE          0x200     // winnt
*/

std::string UnpackingEngine::retProtectionString(ULONG protectionbits)
{
	std::string protectionstring;
	protectionstring.reserve(64);

	if(protectionbits & PAGE_NOACCESS){
		protectionstring.append("PAGE_NOACCESS");
		protectionbits &= (~PAGE_NOACCESS);
	}
	if(protectionbits & PAGE_READONLY){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_READONLY");
		protectionbits &= (~PAGE_READONLY);
	}
	if(protectionbits & PAGE_READWRITE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_READWRITE");
		protectionbits &= (~PAGE_READWRITE);
	}
	if(protectionbits & PAGE_WRITECOPY){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_WRITECOPY");
		protectionbits &= (~PAGE_WRITECOPY);
	}
	if(protectionbits & PAGE_EXECUTE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_EXECUTE");
		protectionbits &= (~PAGE_EXECUTE);
	}
	if(protectionbits & PAGE_EXECUTE_READ){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_EXECUTE_READ");
		protectionbits &= (~PAGE_EXECUTE_READ);
	}
	if(protectionbits & PAGE_EXECUTE_READWRITE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_EXECUTE_READWRITE");
		protectionbits &= (~PAGE_EXECUTE_READWRITE);
	}
	if(protectionbits & PAGE_EXECUTE_WRITECOPY){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_EXECUTE_WRITECOPY");
		protectionbits &= (~PAGE_EXECUTE_WRITECOPY);
	}
	if(protectionbits & PAGE_GUARD){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_GUARD");
		protectionbits &= (~PAGE_GUARD);
	}
	if(protectionbits & PAGE_NOCACHE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("PAGE_NOCACHE");
		protectionbits &= (~PAGE_NOCACHE);
	}
	if(protectionbits & MEM_COMMIT){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("MEM_COMMIT");
		protectionbits &= (~MEM_COMMIT);
	}
	if(protectionbits & MEM_RELEASE){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("MEM_RELEASE");
		protectionbits &= (~MEM_RELEASE);
	}
	if(protectionbits & MEM_DECOMMIT){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("MEM_DECOMMIT");
		protectionbits &= (~MEM_DECOMMIT);
	}

	if(protectionbits){
		if(protectionstring.length() > 0)
			protectionstring.append("|");
		protectionstring.append("FIXMEEEEEE");
	}
	return protectionstring;
}

NTSTATUS UnpackingEngine::onNtProtectVirtualMemory(HANDLE process, PVOID* baseAddress, PULONG numberOfBytes, ULONG newProtection, PULONG OldProtection)
{

	Logger::getInstance()->write(LOG_INFO, "PRE-NtProtectVirtualMemory(TargetPID %d, Address= 0x%08x, Size= 0x%08x, NewProtection= 0x%08x(%s))\n", GetProcessId(process), (DWORD)*baseAddress, (DWORD)*numberOfBytes, newProtection, retProtectionString(newProtection).c_str());
    
	NTSTATUS ret = this->origNtProtectVirtualMemory(process, baseAddress, numberOfBytes, newProtection, OldProtection);
	Logger::getInstance()->write(LOG_INFO, "PST-NtProtectVirtualMemory(TargetPID %d, Address= 0x%08x, Size= 0x%08x, NewProtection= 0x%08x(%s), OldProtection= 0x%08x(%s))\n", GetProcessId(process), (DWORD)*baseAddress, (DWORD)*numberOfBytes, newProtection, retProtectionString(newProtection).c_str(), *OldProtection, retProtectionString(*OldProtection).c_str());

    return ret;
}

NTSTATUS UnpackingEngine::onNtWriteVirtualMemory(HANDLE process, PVOID baseAddress, PVOID buffer, ULONG numberOfBytes, PULONG numberOfBytesWritten)
{
	Logger::getInstance()->write(LOG_INFO, "PRE-NtWriteVirtualMemory(TargetPID %d, Address 0x%08x, Count 0x%08x)\n", GetProcessId(process), baseAddress, numberOfBytes);

    auto ret = this->origNtWriteVirtualMemory(process, baseAddress, buffer, numberOfBytes, numberOfBytesWritten);
	Logger::getInstance()->write(LOG_INFO, "PST-NtWriteVirtualMemory(TargetPID %d, Address 0x%08x, Count 0x%08x) RET: 0x%08x\n", GetProcessId(process), baseAddress, (numberOfBytesWritten) ? *numberOfBytesWritten : numberOfBytes, ret);

    return ret;
}

BOOL WINAPI UnpackingEngine::onCreateProcessInternalW(
    HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
{
    auto ret = origCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);

    if ((dwCreationFlags & CREATE_SUSPENDED) != CREATE_SUSPENDED)
    {
        /* the process wasnt initially suspended, so we can inject right away */
        Logger::getInstance()->write(LOG_INFO, "Propogating into process %d from CreateProcessInternalW() hook.\n", lpProcessInformation->dwProcessId);
        hooks->injectIntoProcess(lpProcessInformation->hProcess, L"PackerAttackerHook.dll");
        Logger::getInstance()->write(LOG_INFO, "Propogation into process %d from CreateProcessInternalW() hook COMPLETE!\n", lpProcessInformation->dwProcessId);

        if (ResumeThread(lpProcessInformation->hThread) == -1)
            Logger::getInstance()->write(LOG_ERROR, "Failed to resume process! Thread %d\n", lpProcessInformation->dwThreadId);
    }
    

    return ret;
}

NTSTATUS WINAPI UnpackingEngine::onNtCreateThread(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	Logger::getInstance()->write(LOG_INFO, "PRE-NtCreateThread(TargetPID %d, Entry 0x%08x)\n", GetProcessId(ProcessHandle), ThreadContext->Eip);

    return this->origNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

NTSTATUS WINAPI UnpackingEngine::onNtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, ULONG CommitSize,
    PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
	Logger::getInstance()->write(LOG_INFO, "PRE-NtMapViewOfSection(TargetPID %d, Address 0x%08x, Size 0x%08x)\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*ViewSize);

    auto ret = this->origNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
	Logger::getInstance()->write(LOG_INFO, "PST-NtMapViewOfSection(TargetPID %d, Address is 0x%08x, Size 0x%08x, Protect 0x%08x) RET: 0x%08x\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*ViewSize, Protect, ret);

    return ret;
}

NTSTATUS WINAPI UnpackingEngine::onNtResumeThread(HANDLE thread, PULONG suspendCount)
{
    Logger::getInstance()->write(LOG_INFO, "PRE-onNtResumeThread(TargetTID 0x%08x\n", thread);

    return this->origNtResumeThread(thread, suspendCount);
}

NTSTATUS WINAPI UnpackingEngine::onNtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER time)
{
    Logger::getInstance()->write(LOG_INFO, "PRE-onNtDelayExecution Sleep call detected (Low part: 0x%08x, High part: 0x%08x).", time->LowPart, time->HighPart);

	if (time->HighPart == 0x80000000 && time->LowPart == 0){
		Logger::getInstance()->write(LOG_ERROR, "Infinite sleep. Fixing it.");
		time->HighPart= 0;
	}

	time->HighPart= 0;
	time->LowPart= 0; //0x3B9ACA00; 
	Logger::getInstance()->write(LOG_INFO, "Fixed sleep (Low part: 0x%08x, High part: 0x%08x).", time->LowPart, time->HighPart);

    return this->origNtDelayExecution(alertable, time);
}

NTSTATUS WINAPI UnpackingEngine::onNtFreeVirtualMemory(HANDLE process, PVOID* baseAddress, PULONG RegionSize, ULONG FreeType)
{
	Logger::getInstance()->write(LOG_INFO, "PRE-NtFreeVirtualMemory: TargetPID %d, Address 0x%08x, RegionSize 0x%08x, FreeType 0x%08x(%s)", GetProcessId(process), (DWORD)*baseAddress, (DWORD)*RegionSize, FreeType, retProtectionString(FreeType));
	auto ret= this->origNtFreeVirtualMemory(process, baseAddress, RegionSize, FreeType);
	Logger::getInstance()->write(LOG_INFO, "PST-NtFreeVirtualMemory: TargetPID %d, Address 0x%08x, RegionSize 0x%08x, FreeType 0x%08x(%s)", GetProcessId(process), (DWORD)*baseAddress, (DWORD)*RegionSize, FreeType, retProtectionString(FreeType));
	
	return ret;
}

NTSTATUS WINAPI UnpackingEngine::onNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect)
{
	Logger::getInstance()->write(LOG_INFO, "PRE-NtAllocateVirtualMemory(TargetPID %d, Address 0x%08x, Size 0x%08x, Protection 0x%08x(%s))\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (DWORD)*RegionSize, Protect, retProtectionString(Protect).c_str());

    auto ret = this->origNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	Logger::getInstance()->write(LOG_INFO, "PST-NtAllocateVirtualMemory(TargetPID %d, Address 0x%08x, Count 0x%08x, Protection 0x%08x(%s)) RET: 0x%08x\n", GetProcessId(ProcessHandle), (DWORD)*BaseAddress, (RegionSize) ? *RegionSize : 0, Protect, retProtectionString(Protect).c_str(), ret);

    return ret;
}


