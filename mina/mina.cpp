/*
  MINA
 
  Teh Mina Javascript Malware Deobfuscation Helper.
    
    Stephen A. Ridley (stephen@sa7ori.org)

    Copyright (c) 2008 http://dontstuffbeansupyournose.com 
        Stephen C. Lawler
        Stephen A. Ridley

Notes:
   -> because we modify registers and thread context this is only for IA32.
   -> needs c:\the_mina c:\the_mina\syms c:\the_mina\logs to be created and writable
   -> Tested/Developed on XPSP2 32bit.
   -> You will need net access to resolve symbols if you dont have them.
   -> If you have any problems, please email at the address above.

  Shoutouts and Thanks:
    Stephen Lawler, Brad Spengler, Matthieu Suiche, Mark Dowd,
    Dan De Beer (for testing).

*/
#include "sa7ori_wincludes.h"
#include <dbghelp.h>
#include "sa7debug.h"
#include <tchar.h>
#define ONEK 1024
#define _NO_CVCONST_H
#include <psapi.h> //For EnumProcessModules()
#include <stdio.h>
#include <limits.h>
#include <wchar.h>

// bleh where is PAGE_SIZE defined.....
#define PAGE_SIZE 4096
#define MIN(a,b) ((a)<(b)?(a):(b))

#ifdef _NO_CVCONST_H
// CV_HREG_e, originally from CVCONST.H in DIA SDK 
typedef enum CV_HREG_e {
    // Only a limited number of registers included here 
    CV_REG_EAX      =  17, 
    CV_REG_ECX      =  18, 
    CV_REG_EDX      =  19, 
    CV_REG_EBX      =  20, 
    CV_REG_ESP      =  21, 
    CV_REG_EBP      =  22, 
    CV_REG_ESI      =  23, 
    CV_REG_EDI      =  24, 
} CV_HREG_e;
#endif // _NO_CVCONST_H

#pragma comment( lib, "dbghelp.lib" )
typedef HMODULE (__stdcall *PLoadLibraryW)(wchar_t*);
typedef HMODULE (__stdcall *PGetModuleHandleW)(wchar_t*);
typedef BOOL    (__stdcall *PFreeLibrary)(HMODULE);
typedef FARPROC (__stdcall *PGetProcAddress)(HMODULE, char*);
const TCHAR* TagStr( ULONG Tag );

struct CSymbolInfoPackage : public SYMBOL_INFO_PACKAGE {
    CSymbolInfoPackage()
    {
        si.SizeOfStruct = sizeof(SYMBOL_INFO);
        si.MaxNameLen   = sizeof(name);
    }
};

ULONG find_ie(){
/***
    Old code, don't laugh at this function...I found out later about
EnumProcesses(). but it works...and is reliable.
***/
    tZwQuerySystemInformation pZwQuerySystemInformation = NULL;
    DWORD status = 0;
    PVOID mySysInfo = NULL; //pointer to mem we get alloc'd
    DWORD sizeReturned = 0;
    SYSTEM_PROCESSES *p = NULL;
    ULONG sizeAlloc = 0;  
    //ULONG sizeIncrement = 0;
    BOOL done = FALSE;
    ULONG targeted_pid = 0;

    HMODULE hLib = LoadLibrary("ntdll.dll");
    if (pZwQuerySystemInformation == NULL){
        pZwQuerySystemInformation = (tZwQuerySystemInformation)GetProcAddress(hLib, "ZwQuerySystemInformation"); 
        printf("\nAcquired System Information...");
    }   
    FreeLibrary(hLib);

    do{ 
        mySysInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeAlloc);
        //printf("%d", sizeAlloc);
        if (!mySysInfo){ //do an error
            printf("\nCould not Alloc. I am made entirely of cheese.");
        }   
        status = pZwQuerySystemInformation(
                SystemProcessesAndThreadsInformation,
                mySysInfo,
                sizeAlloc,
                &sizeReturned);
//        printf("Stat: 0x%x Returned: %x", status, sizeReturned);
        if((STATUS_INFO_LENGTH_MISMATCH != status)){
//            printf("\nSTATUS_INFO_LENGTH_MISMATCH != status");
            break;
        };  

        HeapFree(GetProcessHeap(), 0, mySysInfo);
        mySysInfo = NULL;

        sizeAlloc += sizeReturned;printf(".");

    }while(1);
    printf("\nSearching for IE...");
    for (p = (struct _SYSTEM_PROCESSES *)mySysInfo; !done; p = (SYSTEM_PROCESSES *)(((char*)p) + p->NextEntryDelta)){
        // do some shit with the info for the current process at p->
        //printf("\n%d", p->ProcessId);
        if (wcsncmp(p->ProcessName.Buffer, L"iexplore.exe", (p->ProcessName.Length/2)) == 0 && p->ProcessId != 0) {//Sometimes UNICODE_STRINGS are not null terminated so we have to do this gayness.
            _tprintf("\nFound IE (%ws) at pid %d !!!",p->ProcessName.Buffer, p->ProcessId);
            targeted_pid = p->ProcessId;
        }
        //_tprintf(":%ws", (PWSTR *)p->ProcessName.Buffer);
        done = (p->NextEntryDelta == 0); 
    }
    if (targeted_pid == 0)
        printf("\nI don't see IE running, please start it.");
    return targeted_pid;
}

bool attach(DWORD pid){
    if (!DebugActiveProcess(pid)){
        _tprintf( _T("DebugActiveProcess() failed. Error: %u \n"),GetLastError());
        return false;
    }
    printf("\nAttached to IE...");
    return true;
}

bool EnableDebugPrivilege( bool Enable ) {
    bool Success = false;
    HANDLE hToken = NULL;
    DWORD ec = 0;
    do{
        // Open the process' token
        if( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken ) ){
            ec = GetLastError();
            _tprintf(_T("OpenProcessToken() failed."));
            break;
        }
        // Lookup the privilege value 
        TOKEN_PRIVILEGES tp; 
        tp.PrivilegeCount = 1;
        if( !LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid )){
            ec = GetLastError();
            _tprintf(_T("LookupPrivilegeValue() failed."));
            break;
        }
        // Enable/disable the privilege
        tp.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;
        if( !AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof(tp), NULL, NULL )){
            ec = GetLastError();
            _tprintf(_T("AdjustPrivilegeValue() failed."));
            break;
        }
        // Success 
        Success = true;
    }
    while(0);
    // Cleanup
    if( hToken != NULL ){
        if( !CloseHandle( hToken ) ){
            ec = GetLastError();
            _tprintf(_T("CloseHandle() failed."));
        }
    }
    // Complete 
    return Success;
}

HANDLE GetProcessHandle(DWORD pid){
    HANDLE hProcess;
//    printf("\nAcquiring process handle for pid %d.", pid);
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE,
                  FALSE, pid ); //MAXIMUM_ALLOWED lawlerskillz (I'll have to try it later)
    if (NULL == hProcess){
        printf("Error obtaining process handle...Quitting.");
        return 0;
    };
    return hProcess;
}

HANDLE GetThreadHandle(DWORD tid){
    HANDLE hThread;
//    printf("\nAcquiring thread handle for tid %d.", tid);
    //hThread = OpenThread((THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME), FALSE, tid); //Be warned THREAD_ALL_ACCESS is not enough!
    hThread = OpenThread(MAXIMUM_ALLOWED, FALSE, tid); //Be warned THREAD_ALL_ACCESS is not enough!
    if (NULL == hThread){
        printf("Error obtaining process handle...Quitting.");
        return 0;
    };
    return hThread;
}

void ShowSymbolDetails( SYMBOL_INFO& SymInfo ) {
    // Kind of symbol (tag) 
    //_tprintf( _T("Symbol: %s  "), TagStr(SymInfo.Tag) );//broke cuz TagStr is
    //broke
    _tprintf( _T("Symbol: %d  "), SymInfo.Tag );
    // Address 
    _tprintf( _T("Address: %x  "), SymInfo.Address );
    // Size 
    _tprintf( _T("Size: %u  "), SymInfo.Size );
    // Name 
    _tprintf( _T("Name: %s"), SymInfo.Name );
    _tprintf( _T("\n") );

}

void print_modules_by_handle(HANDLE hProcess) { 
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i; 
    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)){
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ ){
            char szModName[MAX_PATH];
            // Get the full path to the module's file.
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName))) {
                // Print the module name and handle value.
                    printf("\t==> %s (0x%08X)\n", szModName, hMods[i]);
            }   
        }   
    }   
};

void print_modules(DWORD processID) { 
//mostly ripped from: 
//http://msdn.microsoft.com/library/default.asp?url=/library/en-us/perfmon/base/enumerating_all_modules_for_a_process.asp
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i; 
    // Print the process identifier.
    printf("\nIE has the following dlls loaded:\n", processID );
    // Get a list of all the modules in this process.
    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                  PROCESS_VM_READ,
                  FALSE, processID );
    if (NULL == hProcess)
    return;
    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)){
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ ){
            char szModName[MAX_PATH];
            // Get the full path to the module's file.
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName))) {
                // Print the module name and handle value.
                    printf("\t==> %s (0x%08X)\n", szModName, hMods[i]);
            }   
        }   
    }   
    CloseHandle(hProcess);
};

void load_jscript(HANDLE hProcess){
//Force Jscript to load
    HANDLE hThread;
    char    szLibPath[] = "c:\\windows\\system32\\jscript.dll";  // The name of our "LibSpy.dll" module
                                   // (including full path!);
    void*   pLibRemote;   // The address (in the remote process) where 
                          // szLibPath will be copied to;
    DWORD   hLibModule;   // Base address of loaded module (==HMODULE);
    HMODULE hKernel32 = GetModuleHandle("Kernel32");
    // initialize szLibPath
    //...
    // 1. Allocate memory in the remote process for szLibPath
    // 2. Write szLibPath to the allocated memory
    pLibRemote = VirtualAllocEx( hProcess, NULL, sizeof(szLibPath),
                                   MEM_COMMIT, PAGE_READWRITE );
    WriteProcessMemory( hProcess, pLibRemote, (void*)szLibPath,
                          sizeof(szLibPath), NULL );
    // (via CreateRemoteThread & LoadLibrary)
    hThread = CreateRemoteThread( hProcess, NULL, 0,
                (LPTHREAD_START_ROUTINE) GetProcAddress( hKernel32, "LoadLibraryA" ),
                 pLibRemote, 0, NULL );
    WaitForSingleObject( hThread, INFINITE );
    // Get handle of the loaded module
    GetExitCodeThread( hThread, &hLibModule );
    printf("\nJscript should be loaded in target process at %d.", hLibModule);
    print_modules_by_handle(hProcess); 
    // Clean up
    CloseHandle( hThread );
    VirtualFreeEx( hProcess, pLibRemote, sizeof(szLibPath), MEM_RELEASE );
}

bool find_jscript(DWORD pid){
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    char *strstrptr;
    unsigned int i;
    bool found = 0; 
    printf("\nChecking if jscript.dll is loaded...");
    // Get a list of all the modules in this process.
    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                  PROCESS_VM_READ,
                  FALSE, pid );
    if (NULL == hProcess)
    return 0;
    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)){
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ ){
            char szModName[MAX_PATH];
            // Get the full path to the module's file.
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName))) {
                    strstrptr = strstr(szModName, _T("jscript"));
                    if (strstrptr != NULL){
                        printf("\nFound JSCRIPT ==> %s (0x%08X)\n", szModName, hMods[i]);
                        found = 1;
                    }  
            }   
        }   
    }
    CloseHandle(hProcess);
    if (found != 1){
        //printf("\nJscript.dll is not loaded in IE...forcibly loading it."); 
        return 0;
    }
    return 1;
};

int writeByteToProcessMemory(HANDLE hProcess, LPCVOID TargetAddr, unsigned char *sourceByte){
//Write sourceByte to TargetAddress in hProcess.
    MEMORY_BASIC_INFORMATION MemInfo;
    SIZE_T readcount;
    char buf[10] = ""; //scratch space

    VirtualQueryEx(hProcess, TargetAddr, &MemInfo, sizeof(MemInfo));
    if(!VirtualProtectEx(hProcess, MemInfo.BaseAddress, MemInfo.RegionSize, PAGE_EXECUTE_READWRITE, &MemInfo.Protect)){
        printf("\nCould not change page permissions at 0x%08X (page: 0x%08X) ...failing.", TargetAddr, MemInfo.BaseAddress);
        return 1; 
    }
    ReadProcessMemory(hProcess, TargetAddr, &buf, 1, &readcount); 
    WriteProcessMemory(hProcess, (LPVOID)TargetAddr, sourceByte, 1, &readcount);
    //Double check that our break byte was really set
    ReadProcessMemory(hProcess, (LPCVOID)TargetAddr, &buf[1], 1, &readcount);
//    printf("\nRead the byte 0x%02X.", sourceByte[0]);
    if(!VirtualProtectEx(hProcess, MemInfo.BaseAddress, MemInfo.RegionSize, MemInfo.Protect, &MemInfo.Protect)){
        printf("\nCould not restore page permissions at 0x%08X (page: 0x%08X).", TargetAddr, MemInfo.BaseAddress);
    }
    if ((unsigned char)buf[1] == sourceByte[0]){ //Then the write was successful.
        //printf("\nWriteProcessMemory() success!");
        if (FlushInstructionCache(hProcess, NULL, NULL)==0)
            printf("\nFlushInstructionCache() failed...");
        return 0;
    };
    return 1;
};

char setBreakpoint(ULONG TargetAddr, HANDLE hProcess){
    //So to do this we:
    //1. have to read the byte at the address and "preserve" it.
    //2. Because we have to modify the .text region we need to change page
    //  permissions.
    //2. then we have to overwrite the location with a \xcc
    char buf[10] = ""; //scratch space
    char ccbuf[] = "\xcc";
    char savebuf[1];
    LPCVOID pccbuf = &ccbuf[0]; 
    SIZE_T readcount, target_size;
    MEMORY_BASIC_INFORMATION MemInfo;

    VirtualQueryEx(hProcess, (LPCVOID)TargetAddr, &MemInfo, sizeof(MemInfo));
    printf("\nAttempting to set breakpoint at 0x%08X who's page starts at 0x%08X", TargetAddr, MemInfo.BaseAddress);
    ReadProcessMemory(hProcess, (LPCVOID)TargetAddr, &buf, 1, &readcount);
    printf("\nRead the byte 0x%02X.", (unsigned char)buf[0]);
    savebuf[0] = buf[0]; //saving the byte

    if (writeByteToProcessMemory(hProcess, (LPCVOID)TargetAddr, (unsigned char*)pccbuf) == 0){
        printf("\nBreakpoint set successfully. Preserving byte: 0x%02X.", (unsigned char)savebuf[0]);
        return savebuf[0];
    };

    return 0;
};

int setHardwareBreakpointInThread(PBYTE TargetAddr, DWORD tid){
    UINT Drx;
    CONTEXT cThread, cThread2;
    HANDLE hThread;

    hThread = GetThreadHandle(tid); 
    cThread.ContextFlags = CONTEXT_FULL;//CONTEXT_DEBUG_REGISTERS;
    cThread2.ContextFlags = CONTEXT_FULL;//CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &cThread) == 0)
        printf("\nGetThreadContext() for setHardwareBreakpoint() failed... %d", GetLastError());

    if (GetThreadContext(hThread, &cThread2) == 0)
        printf("\nGetThreadContext() for setHardwareBreakpoint() failed... %d", GetLastError());

    for (Drx = 0; Drx < 4; Drx++) {   
        if (((cThread.Dr7 & (1 << (Drx*2))) == 0) && ((cThread.Dr7 & (1 << (Drx*2+1))) == 0)) 
            break;
    }   

    if(Drx == 4) {        // All DRs are already being used.
        printf("\nAll HW breakpoints already in use!");
        return FALSE;
    }
    switch(Drx) {
        case ID_DR0: cThread.Dr0 =   (DWORD)TargetAddr; break;
        case ID_DR1: cThread.Dr1 =   (DWORD)TargetAddr; break;
        case ID_DR2: cThread.Dr2 =   (DWORD)TargetAddr; break;
        case ID_DR3: cThread.Dr3 =   (DWORD)TargetAddr; break;
    }   

    GlobalnLocalExcept(cThread);
    ActivateGlobalnLocal(cThread,Drx);
    SetLength(cThread,Drx);
    SetCondition(cThread,Drx);
    printDr7(cThread.Dr7);

    if(!SetThreadContext(hThread, &cThread)){
        printf("\nCould not set Thread context.");
        return FALSE;
    }
//    printf("before: %.08X after: %.08X", cThread2.Dr7, cThread.Dr7);
//    printf("%.08X %.08X %.08X %.08X", cThread.Dr0, cThread.Dr1, cThread.Dr2, cThread.Dr3);
    printf("\nSuccessfully set HardwareBreak in %d at 0x%.08x", tid, TargetAddr);
    return TRUE;
}

int unSetHardwareBreakpointInThread(PBYTE TargetAddr, DWORD tid){
    UINT Drx;
    CONTEXT cThread;
    HANDLE hThread;

    hThread = GetThreadHandle(tid); 
    cThread.ContextFlags = CONTEXT_FULL;//CONTEXT_DEBUG_REGISTERS; //CONTEXT_ALL!?
    if (GetThreadContext(hThread, &cThread) == 0)
        printf("\nGetThreadContext() for setHardwareBreakpoint() failed... %d", GetLastError);

    if(cThread.Dr0 == (DWORD)TargetAddr){cThread.Dr0 = NULL; Drx= 0;}
    else if(cThread.Dr1 == (DWORD)TargetAddr){cThread.Dr1 = NULL; Drx = 1;}
    else if(cThread.Dr2 == (DWORD)TargetAddr){cThread.Dr2 = NULL; Drx = 2;}
    else if(cThread.Dr3 == (DWORD)TargetAddr){cThread.Dr3 = NULL; Drx = 3;}

    cThread.Dr7 = (cThread.Dr7 & ~(0x3 << (Drx*2))|(0xF << (Drx*4+16)));

    if(!SetThreadContext(hThread, &cThread))
        return FALSE;

    printf("\nSuccessfully unset HardwareBreak in %d\n", tid);
    return TRUE;

}

int setHardwareBreakpoint(ULONG TargetAddr, HANDLE hProcess, LPDEBUG_EVENT pdebugEvent){
    CONTEXT cThread, cThread2;
    HANDLE hThread;

    tZwQuerySystemInformation pZwQuerySystemInformation = NULL;
    DWORD status = 0;
    PVOID mySysInfo = NULL; //pointer to mem we get alloc'd
    DWORD sizeReturned = 0;
    SYSTEM_PROCESSES *p = NULL;
    ULONG sizeAlloc = 0;  
    //ULONG sizeIncrement = 0;
    BOOL done = FALSE;
    ULONG targeted_pid = 0;
    LPWSTR target_name = L"iexplore.exe";
    int idx = 0;

    HMODULE hLib = LoadLibrary("ntdll.dll");
    if (pZwQuerySystemInformation == NULL){
        pZwQuerySystemInformation = (tZwQuerySystemInformation)GetProcAddress(hLib, "ZwQuerySystemInformation"); 
        printf("\nAcquired System Information...");
    }   
    FreeLibrary(hLib);

    do{ 
        mySysInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeAlloc);
        //printf("%d", sizeAlloc);
        if (!mySysInfo){ //do an error
            printf("\nCould not Alloc. I am made entirely of cheese.");
        }   
        status = pZwQuerySystemInformation(
                SystemProcessesAndThreadsInformation,
                mySysInfo,
                sizeAlloc,
                &sizeReturned);
//        printf("Stat: 0x%x Returned: %x", status, sizeReturned);
        if((STATUS_INFO_LENGTH_MISMATCH != status)){
//            printf("\nSTATUS_INFO_LENGTH_MISMATCH != status");
            break;
        };

        HeapFree(GetProcessHeap(), 0, mySysInfo);
        mySysInfo = NULL;

        sizeAlloc += sizeReturned;printf(".");

    }while(1);
    printf("\nSearching for IE AGAIN!");
    for (p = (struct _SYSTEM_PROCESSES *)mySysInfo; !done; p = (SYSTEM_PROCESSES *)(((char*)p) + p->NextEntryDelta)){
        if (p->ProcessId == GetProcessId(hProcess)) {
            printf("\nIE has %d Threads.", p->ThreadCount);
            while (idx != p->ThreadCount){
                setHardwareBreakpointInThread((PBYTE)TargetAddr, p->Threads[idx].ClientId.UniqueThread);
                idx++;
            }
            done = true;
        }
        //_tprintf(":%ws", (PWSTR *)p->ProcessName.Buffer);
        done = (p->NextEntryDelta == 0);
    }
    return 0;
};

void ReportExceptionEvent( DWORD ProcessId, DWORD ThreadId, const EXCEPTION_DEBUG_INFO& Event ) {
// Ripped DIRECTLY from Oleg Starodumov (www.debuginfo.com)
    _tprintf( _T("\nEVENT: Exception\n") );
    _tprintf( _T("  ProcessId:                %u\n"), ProcessId );
    _tprintf( _T("  ThreadId:                 %u\n"), ThreadId );
    _tprintf( _T("  EXCEPTION_DEBUG_INFO members:\n") );
    _tprintf( _T("    dwFirstChance:          %u\n"), Event.dwFirstChance );
    _tprintf( _T("    EXCEPTION_RECORD members:\n") );
    _tprintf( _T("      ExceptionCode:        %08x\n"), Event.ExceptionRecord.ExceptionCode );
    _tprintf( _T("      ExceptionFlags:       %08x\n"), Event.ExceptionRecord.ExceptionFlags );
    _tprintf( _T("      ExceptionRecord:      %08p\n"), Event.ExceptionRecord.ExceptionRecord );
    _tprintf( _T("      ExceptionAddress:     %08p\n"), Event.ExceptionRecord.ExceptionAddress );
    _tprintf( _T("      NumberParameters:     %u\n"), Event.ExceptionRecord.NumberParameters );

    DWORD NumParameters = Event.ExceptionRecord.NumberParameters;

    if( NumParameters > EXCEPTION_MAXIMUM_PARAMETERS )
        NumParameters = EXCEPTION_MAXIMUM_PARAMETERS;

    for( DWORD i = 0; i < NumParameters; i++ )
        _tprintf( _T("      ExceptionInformation[%d]:     %08p\n"), i, Event.ExceptionRecord.ExceptionInformation[i] );
}

void singleStepEventHandler(LPDEBUG_EVENT pdebugEvent){
    CONTEXT cThread;
    HANDLE hThread;

//    printf("SINGLE STEP HANDLER\n");
    hThread = GetThreadHandle(pdebugEvent->dwThreadId);
    cThread.ContextFlags = CONTEXT_FULL;//CONTEXT_CONTROL;
    if (GetThreadContext(hThread, &cThread) == 0)
        printf("\nGetThreadContext() for singleStepEventHandler() failed... %d", GetLastError());
    if ((cThread.Eip&0xFFF00000) == 0x00400000){
        printf("\nIts really a SingleStep!");
    }
//    printf("\n -- WE ARE CONTINUING AT %08x\n", cThread.Eip);
    //ContinueSingleStepMode(cThread,hThread); 
    ClearSingleStepMode(cThread,hThread); 
    CloseHandle(hThread);
}

void breakpointEventHandler(LPDEBUG_EVENT pdebugEvent){
    CONTEXT cThread;
    HANDLE hThread;

//    printf("BREAKPOINT HANDLER\n");
    hThread = GetThreadHandle(pdebugEvent->dwThreadId);
    cThread.ContextFlags = CONTEXT_FULL;//CONTEXT_CONTROL;
    if (GetThreadContext(hThread, &cThread) == 0)
        printf("\nGetThreadContext() for breakpointEventHandler() failed... %d", GetLastError());

//    printf("\n -- WE ARE BROKEN AT %08x\n", cThread.Eip);

    ContinueSingleStepModeAndDecEip(cThread,hThread);
    CloseHandle(hThread);

}

void preview_bytes(PVOID buffer){
    DWORD temp;
    int i;
    temp = (DWORD)buffer;
    printf("\n\t");
    for (i=0; i<=8; i++){
        printf(" %02X", ((unsigned char *)temp)[0]);
        temp++;
    } 
    printf("\n");
};

SIZE_T slurp_remote_unistring(HANDLE hProcess, PVOID p_diddy, PUCHAR buf, SIZE_T buf_size)
{
    UCHAR bytes[PAGE_SIZE];
    SIZE_T size;
    SIZE_T cur_size;
    SIZE_T copy_size;
    ULONG tx;
    ULONG_PTR ul_diddy;
    PWCHAR ntz;

    size = 0;
    ul_diddy = (ULONG_PTR)p_diddy;

    while (TRUE) {
        cur_size = PAGE_SIZE - (ul_diddy & (PAGE_SIZE-1));
        if (!ReadProcessMemory(hProcess, (PVOID)ul_diddy, bytes, cur_size, &tx)) break;

        ntz = wmemchr((PWCHAR)bytes, 0, cur_size / sizeof(WCHAR));
        if (ntz) {
            cur_size = ((PUCHAR)ntz) - bytes;
        }

        copy_size = MIN(buf_size, cur_size);
        memcpy(buf, bytes, copy_size);
        buf_size -= copy_size;
        if (buf) buf += copy_size;
        size += cur_size; // {sic} -- the required size
        if (ntz) break;

        // Go up to the next page
        ul_diddy = ul_diddy + PAGE_SIZE;
        ul_diddy = ul_diddy & (-PAGE_SIZE);
    }

    return size;
}

int fetch_jscript_compile_info(HANDLE hProcess, LPDEBUG_EVENT pdebugEvent){
    CONTEXT cThread;
    HANDLE hThread,hFile;
    DWORD esp;
    DWORD p_script = 0x00000000;
    SYSTEMTIME st;
    int idx = 0;
    CHAR logfile[MAX_PATH+1];
    BOOL prev_was_null=FALSE;
    SIZE_T sz;
    PWCHAR buf;
 
    SIZE_T readcount;

    hThread = GetThreadHandle(pdebugEvent->dwThreadId);
    cThread.ContextFlags = CONTEXT_FULL;//CONTEXT_CONTROL;

    if (GetThreadContext(hThread, &cThread) == 0)
        printf("\nGetThreadContext() for breakpointEventHandler() failed... %d", GetLastError());

    esp = cThread.Esp;

    ReadProcessMemory(hProcess, (LPCVOID)(esp+8), (LPVOID)&p_script, 4, &readcount);    

    sz = slurp_remote_unistring(hProcess, (PVOID)p_script, 0, 0);
    buf = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!buf) ExitProcess(0x141773); // screw it man
    slurp_remote_unistring(hProcess, (PVOID)p_script, (PUCHAR)buf, sz);

    GetSystemTime(&st);
    sprintf(logfile, "c:\\the_mina\\logs\\mina_%2d_%2d_%2d.log", st.wMinute, st.wSecond, st.wMilliseconds);
    printf("\nLogging jscript at 0x%08x to %s.", p_script, logfile);
    preview_bytes((PVOID)buf);

    //wprintf(L"%.*s\n", sz/sizeof(WCHAR),buf);

    hFile = CreateFile((LPCSTR)&logfile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL); 
    if( hFile == INVALID_HANDLE_VALUE ) {   
        hFile = CreateFile((LPCSTR)&logfile, GENERIC_WRITE, FILE_SHARE_READ, NULL, TRUNCATE_EXISTING, 0, NULL); 
        if( hFile == INVALID_HANDLE_VALUE ){
            printf("\nCreateFile() for %s failed.", logfile);
            HeapFree(GetProcessHeap(), 0, buf);
            return false; 
        }
    } 

    WriteFile(hFile, "\xff\xfe", 2, &readcount, NULL); // put a BOM on so Windows can automagically prettyprint the unicode for us
    WriteFile(hFile, (PVOID)buf, sz, &readcount, NULL);
    printf("\nWrote %d bytes.", readcount);
    CloseHandle(hThread);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, buf);
    return 0;
}

bool debugLoop_hardwarebp(DWORD Timeout, ULONG symAddr,  HANDLE hProcess){
/*
     There are two versions of this function...the other one usues the old
"software breakpoint" approach, which was broken for some reason...this one
tries Hardware Breakpoints.

*/
    DEBUG_EVENT debugEvent;
    bool bCont = true;
    bool bSeenInitialBreakpoint = false;
    bool bTrapOneSet = false; // for Step 2
    CONTEXT cThread,cThread2;
    HANDLE hThread;
    DWORD saved_eip;

    printf("\nOk...we're all set. I am setting IE to continue execution, you can browse with it now.");

    while(bCont){
        if(WaitForDebugEvent(&debugEvent, Timeout)){
            DWORD ContinueStatus = DBG_CONTINUE;
            DWORD ExceptionCode =debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
            DWORD trapOneAddr;

            switch(debugEvent.dwDebugEventCode){
                case EXCEPTION_DEBUG_EVENT:
                    //ReportExceptionEvent(debugEvent.dwProcessId,
                    //debugEvent.dwThreadId, debugEvent.u.Exception);
                    //ContinueStatus = DBG_CONTINUE;
                    ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    if(!bSeenInitialBreakpoint && (ExceptionCode == EXCEPTION_BREAKPOINT)){
                        printf("\nUsing initial breakpoint to set HardwareBP");
                        setHardwareBreakpoint(symAddr, hProcess, &debugEvent);
                        bSeenInitialBreakpoint = true;
                        ContinueStatus = DBG_CONTINUE;
                    }
                    if (ExceptionCode == EXCEPTION_SINGLE_STEP){//Hardware breakpoints throw SINGLE_STEP exceptions.
                        printf("\nSINGLESTEP!");
                        ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                        SuspendThread(GetThreadHandle(debugEvent.dwThreadId));
                        //ContinueStatus = DBG_CONTINUE;
                        ReportExceptionEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception);
                    };
                    if (ExceptionCode == EXCEPTION_BREAKPOINT){
                        //printf("\nBREAK!");
                        ContinueStatus = DBG_CONTINUE;
                        ReportExceptionEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception);
                    };
                    break;

                case CREATE_THREAD_DEBUG_EVENT:
                    printf("\nA new thread is spawning...setting our breakpoint.");
                    setHardwareBreakpointInThread((PBYTE)symAddr, debugEvent.dwThreadId); 
                    break;
            }
            // Allow Debugee to continue
            if(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, ContinueStatus)){
                printf("\nContinuedebugEvent() failed!...quitting");
                return false;
            }
            ResumeThread(GetThreadHandle(debugEvent.dwThreadId));
        } else {
            DWORD ErrCode = GetLastError();
            if (ErrCode == ERROR_SEM_TIMEOUT){
                printf("\nTimeout error.");
            } else {
                printf("\nWaitfordebugEvent() failed...");
                return false;
            }
        }

    }
    return true; 
};

bool debugLoop_softwarebp(DWORD Timeout, ULONG symAddr, PUCHAR savedByte, HANDLE hProcess){
/*
    Ok so this is what we gotta do when our int3 (software) breakpoint hits:

    1. Make sure that its *our* breakpoint.
    2. Step once. 
      ** It turns out this step is unecessary... ***
      If an int3 is at 0xA9, then when the exception is thrown, EIP is actually at 0xAA
      which is how you'd expect it to work, but if you "tested" your algorithm
      by hand in another debugger, the other debuggers lie about EIP after an
      int3...so you wouldve designed your algorithm wrong...like I did ;-)

    3. Change the breakpoint byte back to what it was previously.
    4. Set EIP to EIP-1
    5. Step once.
    6. Change the byte back to our breakpoint.
    7. Continue without singlestep. 
*/
    DEBUG_EVENT debugEvent;
    bool bCont = true;
    DWORD ContinueStatus = DBG_CONTINUE;
    DWORD ExceptionCode;

    printf("\nOk...we're all set. I am setting IE to continue execution, you can browse with it now.");

    while(bCont){
        if(WaitForDebugEvent(&debugEvent, Timeout)){
            ExceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
            switch(debugEvent.dwDebugEventCode){
                case EXCEPTION_DEBUG_EVENT:
                    //printf("\n!!! EXCEPTION_DEBUG !!! Code = %08x\n", ExceptionCode);
                    //ReportExceptionEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception);
                    if (ExceptionCode == EXCEPTION_BREAKPOINT){
                        if(debugEvent.u.Exception.ExceptionRecord.ExceptionAddress != (PVOID)symAddr){
                            //printf("\nSKIPPING BREAKPOINT @0x%.08x !",debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
                        } else {
                            if (debugEvent.u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)symAddr) 
                                printf("\nA JAVASCRIPT COMPILE IS OCCURING!!!");
                            //printf("\nBREAK HIT!");
                            breakpointEventHandler(&debugEvent);
                            //printf("\nWRITE BACK BYTE\n");
                            writeByteToProcessMemory(hProcess, (PVOID)symAddr, savedByte);
                            fetch_jscript_compile_info(hProcess, &debugEvent);
                        //    ReportExceptionEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception);
                        }
                    }
                    if (ExceptionCode == EXCEPTION_SINGLE_STEP){
                        //printf("\nSINGLESTEP!");
                        singleStepEventHandler(&debugEvent);
                        UCHAR ccbuf[] = "\xcc";
                        //printf("\nWRITE BACK CC\n");
                        writeByteToProcessMemory(hProcess, (PVOID)symAddr, ccbuf);
                        //ReportExceptionEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.Exception);
                    }
                    break;
            }
            // Allow Debugee to continue
            if(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, ContinueStatus)){
                printf("\nContinuedebugEvent() failed!...quitting");
                return false;
            }
        } else {
            DWORD ErrCode = GetLastError();
            if (ErrCode == ERROR_SEM_TIMEOUT){
                printf("\nTimeout error.");
            } else {
                printf("\nWaitfordebugEvent() failed...");
                return false;
            }
        }

    }
    return true; 
};


int _tmain( int argc, const TCHAR* argv[] ) {
    BOOL bRet = FALSE; 
    //Might have to do some SymSearchPath() stuff later.
    TCHAR symName[] = "jscript!COleScript::Compile";
    TCHAR symLocalRemote[] = "symsrv*symsrv.dll*c:\\the_mina\\syms*http://msdl.microsoft.com/download/symbols";
    TCHAR symUserDefined[MAX_PATH+1];
    ULONG symAddr;
    char saved_byte[1]; //place to hold the byte that gets overwritten by our breakpoint 
    // Set options 
    printf("\n\n\
    THE MINA\n\
    \n\
    Javascript Malware Deobfuscation Helper.\n\
   \n\
        stephen@sa7ori.org\n\
\n\n\
    Copyright (c) 2008 http://dontstuffbeansupyournose.com\n\
    Stephen C. Lawler\n\
    Stephen A. Ridley\n\
    ");


    HANDLE hProcess;
    DWORD Options = SymGetOptions(); 
    // SYMOPT_DEBUG option asks DbgHelp to print additional troubleshooting 
    // messages to debug output - use the debugger's Debug Output window 
    // to view the messages 
    ULONG target = find_ie();
    if (target == 0)
    return 1; //fail
    EnableDebugPrivilege(true); 
    if (target != 0){
        hProcess = GetProcessHandle(target); 
        //attach(target);
    };

    Options |= SYMOPT_DEBUG;
    SymSetOptions(Options);
//    print_modules(target);
    if (find_jscript(target) == 0){
       //forcibly loading not is in use right now...it uses remotealloc and createremotethread()...
       /* load_jscript(hProcess);
        find_jscript(target); //ok see if its loaded *now*
       */ 
        printf("\nJscript.dll is not loaded in IE. Browse to google or something first...");
        return 1;
    }
    printf("\nChecking Environment...");
    // Initialize DbgHelp and load symbols for all modules of the current process
    if (GetEnvironmentVariable("_NT_SYMBOL_PATH", symUserDefined, MAX_PATH) == 0){
        printf("\n_NT_SYMBOL_PATH not defined in environment.");
        printf("\nLoading Symbols (Note: This may take a while if it's the first time, cuz we gotta download 'em.)");
        bRet = SymInitialize (
                hProcess,  // Process handle of the current process
                (PSTR)&symLocalRemote,
                TRUE                  // Load symbols for all modules in the current process
              );
        if( !bRet ){
            _tprintf(_T("Error: SymInitialize() failed. Error code: %u \n"), GetLastError());
            return 0;
        }
    } else {   
        bRet = SymInitialize (
                hProcess,  // Process handle of the current process
                (PSTR)&symUserDefined,
                TRUE                  // Load symbols for all modules in the current process
              );
        if( !bRet ){
            _tprintf(_T("Error: SymInitialize() failed. Error code: %u \n"), GetLastError());
            return 0;
        }
    }
    
     _tprintf( _T("\nLooking for symbol %s ... \n"), (LPSTR)&symName);
    CSymbolInfoPackage sip; // it contains SYMBOL_INFO structure plus additional 
                                                    // space for the name of
                                                    // the symbol 
    bRet = SymFromName( 
                            hProcess, // Process handle of the current process 
                            (LPSTR)&symName,            // Symbol name 
                            &sip.si              // Address of the SYMBOL_INFO structure (inside "sip" object) 
                        );  

    if( !bRet ) {   
        _tprintf( _T("Error: SymFromName() failed.\n") );
//        if (GetLastError() == 126) printf("\nBe sure that symsrv.dll and dbghelp.dll are in your resolv path.");
//        else printf("\nError: %u", GetLastError());
        printf("\nError: %u", GetLastError());
    }   
    else {   
        _tprintf( _T("Symbol found!\n") );  
        ShowSymbolDetails(sip.si);
        symAddr = sip.si.Address;
        attach(target);
        saved_byte[0] = setBreakpoint(symAddr,hProcess);
//        debugLoop_hardwarebp(INFINITE, symAddr, hProcess);
        debugLoop_softwarebp(INFINITE, symAddr, (PUCHAR)&saved_byte[0], hProcess);
    }   

    // Deinitialize DbgHelp
    bRet = SymCleanup(hProcess);
    if( !bRet ){
        _tprintf(_T("Error: SymCleanup() failed. Error code: %u \n"), GetLastError());
        return 0;
    }
    
    // Complete
    return 0;
}
