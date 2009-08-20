#!/usr/bin/env python
#
# PyDBGHelp
# 
#   The purpose of this is to be a wrapper for *just* enough
#   functionality from the dbghelp library to resolve debug symbols 
#   for windows binaries. This means not just PE EXPORT_TABLE symbols.
#   Why? Because sometimes you want to break on more than dllcanunloadnow ;-)
#
# Notes:
# 1. OpenProcess() needed for hProcess of dbghelp functions
# 
import ctypes
import os
import sys


global SYMOPT_CASE_INSENSITIVE        
global SYMOPT_UNDNAME                 
global SYMOPT_DEFERRED_LOADS          
global SYMOPT_NO_CPP                  
global SYMOPT_LOAD_LINES              
global SYMOPT_OMAP_FIND_NEAREST       
global SYMOPT_LOAD_ANYTHING           
global SYMOPT_IGNORE_CVREC            
global SYMOPT_NO_UNQUALIFIED_LOADS    
global SYMOPT_FAIL_CRITICAL_ERRORS    
global SYMOPT_EXACT_SYMBOLS           
global SYMOPT_ALLOW_ABSOLUTE_SYMBOLS  
global SYMOPT_IGNORE_NT_SYMPATH       
global SYMOPT_INCLUDE_32BIT_MODULES   
global SYMOPT_PUBLICS_ONLY            
global SYMOPT_NO_PUBLICS              
global SYMOPT_AUTO_PUBLICS            
global SYMOPT_NO_IMAGE_SEARCH         
global SYMOPT_SECURE                  
global SYMOPT_NO_PROMPTS              
global SYMOPT_DEBUG                   

SYMOPT_CASE_INSENSITIVE=         0x00000001
SYMOPT_UNDNAME=                  0x00000002
SYMOPT_DEFERRED_LOADS=           0x00000004
SYMOPT_NO_CPP=                   0x00000008
SYMOPT_LOAD_LINES=               0x00000010
SYMOPT_OMAP_FIND_NEAREST=        0x00000020
SYMOPT_LOAD_ANYTHING=            0x00000040
SYMOPT_IGNORE_CVREC=             0x00000080
SYMOPT_NO_UNQUALIFIED_LOADS=     0x00000100
SYMOPT_FAIL_CRITICAL_ERRORS=     0x00000200
SYMOPT_EXACT_SYMBOLS=            0x00000400
SYMOPT_ALLOW_ABSOLUTE_SYMBOLS=   0x00000800
SYMOPT_IGNORE_NT_SYMPATH=        0x00001000
SYMOPT_INCLUDE_32BIT_MODULES=    0x00002000
SYMOPT_PUBLICS_ONLY=             0x00004000
SYMOPT_NO_PUBLICS=               0x00008000
SYMOPT_AUTO_PUBLICS=             0x00010000
SYMOPT_NO_IMAGE_SEARCH=          0x00020000
SYMOPT_SECURE=                   0x00040000
SYMOPT_NO_PROMPTS=               0x00080000
SYMOPT_DEBUG=                    0x80000000

global DELETE                           
global READ_CONTROL                     
global WRITE_DAC                        
global WRITE_OWNER                      
global SYNCHRONIZE                      
global STANDARD_RIGHTS_REQUIRED         
global STANDARD_RIGHTS_READ             
global STANDARD_RIGHTS_WRITE            
global STANDARD_RIGHTS_EXECUTE          
global STANDARD_RIGHTS_ALL              
global SPECIFIC_RIGHTS_ALL              

DELETE=                           (0x00010000L)
READ_CONTROL=                     (0x00020000L)
WRITE_DAC=                        (0x00040000L)
WRITE_OWNER=                      (0x00080000L)
SYNCHRONIZE=                      (0x00100000L)
STANDARD_RIGHTS_REQUIRED=         (0x000F0000L)
STANDARD_RIGHTS_READ=             (READ_CONTROL)
STANDARD_RIGHTS_WRITE=            (READ_CONTROL)
STANDARD_RIGHTS_EXECUTE=          (READ_CONTROL)
STANDARD_RIGHTS_ALL=              (0x001F0000L)
SPECIFIC_RIGHTS_ALL=              (0x0000FFFFL)

#Ignore this token stuff, for a while I thought I was going
# to have to get debug privs in the token
global TOKEN_ASSIGN_PRIMARY    
global TOKEN_DUPLICATE         
global TOKEN_IMPERSONATE       
global TOKEN_QUERY             
global TOKEN_QUERY_SOURCE      
global TOKEN_ADJUST_PRIVILEGES 
global TOKEN_ADJUST_GROUPS     
global TOKEN_ADJUST_DEFAULT    
global TOKEN_ADJUST_SESSIONID  
global TOKEN_ALL_ACCESS_P
global TOKEN_ALL_ACCESS
global TOKEN_READ
global TOKEN_WRITE
global TOKEN_EXECUTE
 
TOKEN_ASSIGN_PRIMARY=    0x0001
TOKEN_DUPLICATE=         0x0002
TOKEN_IMPERSONATE=       0x0004
TOKEN_QUERY=             0x0008
TOKEN_QUERY_SOURCE=      0x0010
TOKEN_ADJUST_PRIVILEGES= 0x0020
TOKEN_ADJUST_GROUPS=     0x0040
TOKEN_ADJUST_DEFAULT=    0x0080
TOKEN_ADJUST_SESSIONID=  0x0100

TOKEN_ALL_ACCESS_P = (STANDARD_RIGHTS_REQUIRED  |\
TOKEN_ASSIGN_PRIMARY      |\
TOKEN_DUPLICATE           |\
TOKEN_IMPERSONATE         |\
TOKEN_QUERY               |\
TOKEN_QUERY_SOURCE        |\
TOKEN_ADJUST_PRIVILEGES   |\
TOKEN_ADJUST_GROUPS       |\
TOKEN_ADJUST_DEFAULT)

TOKEN_ALL_ACCESS = TOKEN_ALL_ACCESS_P

TOKEN_READ=(STANDARD_RIGHTS_READ | TOKEN_QUERY)

TOKEN_WRITE=(STANDARD_RIGHTS_WRITE     |\
TOKEN_ADJUST_PRIVILEGES   |\
TOKEN_ADJUST_GROUPS       |\
TOKEN_ADJUST_DEFAULT)

TOKEN_EXECUTE=STANDARD_RIGHTS_EXECUTE

global PROCESS_TERMINATE         
global PROCESS_CREATE_THREAD     
global PROCESS_SET_SESSIONID     
global PROCESS_VM_OPERATION      
global PROCESS_VM_READ           
global PROCESS_VM_WRITE          
global PROCESS_DUP_HANDLE        
global PROCESS_CREATE_PROCESS    
global PROCESS_SET_QUOTA         
global PROCESS_SET_INFORMATION   
global PROCESS_QUERY_INFORMATION 
global PROCESS_SUSPEND_RESUME    
global PROCESS_ALL_ACCESS        

PROCESS_TERMINATE=         (0x0001)  
PROCESS_CREATE_THREAD=     (0x0002)  
PROCESS_SET_SESSIONID=     (0x0004)  
PROCESS_VM_OPERATION=      (0x0008)  
PROCESS_VM_READ=           (0x0010)  
PROCESS_VM_WRITE=          (0x0020)  
PROCESS_DUP_HANDLE=        (0x0040)  
PROCESS_CREATE_PROCESS=    (0x0080)  
PROCESS_SET_QUOTA=         (0x0100)  
PROCESS_SET_INFORMATION=   (0x0200)  
PROCESS_QUERY_INFORMATION= (0x0400)  
PROCESS_SUSPEND_RESUME=    (0x0800)  
PROCESS_ALL_ACCESS=        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)

class Symbol_Info(ctypes.Structure):
#    typedef struct _SYMBOL_INFO {
#      ULONG SizeOfStruct;
#      ULONG TypeIndex;
#      ULONG64 Reserved[2];
#      ULONG Index;
#      ULONG Size;
#      ULONG64 ModBase;
#      ULONG Flags;
#      ULONG64 Value;
#      ULONG64 Address;
#      ULONG Register;
#      ULONG Scope;
#      ULONG Tag;
#      ULONG NameLen;
#      ULONG MaxNameLen;
#      TCHAR Name[1];
#    } SYMBOL_INFO, 
#     *PSYMBOL_INFO;
    _fields_ = [("SizeOfStruct", ctypes.c_ulong),
                ("TypeIndex", ctypes.c_ulong),
                ("Reserved", ctypes.c_double * 2),
                ("Index", ctypes.c_ulong),
                ("Size", ctypes.c_ulong),
                ("ModBase", ctypes.c_double),
                ("Flags", ctypes.c_ulong),
                ("Value", ctypes.c_double),
                ("Address", ctypes.c_double),
                ("Register", ctypes.c_ulong),
                ("Scope", ctypes.c_ulong),
                ("Tag", ctypes.c_ulong),
                ("NameLen", ctypes.c_ulong),
                ("MaxNameLen", ctypes.c_ulong),
                ("Name", ctypes.c_wchar)]

                 

def popup(title, message):
    """
        A stupid little test.
    """
    hUser32 = ctypes.windll.LoadLibrary("user32")
    MessageBoxA = getattr(hUser32, "MessageBoxA")
    MessageBoxA(0, message, title,0)

class symHelper():
    """
        
        The following dbghelp.dll functions are available as attributes of this class: 
        
            SymSetOptions()
            SymGetOptions()
            SymCleanup()
            SymInitialize()
            SymFromName() 

    """
    def __init__(self, pid = None, hProcess= None):
        self.startup() #readability

        if (hProcess == None) & (pid != None): #No handle specified, we gotta fetch it
            self.getProcessHandle(pid)
        elif (hProcess != None):
            self.hProcess = hProcess
        elif (hProcess == None) & (pid == None):
            raise "\nRequire *atleast* a process id argument."

        self.symGet_and_symInit()

    def __del__(self):
        self.SymCleanup(self.hProcess)
                
    def startup(self):
        """
            Resolve all the functions we are gonna need...and do
            some other init 
        """
        try:
            self.hDbgHelp = ctypes.windll.LoadLibrary("dbghelp")
        except WindowsError (errno, strerror):
            if errno == 126: #module not found
                print("\nLooks like you dont have dbghelp.dll in your resolve PATH. Quitting.") 
                sys.exit(1)

        self.hAdvapi32 = ctypes.windll.LoadLibrary("advapi32") #We need this for
                                                               #token manipulation

        #DbgHelp Imports
        self.SymSetOptions = getattr(self.hDbgHelp, "SymSetOptions")
        self.SymGetOptions = getattr(self.hDbgHelp, "SymGetOptions")
        self.SymCleanup = getattr(self.hDbgHelp, "SymCleanup")
        self.SymInitialize = getattr(self.hDbgHelp, "SymInitialize")
        self.SymFromName = getattr(self.hDbgHelp, "SymFromName")
        self.symoptions = ctypes.c_long(0) #DWORD

        #Advapi32 Imports
        self.OpenProcessToken = getattr(self.hAdvapi32, "OpenProcessToken")
        self.LookupPrivilegeValue = getattr(self.hAdvapi32, "LookupPrivilegeValueA")
        self.AdjustTokenPrivileges = getattr(self.hAdvapi32, "AdjustTokenPrivileges")
        
        # Kernel32 imports 
        self.OpenProcess = getattr(ctypes.windll.kernel32,"OpenProcess")
        self.GetLastError = getattr(ctypes.windll.kernel32,"GetLastError")
        self.GetCurrentProcess = getattr(ctypes.windll.kernel32,"GetCurrentProcess") 

    def symGet_and_symInit(self, sympath = None):
        """
            Do SymGetOptions()
            Do symSetOtions(DEBUG)
            Do SymInitialize(hProcess)
            return hProcess
        """
        self.symoptions = self.SymGetOptions()
        self.symoptions |= SYMOPT_DEBUG
        print self.symoptions
        self.SymSetOptions(self.symoptions)
        if sympath == None:
            sympath = os.getenv("_NT_SYMBOL_PATH")
            if sympath == None:
                sympath = os.getenv("TEMP")
                if sympath == None:
                    print("\nWTF? No TEMP is defined in environment!?")
                    sys.exit(1)
                else:
                    sympath+="\\pydbghelp_temp\\"
                    if not os.path.exists(sympath):
                        os.mkdir(sympath) 
                print("\n_NT_SYMBOL_PATH not defined in environment.\n\tUsing %s and Microsoft Symbol Server." % sympath )
                print("\n INITIALIZING SYMBOLS! ")
                print("\n\t*** Symbol Download could take a while, please wait. ***");
                return(self.SymInitialize(self.hProcess, "symsrv*symsrv.dll*"+sympath+"*http://msdl.microsoft.com/download/symbols", True))

        print("\n INITIALIZING SYMBOLS! ")
        print("\n\tUsing %s as symbol path." % sympath )
        return(self.SymInitialize(self.hProcess, sympath, True))

    def getSymFromName(self, name):
        """
            The main "useful" function in this class:

            USAGE:
            getSymFromName("jscript!COleScript::Compile")

            Returns:
                Address of symbol if successful
                Zero if Fail.

        """
        #symInfo = Symbol_Info()
        symInfo = ctypes.create_string_buffer(40)
        bret = False
        #bret = self.SymFromName(self.hProcess, ctypes.byref(ctypes.create_string_buffer(name)), ctypes.byref(symInfo))
        
        bret = self.SymFromName(self.hProcess, name, ctypes.byref(symInfo))
        print repr(symInfo.raw)
        if bret == False:
            print("\nSymFromName() failed for symbol: %s" % name)
            print("\nError: %d.",self.GetLastError())
            return 0
        else:
            print ("\nSymbol Found!")
            #self.showSymbolInfo(symInfo)
            #return(symInfo.Address)
 
    def getProcessHandle(self, pid):
        #self.hProcess = self.OpenProcess(PROCESS_QUERY_INFORMATION, True, pid)
        self.hProcess = self.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE, False, pid)
        if self.hProcess == 0:
            print("\nOpenProcess() failed for %d" % pid)
        else:
            print("\nAttached to process id: %d" % pid)
            self.pid = pid

    def showSymbolInfo(self, symInfo):
        print("Symbol:\t%d" % symInfo.Tag)
        print("SizeOfStruct:\t%d" % symInfo.SizeOfStruct)
        print("Address:\t%x" % symInfo.Address)
        print("Size:\t%u" % symInfo.Size)
        print("Name:\t%s" % symInfo.Name)
        print("\n")
