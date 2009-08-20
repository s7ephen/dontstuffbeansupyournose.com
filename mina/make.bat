rem HOLY SHIT when using cpp libs and headers (such as msi.h in this case
rem our actual file name (ident_self) has to have the .cpp extension
rem or cl.exe parses it differently or something... if named .c it doesnt compile
rem when named .cpp it does.

cl /nologo /Z7 mina.cpp /I"C:\Program Files\Microsoft Visual Studio 8\VC\PlatformSDK\Include" /c
link /nologo /libpath:"C:\Program Files\Microsoft Visual Studio 8\VC\PlatformSDK\Lib" dbghelp.lib advapi32.lib psapi.lib /out:mina.exe mina.obj
