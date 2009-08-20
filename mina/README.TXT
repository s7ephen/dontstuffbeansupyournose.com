
INSTALL:
 * Be sure dbghelp.dll and symsrv.dll are in the system path if not, install
        "Debugging tools for Windows"
 * Create C:\the_mina and C:\the_mina\syms c:\the_mina\logs
 
USING:
 * Goto Start->Run->"iexplore www.google.com"
 * run mina.exe

BUILDING FROM SCRATCH:
 * You need Visual Studio. Run vcvars32.bat (or vsvars32.bat) from
   cmd.exe
 * you may need to change lib and include path in make.bat
 * run make.bat from the vcvars32 env term

