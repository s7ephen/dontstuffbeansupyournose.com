lawler's quick notes:

1) edit build.py to point IDASDK to wherever you unpacked the IDA 54
   sdk
   this cannot have spaces in the name
2) download swigwin from for example
   http://prdownloads.sourceforge.net/swig/swigwin-1.3.38.zip
3) unpack swigwin somewhere.  copy the "swig.exe" and the "lib"
   directory from swig into the idapython directory
   (so that "lib/" and "swig.exe" from swigwin live right next to
   "README.txt" and "doc/" etc from idapython)
4) python build.py
5) copy the idapython-1.1.0_ida5.4_py2.5_win32 into your ida
   directory
   (e.g., plugins/python.plw to %IDA%/plugins/python.plw, python/*
   to %IDA%/python/*, etc)

I changed swig/idp.i and swig/ua.i so far, minor stuff...

----------------------------------------------------------
IDAPython - Python plugin for Interactive Disassembler Pro
----------------------------------------------------------

WHAT IS IDAPTYHON?
------------------

IDAPython is an IDA plugin which makes it possible to write scripts
for IDA in the Python programming language. IDAPython provides full
access to both the IDA API and any installed Python module.

Check the scripts in the examples directory to get an quick glimpse.


AVAILABILITY
------------

Latest stable versions of IDAPython are available from
  http://www.d-dome.net/idapython/

Development builds are available from
  http://code.google.com/p/idapython/


RESOURCES
---------

The full function cross-reference is readable online at
  http://www.d-dome.net/idapython/reference/

Bugs and enhancement requests should be submitted to
  http://code.google.com/p/idapython/issues/list

Mailing list for the project is hosted by Google Groups at
  http://groups.google.com/group/idapython


INSTALLATION FROM BINARIES
--------------------------

1, Install Python 2.5 from http://www.python.org/
2, Copy the directory python\ to the IDA install directory
3. Copy the plugin to the %IDADIR%\plugins\


USAGE
-----

The plugin has three hotkeys: 

 - Run script (Alt-9)
 - Execute Python statement(s) (Alt-8)
 - Run previously executed script again (Alt-7)

Batch mode execution:

Start IDA with the following command line options:

 -A -OIDAPython:yourscript.py file_to_work_on

If you want fully unattended execution mode, make sure your script
exits with a qexit() call.


User init file:

You can place your custom settings to a file called 'idapythonrc.py'
that should be placed to 

${HOME}/.idapro/

or 

C:\Documents and Settings\%USER%\Application Data\Hex-Rays\IDA Pro

The user init file is read and executed at the end of the init process.

