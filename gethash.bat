@echo off

if not exist t:\deeptide\mysthookproc\mysthookproc32.dll (
	echo "source mysthookproc32.dll not found"
	goto :eof
)
if not exist t:\deeptide\mysthookproc\mysthookproc64.dll (
	echo "source mysthookproc64.dll not found"
	goto :eof
)

del c:\programdata\arcticmyst\mysthookproc32.dll >nul 2>&1
if exist c:\programdata\arcticmyst\mysthookproc32.dll (
	echo "target mysthookproc32.dll is still in use"
	goto :eof
)
del c:\programdata\arcticmyst\mysthookproc64.dll >nul 2>&1
if exist c:\programdata\arcticmyst\mysthookproc64.dll (
	echo "target mysthookproc64.dll is still in use"
	goto :eof
)

FOR /F "delims=" %%i IN ('certUtil -hashfile t:\deeptide\mysthookproc\mysthookproc32.dll SHA256 ^| find /V "hash"') DO set hash=%%i
echo #define _hash32 "%hash%" >hashes.h
echo #define _hash32 "%hash%" >t:/deeptide/mystsvc/hashes.h

FOR /F "delims=" %%i IN ('certUtil -hashfile t:\deeptide\mysthookproc\mysthookproc64.dll SHA256 ^| find /V "hash"') DO set hash=%%i
echo #define _hash64 "%hash%" >>hashes.h
echo #define _hash64 "%hash%" >>t:/deeptide/mystsvc/hashes.h

FOR /F "delims=" %%i IN ('certUtil -hashfile t:\deeptide\arcticmyst.exe SHA256 ^| find /V "hash"') DO set hash=%%i
echo #define _mainexe "%hash%" >>t:/deeptide/mystsvc/hashes.h

copy t:\deeptide\mysthookproc\mysthookproc32.dll c:\programdata\arcticmyst\mysthookproc32.dll
copy t:\deeptide\mysthookproc\mysthookproc64.dll c:\programdata\arcticmyst\mysthookproc64.dll


