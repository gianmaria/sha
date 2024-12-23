@echo off

setlocal
set mode=%1

if "%mode%"=="debug" (
    set optimization=/Od /Zi /MDd
    set macro=/D "_DEBUG"
) else if "%mode%"=="release" (
    set optimization=/O2 /Zi /MD
    set macro=/D "_NDEBUG"
) else (
    echo Invalid mode specified. Use "debug" or "release".
    exit /b 1
)

rem echo Building in: %mode%
rem echo Options: %opt%
rem echo Macros: %macro%
rem exit /b 0

set base=%~dp0

if not exist build\%mode% mkdir build\%mode%
pushd build\%mode%

cl /nologo /FC /std:c++20 ^
/EHsc ^
%optimization% ^
/utf-8 /Zc:__cplusplus ^
%macro% ^
/D "_CONSOLE" /D "_UNICODE" /D "UNICODE" ^
/I%base% ^
%base%\win_cpp_crypt.cpp %base%\sha.cpp ^
/link /MACHINE:X64 /SUBSYSTEM:CONSOLE /DEBUG:full /OUT:sha.exe

popd
endlocal
