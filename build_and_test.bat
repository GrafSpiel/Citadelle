@echo off
REM Script to build and test citadelle on Windows

REM Create build directory if it doesn't exist
if not exist build mkdir build
cd build

REM Configure with CMake
echo Configuring with CMake...
cmake ..

REM Build
echo Building the library and tests...
cmake --build . --config Release

REM Run example executable
echo Running example application...
Release\citadelle_bin.exe

REM Run tests
echo Running tests...
ctest -V -C Release

echo Build and tests completed successfully!
pause 