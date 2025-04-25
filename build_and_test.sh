#!/bin/bash
# Script to build and test citadelle

# Stop on error
set -e

# Create build directory if it doesn't exist
mkdir -p build
cd build

# Configure with CMake
echo "Configuring with CMake..."
cmake ..

# Build
echo "Building the library and tests..."
cmake --build . --config Release

# Run example executable
echo "Running example application..."
./citadelle_bin

# Run tests
echo "Running tests..."
ctest -V

echo "Build and tests completed successfully!" 