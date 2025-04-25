cmake_minimum_required(VERSION 3.10)
project(citadelle VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add option to use liboqs for real PQC implementation
option(USE_LIBOQS "Use liboqs for real post-quantum cryptography" OFF)

# Include FetchContent for fetching Google Test
include(FetchContent)

# Find OpenSSL which we'll use for basic cryptographic operations
find_package(OpenSSL REQUIRED)

# Conditionally find liboqs
if(USE_LIBOQS)
    # Try to find liboqs through pkg-config first
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBOQS liboqs)
    endif()
    
    # If pkg-config failed, try find_package
    if(NOT LIBOQS_FOUND)
        find_package(liboqs QUIET)
    endif()
    
    # If both failed, fetch liboqs via FetchContent as a last resort
    if(NOT LIBOQS_FOUND AND NOT liboqs_FOUND)
        message(STATUS "liboqs not found, fetching from source")
        set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "Build only liboqs library" FORCE)
        set(OQS_USE_OPENSSL OFF CACHE BOOL "Use OpenSSL" FORCE)
        FetchContent_Declare(
            liboqs
            GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
            GIT_TAG main  # Replace with a specific tag for reproducible builds
        )
        FetchContent_MakeAvailable(liboqs)
        set(LIBOQS_LIBRARIES oqs)
        set(LIBOQS_INCLUDE_DIRS ${liboqs_SOURCE_DIR}/src/common/include ${liboqs_SOURCE_DIR}/src)
    endif()

    # Define that we're using liboqs for the real implementation
    add_compile_definitions(CITADELLE_USE_LIBOQS)
endif()

# Set include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
if(USE_LIBOQS)
    include_directories(${LIBOQS_INCLUDE_DIRS})
endif()

# Add library
add_library(citadelle STATIC
    src/key_exchange.cpp
)

target_link_libraries(citadelle
    OpenSSL::Crypto
)

if(USE_LIBOQS)
    target_link_libraries(citadelle ${LIBOQS_LIBRARIES})
endif()

# Add executable
add_executable(citadelle_bin src/main.cpp)
target_link_libraries(citadelle_bin
    citadelle
)

# Installation
install(TARGETS citadelle DESTINATION lib)
install(TARGETS citadelle_bin DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)

# Enable testing
option(BUILD_TESTS "Build the tests" ON)
if(BUILD_TESTS)
    # Fetch Google Test
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    
    enable_testing()
    
    # Add test executable
    add_executable(citadelle_tests
        tests/key_exchange_test.cpp
        tests/integration_test.cpp
        tests/security_test.cpp
    )
    
    target_link_libraries(citadelle_tests
        citadelle
        GTest::gtest_main
        GTest::gmock_main
    )
    
    include(GoogleTest)
    gtest_discover_tests(citadelle_tests)
endif() 