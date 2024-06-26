# Copyright 2023 TikTok Pte. Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.14)

###################################################
# Project SOLO includes the following components: #
#   1. SOLO C++ library                           #
#   2. SOLO C++ test                              #
#   3. SOLO C++ bench                             #
#   4. SOLO C++ example                           #
###################################################

# [OPTION] CMAKE_BUILD_TYPE (DEFAULT: "Release")
# Select from Release, Debug, MiniSizeRel, or RelWithDebInfo.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

project(SOLO VERSION 0.3.0 LANGUAGES CXX C)

########################
# Global configuration #
########################

# CMake modules
include(CMakeDependentOption)
include(CMakePushCheckState)
include(CheckIncludeFileCXX)
include(CheckCXXSourceCompiles)
include(CheckCXXSourceRuns)

# Custom modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
include(SoloCustomMacros)

# In Debug mode, define SOLO_DEBUG.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(SOLO_DEBUG ON)
else()
    set(SOLO_DEBUG OFF)
endif()
message(STATUS "SOLO debug mode: ${SOLO_DEBUG}")

# In Debug mode, enable extra compiler flags.
include(EnableDebugFlags)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# [OPTION] SOLO_USE_CXX17 (default: OFF)
# Use C++17, use C++14 otherwise.
set(SOLO_USE_CXX17_OPTION_STR "Use C++17")
option(SOLO_USE_CXX17 ${SOLO_USE_CXX17_OPTION_STR} OFF)
message(STATUS "SOLO_USE_CXX17: ${SOLO_USE_CXX17}")
# Enable features from C++17 if available, disable features if set to OFF.
include(EnableCXX17)

# Add default files and directories.
include(GNUInstallDirs)

# Runtime path
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Source Tree
set(SOLO_INCLUDES_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(SOLO_CONFIG_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/cmake/PETAce-SoloConfig.cmake.in)
set(SOLO_CONFIG_H_IN_FILENAME ${SOLO_INCLUDES_DIR}/solo/util/config.h.in)

# Build tree
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(SOLO_CONFIG_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/PETAce-SoloConfig.cmake)
set(SOLO_TARGETS_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/PETAce-SoloTargets.cmake)
set(SOLO_CONFIG_VERSION_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/PETAce-SoloConfigVersion.cmake)
set(SOLO_CONFIG_H_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/src/solo/util/config.h)
set(SOLO_THIRDPARTY_DIR ${CMAKE_CURRENT_BINARY_DIR}/thirdparty)

# Installation tree
set(SOLO_CONFIG_INSTALL_DIR  ${CMAKE_INSTALL_LIBDIR}/cmake/PETAce-Solo-${SOLO_VERSION_MAJOR}.${SOLO_VERSION_MINOR})
set(SOLO_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/PETAce-${SOLO_VERSION_MAJOR}.${SOLO_VERSION_MINOR})
set(SOLO_THIRDPARTY_INCLUDES_INSTALL_DIR ${SOLO_INCLUDES_INSTALL_DIR}/thirdparty)

# Make the install target depend on the all target.
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY OFF)

# Supported target operating systems are Linux and macOS.
if(NOT DEFINED LINUX)
    if (UNIX AND NOT APPLE AND NOT CYGWIN AND NOT MINGW)
        set(LINUX ON)
    endif()
endif()
if(UNIX AND APPLE)
    set(MACOS ON)
endif()
if(NOT LINUX AND NOT MACOS)
    message(FATAL_ERROR "Supported target operating systems are Linux and macOS")
endif()

# Only support x86_64 and arm64
set(CMAKE_REQUIRED_QUIET_OLD ${CMAKE_REQUIRED_QUIET})
set(CMAKE_REQUIRED_QUIET ON)
CHECK_CXX_SOURCE_RUNS("
    #if defined(__aarch64__)
        int main() {
            return 0;
        }
    #else
        #error
    #endif
    "
    SOLO_ARM64
)
CHECK_CXX_SOURCE_RUNS("
    #if defined(__amd64)
        int main() {
            return 0;
        }
    #else
        #error
    #endif
    "
    SOLO_AMD64
)
set(CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET_OLD})
if(NOT SOLO_AMD64 AND NOT SOLO_ARM64)
    message(FATAL_ERROR "Supported target architectures are x86_64 and arm64")
endif()

# AES, SSE, and AVX
CHECK_INCLUDE_FILE_CXX("wmmintrin.h" SOLO_USE_AES_INTRIN)
if(SOLO_USE_AES_INTRIN)
    add_compile_options(-msse4.2 -mavx -maes)
endif()

# Enable test coverage
set(SOLO_ENABLE_GCOV_STR "Enable gcov")
option(SOLO_ENABLE_GCOV ${SOLO_ENABLE_GCOV_STR} OFF)
message(STATUS "SOLO_ENABLE_GCOV: ${SOLO_ENABLE_GCOV_STR}")
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND SOLO_ENABLE_GCOV)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -fprofile-arcs -ftest-coverage -lgcov")
endif()

#########################
# External dependencies #
#########################

# [OPTION] SOLO_BUILD_DEPS (DEFAULT: ON)
# Download and build dependencies if set to ON.
# Look for dependencies using find_package, otherwise.
set(SOLO_BUILD_DEPS_OPTION_STR "Automatically download and build unmet dependencies")
option(SOLO_BUILD_DEPS ${SOLO_BUILD_DEPS_OPTION_STR} ON)
message(STATUS "SOLO_BUILD_DEPS: ${SOLO_BUILD_DEPS}")

# [OPTION] SOLO_USE_IPCL (default: OFF)
set(SOLO_USE_IPCL_OPTION_STR "Use IPCL")
option(SOLO_USE_IPCL ${SOLO_USE_IPCL_OPTION_STR} OFF)
message(STATUS "SOLO_USE_IPCL: ${SOLO_USE_IPCL}")

if(SOLO_BUILD_DEPS)
    include(FetchContent)
    mark_as_advanced(FETCHCONTENT_BASE_DIR)
    mark_as_advanced(FETCHCONTENT_FULLY_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_QUIET)
endif()

# OpenSSL
find_package(OpenSSL 1.1.1 QUIET)
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL: found")
    set(openssl "OpenSSL::Crypto")
else()
    if(SOLO_BUILD_DEPS)
        message(STATUS "OpenSSL: download ...")
        solo_fetch_thirdparty_content(ExternalOpenSSL)
        set(openssl "crypto")
        set(SOLO_BUILD_OPENSSL TRUE)
    else()
        message(FATAL_ERROR "OpenSSL: not found, please download and install manually")
    endif()
endif()

# Intel Paillier Cryptosystem Library
if(SOLO_USE_IPCL)
    find_package(IPCL QUIET REQUIRED)
    if(IPCL_FOUND)
        message(STATUS "IPCL: found")
        if (TARGET ipcl AND NOT TARGET IPCL::ipcl)
            add_library(IPCL::ipcl ALIAS ipcl)
        endif()
    else()
        message(FATAL_ERROR "IPCL: not found, please download and install manually")
    endif()
else()
    solo_fetch_thirdparty_content(ExternalGMP)
    set(SOLO_BUILD_GMP TRUE CACHE BOOL "" FORCE)
endif()

# Require Threads::Threads
if(NOT TARGET Threads::Threads)
    set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads REQUIRED)
endif()

if(NOT SOLO_USE_IPCL)
    # OpenMP::OpenMP_CXX
    if(NOT TARGET OpenMP::OpenMP_CXX)
        find_package(OpenMP REQUIRED)
        if(NOT OpenMP_FOUND)
            message(FATAL_ERROR "OpenMP: not found")
        else()
            message(STATUS "OpenMP: found")
        endif()
    endif()
endif()

####################
# SOLO C++ library #
####################

# [OPTION] SOLO_BUILD_SHARED_LIBS (DEFAULT: OFF)
# Build a shared library if set to ON.
set(SOLO_BUILD_SHARED_LIBS_STR "Build shared library")
option(SOLO_BUILD_SHARED_LIBS ${SOLO_BUILD_SHARED_LIBS_STR} OFF)
message(STATUS "SOLO_BUILD_SHARED_LIBS: ${SOLO_BUILD_SHARED_LIBS}")

# Add source files to library and header files to install
set(SOLO_SOURCE_FILES "")
add_subdirectory(src/solo)

# Create the config file
configure_file(${SOLO_CONFIG_H_IN_FILENAME} ${SOLO_CONFIG_H_FILENAME})
install(
    FILES ${SOLO_CONFIG_H_FILENAME}
    DESTINATION ${SOLO_INCLUDES_INSTALL_DIR}/solo/util)

# Build only a static library
if(NOT SOLO_BUILD_SHARED_LIBS)
    add_library(solo STATIC ${SOLO_SOURCE_FILES})
    if(SOLO_USE_CXX17)
        target_compile_features(solo PUBLIC cxx_std_17)
    else()
        target_compile_features(solo PUBLIC cxx_std_14)
    endif()
    target_include_directories(solo PUBLIC
        $<BUILD_INTERFACE:${SOLO_INCLUDES_DIR}>
        $<INSTALL_INTERFACE:${SOLO_INCLUDES_INSTALL_DIR}>)
    target_include_directories(solo PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src/>)
    set_target_properties(solo PROPERTIES VERSION ${SOLO_VERSION})
    set_target_properties(solo PROPERTIES OUTPUT_NAME petace_solo-${SOLO_VERSION_MAJOR}.${SOLO_VERSION_MINOR})
    install(TARGETS solo EXPORT PETAce-SoloTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    if(SOLO_BUILD_OPENSSL)
        add_dependencies(solo ${openssl})
        target_include_directories(solo PUBLIC $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>)
        target_include_directories(solo PUBLIC $<BUILD_INTERFACE:$<TARGET_PROPERTY:${openssl},BINARY_DIR>>)
        target_include_directories(solo PUBLIC $<INSTALL_INTERFACE:${SOLO_THIRDPARTY_INCLUDES_INSTALL_DIR}>)
        solo_combine_archives(solo ${openssl})
        set(SOLO_CARRY_OPENSSL TRUE)
    else()
        target_link_libraries(solo PUBLIC ${openssl})
        set(SOLO_CARRY_OPENSSL FALSE)
    endif()

    if(SOLO_USE_IPCL)
        target_link_libraries(solo PUBLIC IPCL::ipcl)
    else()
        add_dependencies(solo gmpxx gmp)
        target_include_directories(solo PUBLIC $<BUILD_INTERFACE:${GMP_INCLUDE_DIR}>)
        solo_combine_archives(solo gmpxx)
        solo_combine_archives(solo gmp)
        target_link_libraries(solo PUBLIC OpenMP::OpenMP_CXX)
        set(SOLO_CARRY_GMP TRUE)
    endif()
    target_link_libraries(solo PUBLIC Threads::Threads)

# Build only a shared library
else()
    add_library(solo_shared SHARED ${SOLO_SOURCE_FILES})
    if(SOLO_USE_CXX17)
        target_compile_features(solo_shared PUBLIC cxx_std_17)
    else()
        target_compile_features(solo_shared PUBLIC cxx_std_14)
    endif()
    target_include_directories(solo_shared PUBLIC
        $<BUILD_INTERFACE:${SOLO_INCLUDES_DIR}>
        $<INSTALL_INTERFACE:${SOLO_INCLUDES_INSTALL_DIR}>)
    target_include_directories(solo_shared PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src/>)
    set_target_properties(solo_shared PROPERTIES VERSION ${SOLO_VERSION})
    set_target_properties(solo_shared PROPERTIES OUTPUT_NAME petace_solo)
    set_target_properties(solo_shared PROPERTIES SOVERSION ${SOLO_VERSION_MAJOR}.${SOLO_VERSION_MINOR})
    install(TARGETS solo_shared EXPORT PETAce-SoloTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    if(SOLO_BUILD_OPENSSL)
        target_link_libraries(solo_shared PUBLIC ${openssl})
        target_include_directories(solo_shared PUBLIC $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>)
        target_include_directories(solo_shared PUBLIC $<BUILD_INTERFACE:$<TARGET_PROPERTY:${openssl},BINARY_DIR>>)
        target_include_directories(solo_shared PUBLIC $<INSTALL_INTERFACE:${SOLO_THIRDPARTY_INCLUDES_INSTALL_DIR}>)
    else()
        target_link_libraries(solo_shared PUBLIC ${openssl})
    endif()
    set(SOLO_CARRY_OPENSSL FALSE)

    if(SOLO_USE_IPCL)
        target_link_libraries(solo_shared PUBLIC IPCL::ipcl)
    else()
        add_dependencies(solo_shared gmpxx_shared gmp_shared)
        target_include_directories(solo_shared PUBLIC $<BUILD_INTERFACE:${GMP_INCLUDE_DIR}>)
        target_link_libraries(solo_shared PUBLIC gmpxx_shared gmp_shared OpenMP::OpenMP_CXX)
        set(SOLO_CARRY_GMP FALSE)
    endif()
    target_link_libraries(solo_shared PUBLIC Threads::Threads)
endif()

# Add standard alias targets for PETAce-Solo::solo and PETAce-Solo::solo_shared
if(TARGET solo)
    add_library(PETAce-Solo::solo ALIAS solo)
endif()
if(TARGET solo_shared)
    add_library(PETAce-Solo::solo_shared ALIAS solo_shared)
endif()

#################################
# Installation and CMake config #
#################################

# Create the CMake config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${SOLO_CONFIG_IN_FILENAME} ${SOLO_CONFIG_FILENAME}
    INSTALL_DESTINATION ${SOLO_CONFIG_INSTALL_DIR})

# Install the export
install(
    EXPORT PETAce-SoloTargets
    NAMESPACE PETAce-Solo::
    DESTINATION ${SOLO_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
write_basic_package_version_file(
    ${SOLO_CONFIG_VERSION_FILENAME}
    VERSION ${SOLO_VERSION}
    COMPATIBILITY SameMinorVersion)

# Install config and module files
install(
    FILES
        ${SOLO_CONFIG_FILENAME}
        ${SOLO_CONFIG_VERSION_FILENAME}
    DESTINATION ${SOLO_CONFIG_INSTALL_DIR})

# We export PETAce-SoloTargets from the build tree so it can be used by other projects
# without requiring an install.
export(
    EXPORT PETAce-SoloTargets
    NAMESPACE PETAce-Solo::
    FILE ${SOLO_TARGETS_FILENAME})

# Install header files of dependencies if SOLO_BUILD_DEPS is ON
if(SOLO_BUILD_DEPS)
    # Insert dependencies here
    if(SOLO_BUILD_OPENSSL)
        install(
            FILES ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY}
            DESTINATION ${CMAKE_INSTALL_LIBDIR})
        install(
            DIRECTORY ${OPENSSL_INCLUDE_DIR}
            DESTINATION ${SOLO_THIRDPARTY_INCLUDES_INSTALL_DIR}/openssl)
    endif()
    if(SOLO_BUILD_GMP)
        if(SOLO_BUILD_SHARED_LIBS)
            install(
                FILES ${GMP_C_SHARED_LIBRARY} ${GMP_CXX_SHARED_LIBRARY}
                DESTINATION ${CMAKE_INSTALL_LIBDIR})
        endif()
        install(
            FILES ${GMP_INCLUDE_DIR}/gmp.h ${GMP_INCLUDE_DIR}/gmpxx.h
            DESTINATION ${SOLO_THIRDPARTY_INCLUDES_INSTALL_DIR})
    endif()
endif()

####################
# SOLO C++ example #
####################

# [option] SOLO_BUILD_EXAMPLE
set(SOLO_BUILD_EXAMPLE_OPTION_STR "Build C++ example for SOLO")
option(SOLO_BUILD_EXAMPLE ${SOLO_BUILD_EXAMPLE_OPTION_STR} ON)
message(STATUS "SOLO_BUILD_EXAMPLE: ${SOLO_BUILD_EXAMPLE}")

if(SOLO_BUILD_EXAMPLE)
    add_subdirectory(example)
endif()

#################
# SOLO C++ test #
#################

# [option] SOLO_BUILD_TEST
set(SOLO_BUILD_TEST_OPTION_STR "Build C++ test for SOLO")
option(SOLO_BUILD_TEST ${SOLO_BUILD_TEST_OPTION_STR} ON)
message(STATUS "SOLO_BUILD_TEST: ${SOLO_BUILD_TEST}")

if(SOLO_BUILD_TEST)
    add_subdirectory(test)

    if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND SOLO_ENABLE_GCOV)
        add_custom_target(test_coverage
            COMMAND gcovr -r ${CMAKE_CURRENT_LIST_DIR} -f \"src\" -e \".+\(test\\.cpp\)\" --xml-pretty -o "${CMAKE_CURRENT_BINARY_DIR}/report/coverage.xml"
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
    endif()
endif()

##################
# SOLO C++ bench #
##################

# [option] SOLO_BUILD_BENCH
set(SOLO_BUILD_BENCH_OPTION_STR "Build C++ benchmark for SOLO")
option(SOLO_BUILD_BENCH ${SOLO_BUILD_BENCH_OPTION_STR} ON)
message(STATUS "SOLO_BUILD_BENCH: ${SOLO_BUILD_BENCH}")

if(SOLO_BUILD_BENCH)
    add_subdirectory(bench)
endif()
