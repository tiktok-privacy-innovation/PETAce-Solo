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

project(SOLOBench VERSION 0.1.0 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SOLO_BUILD_BENCH)
    set(SOLO_BUILD_BENCH ON)

    find_package(PETAce-Solo 0.1.0 EXACT REQUIRED)

    # Must define these variables and include macros
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
    set(SOLO_THIRDPARTY_DIR ${CMAKE_CURRENT_BINARY_DIR}/thirdparty)
    set(THIRDPARTY_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/thirdparty)
    include(FetchContent)
    mark_as_advanced(FETCHCONTENT_BASE_DIR)
    mark_as_advanced(FETCHCONTENT_FULLY_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_QUIET)
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/../cmake)
    include(SoloCustomMacros)
else()
    set(THIRDPARTY_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/../thirdparty)
endif()

if(NOT DEFINED SOLO_BUILD_DEPS)
    # [option] SOLO_BUILD_DEPS (default: ON)
    # Download and build missing dependencies, throw error if disabled.
    set(SOLO_BUILD_DEPS_OPTION_STR "Automatically download and build unmet dependencies")
    option(SOLO_BUILD_DEPS ${SOLO_BUILD_DEPS_OPTION_STR} ON)
endif()

# if SOLO_BUILD_BENCH is ON, use GoogleBenchmark
if(SOLO_BUILD_BENCH)
    find_package(benchmark QUIET CONFIG)
    if(benchmark_FOUND)
        message(STATUS "GoogleBenchmark: found")
    else()
        if(SOLO_BUILD_DEPS)
            message(STATUS "GoogleBenchmark: download ...")
            solo_fetch_thirdparty_content(ExternalBenchmark)
        else()
            message(FATAL_ERROR "GoogleBenchmark: not found, please download and install manually")
        endif()
    endif()

    # Add source files to bench
    set(SOLO_BENCH_FILES "")
    # Test files in this directory
    set(SOLO_BENCH_FILES ${SOLO_BENCH_FILES}
        ${CMAKE_CURRENT_LIST_DIR}/bench.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ec_openssl_bench.cpp
        ${CMAKE_CURRENT_LIST_DIR}/hash_bench.cpp
        ${CMAKE_CURRENT_LIST_DIR}/prng_bench.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sampling_bench.cpp
    )

    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -ldl -lrt")
    add_executable(solo_bench ${SOLO_BENCH_FILES})

    if(TARGET PETAce-Solo::solo)
        target_link_libraries(solo_bench PRIVATE PETAce-Solo::solo benchmark::benchmark)
    elseif(TARGET PETAce-Solo::solo_shared)
        target_link_libraries(solo_bench PRIVATE PETAce-Solo::solo_shared benchmark::benchmark)
    else()
        message(FATAL_ERROR "Cannot find target PETAce-Solo::solo or PETAce-Solo::solo_shared")
    endif()
endif()
