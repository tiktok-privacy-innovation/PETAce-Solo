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

project(SOLOTest VERSION 0.2.0 LANGUAGES CXX C)

# If not called from root CMakeLists.txt
if(NOT DEFINED SOLO_BUILD_TEST)
    set(SOLO_BUILD_TEST ON)

    find_package(PETAce-Solo 0.2.0 EXACT REQUIRED)

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

# if SOLO_BUILD_TEST is ON, use GoogleTest
if(SOLO_BUILD_TEST)
    find_package(GTest 1 CONFIG)
    if(GTest_FOUND)
        message(STATUS "GoogleTest: found")
    else()
        if(SOLO_BUILD_DEPS)
            message(STATUS "GoogleTest: download ...")
            solo_fetch_thirdparty_content(ExternalGTest)
            add_library(GTest::gtest ALIAS gtest)
        else()
            message(FATAL_ERROR "GoogleTest: not found, please download and install manually")
        endif()
    endif()

    # Add source files to test
    set(SOLO_TEST_FILES
        ${CMAKE_CURRENT_LIST_DIR}/ec_openssl_test.cpp
        ${CMAKE_CURRENT_LIST_DIR}/hash_test.cpp
        ${CMAKE_CURRENT_LIST_DIR}/prng_test.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sampling_test.cpp
        ${CMAKE_CURRENT_LIST_DIR}/simple_hashing_test.cpp
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo_hashing_test.cpp
        ${CMAKE_CURRENT_LIST_DIR}/hash_table_entry_test.cpp
        ${CMAKE_CURRENT_LIST_DIR}/test_runner.cpp
    )
    if(SOLO_USE_IPCL)
        set(SOLO_TEST_FILES ${SOLO_TEST_FILES}
            ${CMAKE_CURRENT_LIST_DIR}/ahe_paillier_test.cpp
        )
    endif()

    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -ldl -lrt")

    add_executable(solo_test ${SOLO_TEST_FILES})

    if(TARGET PETAce-Solo::solo)
        target_link_libraries(solo_test PRIVATE PETAce-Solo::solo GTest::gtest)
    elseif(TARGET PETAce-Solo::solo_shared)
        target_link_libraries(solo_test PRIVATE PETAce-Solo::solo_shared GTest::gtest)
    else()
        message(FATAL_ERROR "Cannot find target PETAce-Solo::solo or PETAce-Solo::solo_shared")
    endif()

    # In Debug mode, enable AddressSanitizer (and LeakSanitizer) on Unix-like platforms.
    if(SOLO_DEBUG AND UNIX)
        # On macOS, only AddressSanitizer is enabled.
        # On Linux, LeakSanitizer is enabled by default.
        target_compile_options(solo_test PUBLIC -fsanitize=address)
        target_link_options(solo_test PUBLIC -fsanitize=address)
        if(NOT APPLE)
            message(STATUS "Sanitizers enabled: address, leak")
        else()
            message(STATUS "Sanitizers enabled: address")
        endif()
    endif()

    add_custom_target(test_report
        COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/solo_test --gtest_output="xml:${CMAKE_CURRENT_BINARY_DIR}/../report/solo_test.xml"
        DEPENDS solo_test)
endif()
