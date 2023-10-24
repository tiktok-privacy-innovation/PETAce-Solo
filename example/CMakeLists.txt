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

project(SOLOExample VERSION 0.2.0 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SOLO_BUILD_EXAMPLE)
    set(SOLO_BUILD_EXAMPLE ON)

    # Import PETAce-Solo
    find_package(PETAce-Solo 0.2.0 EXACT REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SOLO_BUILD_EXAMPLE)
    # Add source files to example
    set(SOLO_EXAMPLE_FILES "")
    # Test files in this directory
    set(SOLO_EXAMPLE_FILES ${SOLO_EXAMPLE_FILES}
        ${CMAKE_CURRENT_LIST_DIR}/example.cpp
    )

    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -ldl -lrt")

    add_executable(solo_example ${SOLO_EXAMPLE_FILES})

    if(TARGET PETAce-Solo::solo)
        target_link_libraries(solo_example PRIVATE PETAce-Solo::solo)
    elseif(TARGET PETAce-Solo::solo_shared)
        target_link_libraries(solo_example PRIVATE PETAce-Solo::solo_shared)
    else()
        message(FATAL_ERROR "Cannot find target PETAce-Solo::solo or PETAce-Solo::solo_shared")
    endif()
endif()
