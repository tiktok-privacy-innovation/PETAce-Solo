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

# Source files in this directory
set(SOLO_SOURCE_FILES ${SOLO_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/ahe_paillier.cpp
    ${CMAKE_CURRENT_LIST_DIR}/cuckoo_hashing.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ec_openssl.cpp
    ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
    ${CMAKE_CURRENT_LIST_DIR}/prng.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sampling.cpp
    ${CMAKE_CURRENT_LIST_DIR}/simple_hashing.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/ahe_paillier.h
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo_hashing.h
        ${CMAKE_CURRENT_LIST_DIR}/ec_openssl.h
        ${CMAKE_CURRENT_LIST_DIR}/hash.h
        ${CMAKE_CURRENT_LIST_DIR}/prng.h
        ${CMAKE_CURRENT_LIST_DIR}/sampling.h
        ${CMAKE_CURRENT_LIST_DIR}/simple_hashing.h
        ${CMAKE_CURRENT_LIST_DIR}/solo.h
    DESTINATION
        ${SOLO_INCLUDES_INSTALL_DIR}/solo
)

add_subdirectory(util)

set(SOLO_SOURCE_FILES ${SOLO_SOURCE_FILES} PARENT_SCOPE)
