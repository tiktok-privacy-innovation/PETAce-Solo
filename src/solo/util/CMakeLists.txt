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
    ${CMAKE_CURRENT_LIST_DIR}/blake2b-ref.c
    ${CMAKE_CURRENT_LIST_DIR}/blake2xb-ref.c
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/blake2.h
        ${CMAKE_CURRENT_LIST_DIR}/blake2-impl.h
        ${CMAKE_CURRENT_LIST_DIR}/defines.h
    DESTINATION
        ${SOLO_INCLUDES_INSTALL_DIR}/solo/util
)

if (SOLO_USE_AES_INTRIN)
    set(SOLO_SOURCE_FILES ${SOLO_SOURCE_FILES}
        ${CMAKE_CURRENT_LIST_DIR}/aes_ecb_ctr.cpp
    )
    install(
        FILES
            ${CMAKE_CURRENT_LIST_DIR}/aes_ecb_ctr.h
        DESTINATION
            ${SOLO_INCLUDES_INSTALL_DIR}/solo/util
    )
endif()

set(SOLO_SOURCE_FILES ${SOLO_SOURCE_FILES} PARENT_SCOPE)
