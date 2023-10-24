// Copyright 2023 TikTok Pte. Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "solo/util/config.h"

// Use std::byte as byte type
#ifdef SOLO_USE_STD_BYTE
#include <cstddef>
namespace petace {
namespace solo {
using Byte = std::byte;
}  // namespace solo
}  // namespace petace
#else
namespace petace {
namespace solo {
enum class Byte : unsigned char {};

constexpr Byte operator|(Byte l, Byte r) noexcept {
    return static_cast<Byte>(static_cast<unsigned char>(l) | static_cast<unsigned char>(r));
}

constexpr Byte operator^(Byte l, Byte r) noexcept {
    return static_cast<Byte>(static_cast<unsigned char>(l) ^ static_cast<unsigned char>(r));
}

constexpr Byte operator&(Byte l, Byte r) noexcept {
    return static_cast<Byte>(static_cast<unsigned char>(l) & static_cast<unsigned char>(r));
}

constexpr Byte& operator|=(Byte& l, Byte r) noexcept {
    l = l | r;
    return l;
}

constexpr Byte& operator^=(Byte& l, Byte r) noexcept {
    l = l ^ r;
    return l;
}

constexpr Byte& operator&=(Byte& l, Byte r) noexcept {
    l = l & r;
    return l;
}
}  // namespace solo
}  // namespace petace
#endif

// Use [[nodiscard]] from C++17
#ifdef SOLO_USE_NODISCARD
#define SOLO_NODISCARD [[nodiscard]]
#else
#define SOLO_NODISCARD
#endif
