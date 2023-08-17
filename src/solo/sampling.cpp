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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expouts or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "solo/sampling.h"

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

#include "solo/prng.h"
#include "solo/util/defines.h"

namespace petace {
namespace solo {

SOLO_NODISCARD Byte sample_uniform_byte(petace::solo::PRNG& prng) noexcept {
    Byte out;
    prng.generate(sizeof(out), &out);
    return out;
}

SOLO_NODISCARD std::uint32_t sample_uniform_uint32(petace::solo::PRNG& prng) noexcept {
    std::uint32_t out;
    prng.generate(sizeof(out), reinterpret_cast<Byte*>(&out));
    return out;
}

SOLO_NODISCARD std::uint64_t sample_uniform_uint64(petace::solo::PRNG& prng) noexcept {
    std::uint64_t out;
    prng.generate(sizeof(out), reinterpret_cast<Byte*>(&out));
    return out;
}

void sample_uniform_byte_array(petace::solo::PRNG& prng, std::size_t byte_count, Byte* out) {
    if (out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    prng.generate(byte_count, out);
}

void sample_uniform_uint32_array(petace::solo::PRNG& prng, std::size_t uint32_count, std::uint32_t* out) {
    if (out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    prng.generate(uint32_count * sizeof(std::uint32_t), reinterpret_cast<Byte*>(out));
}

void sample_uniform_uint64_array(petace::solo::PRNG& prng, std::size_t uint64_count, std::uint64_t* out) {
    if (out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    prng.generate(uint64_count * sizeof(std::uint64_t), reinterpret_cast<Byte*>(out));
}

}  // namespace solo
}  // namespace petace
