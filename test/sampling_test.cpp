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

#include "solo/sampling.h"

#include "gtest/gtest.h"

#include "solo/prng.h"

TEST(SamplingTest, Uniform) {
    std::size_t seed_byte_count = 64;
    std::vector<petace::solo::Byte> seed(seed_byte_count, petace::solo::Byte(7));
    petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::SHAKE_128, seed_byte_count);
    std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create(seed);
    {
        petace::solo::Byte rand_byte = petace::solo::sample_uniform_byte(*prng);
        ASSERT_EQ(rand_byte, petace::solo::Byte(0x4F));
        std::uint32_t rand_uint32 = petace::solo::sample_uniform_uint32(*prng);
        ASSERT_EQ(rand_uint32, std::uint32_t(4026420270));
        std::uint64_t rand_uint64 = petace::solo::sample_uniform_uint64(*prng);
        ASSERT_EQ(rand_uint64, std::uint64_t(3930362238982664675));
    }
    {
        petace::solo::Byte rand_byte[1];
        petace::solo::sample_uniform_byte_array(*prng, std::size_t(1), rand_byte);
        ASSERT_EQ(rand_byte[0], petace::solo::Byte(0x0B));
        std::uint32_t rand_uint32[1];
        petace::solo::sample_uniform_uint32_array(*prng, std::size_t(1), rand_uint32);
        ASSERT_EQ(rand_uint32[0], std::uint32_t(2044260689));
        std::uint64_t rand_uint64[1];
        petace::solo::sample_uniform_uint64_array(*prng, std::size_t(1), rand_uint64);
        ASSERT_EQ(rand_uint64[0], std::uint64_t(16049053167049065388ULL));
    }
    {
        ASSERT_THROW(petace::solo::sample_uniform_byte_array(*prng, std::size_t(1), nullptr), std::invalid_argument);
        ASSERT_THROW(petace::solo::sample_uniform_uint32_array(*prng, std::size_t(1), nullptr), std::invalid_argument);
        ASSERT_THROW(petace::solo::sample_uniform_uint64_array(*prng, std::size_t(1), nullptr), std::invalid_argument);
    }
}
