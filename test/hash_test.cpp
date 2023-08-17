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

#include "solo/hash.h"

#include "gtest/gtest.h"

TEST(HashTest, Hash) {
    petace::solo::Byte input[64];
    for (std::size_t i = 0; i < 64; i++) {
        input[i] = static_cast<petace::solo::Byte>(i);
    }
    {
        auto hash = petace::solo::Hash::create(petace::solo::HashScheme::SHA_256);
        std::vector<petace::solo::Byte> block(hash->hash_byte_count());
        EXPECT_NO_THROW(hash->compute(nullptr, 0, nullptr, 0));
        ASSERT_THROW(hash->compute(nullptr, 64, block.data(), block.size()), std::invalid_argument);
        ASSERT_THROW(hash->compute(input, 64, nullptr, block.size()), std::invalid_argument);
        ASSERT_THROW(hash->compute(input, 64, std::vector<petace::solo::Byte>(hash->hash_byte_count() + 1).data(),
                             hash->hash_byte_count() + 1),
                std::invalid_argument);
        hash->compute(input, 64, block.data(), block.size());
        std::vector<petace::solo::Byte> check(hash->hash_byte_count());
        hash->compute(input, 64, check.data(), check.size());
        ASSERT_EQ(block, check);
        ASSERT_NE(petace::solo::HashSHA_256::create(), nullptr);
        petace::solo::HashFactorySHA_256 hash_factory;
        ASSERT_NE(hash_factory.create(), nullptr);
    }
    {
        auto hash = petace::solo::Hash::create(petace::solo::HashScheme::SHA3_256);
        std::vector<petace::solo::Byte> block(hash->hash_byte_count());
        EXPECT_NO_THROW(hash->compute(nullptr, 0, nullptr, 0));
        ASSERT_THROW(hash->compute(nullptr, 64, block.data(), block.size()), std::invalid_argument);
        ASSERT_THROW(hash->compute(input, 64, nullptr, block.size()), std::invalid_argument);
        ASSERT_THROW(hash->compute(input, 64, std::vector<petace::solo::Byte>(hash->hash_byte_count() + 1).data(),
                             hash->hash_byte_count() + 1),
                std::invalid_argument);
        hash->compute(input, 64, block.data(), block.size());
        std::vector<petace::solo::Byte> check(hash->hash_byte_count());
        hash->compute(input, 64, check.data(), check.size());
        ASSERT_EQ(block, check);
        ASSERT_NE(petace::solo::HashSHA3_256::create(), nullptr);
        petace::solo::HashFactorySHA3_256 hash_factory;
        ASSERT_NE(hash_factory.create(), nullptr);
    }
    {
        auto hash = petace::solo::Hash::create(petace::solo::HashScheme::BLAKE2b);
        std::vector<petace::solo::Byte> block(hash->hash_byte_count());
        EXPECT_NO_THROW(hash->compute(nullptr, 0, nullptr, 0));
        ASSERT_THROW(hash->compute(nullptr, 64, block.data(), block.size()), std::invalid_argument);
        ASSERT_THROW(hash->compute(input, 64, nullptr, block.size()), std::invalid_argument);
        ASSERT_THROW(hash->compute(input, 64, std::vector<petace::solo::Byte>(hash->hash_byte_count() + 1).data(),
                             hash->hash_byte_count() + 1),
                std::invalid_argument);
        hash->compute(input, 64, block.data(), block.size());
        std::vector<petace::solo::Byte> check(hash->hash_byte_count());
        hash->compute(input, 64, check.data(), check.size());
        ASSERT_EQ(block, check);
        ASSERT_NE(petace::solo::HashBLAKE2b::create(), nullptr);
        petace::solo::HashFactoryBLAKE2b hash_factory;
        ASSERT_NE(hash_factory.create(), nullptr);
    }
}
