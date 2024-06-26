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

#include "solo/prng.h"

#include "gtest/gtest.h"

TEST(PRNGTest, PRNG) {
    std::size_t seed_byte_count = 16;
    std::vector<petace::solo::Byte> seed(seed_byte_count, petace::solo::Byte(7));
    {
        EXPECT_NO_THROW(petace::solo::PRNG::get_random_byte_array(0, nullptr));
        ASSERT_THROW(petace::solo::PRNG::get_random_byte_array(seed_byte_count, nullptr), std::invalid_argument);
        EXPECT_NO_THROW(petace::solo::PRNG::get_random_byte_array(
                seed_byte_count, std::vector<petace::solo::Byte>(seed_byte_count).data()));
        EXPECT_NO_THROW(petace::solo::PRNG::get_random_byte_array(
                seed_byte_count + 1, std::vector<petace::solo::Byte>(seed_byte_count + 1).data()));
    }
    {
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::BLAKE2Xb>(std::size_t(0)), std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::BLAKE2Xb>(seed_byte_count, std::size_t(0)),
                std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::BLAKE2Xb>(
                             std::vector<petace::solo::Byte>(std::size_t(0)), std::size_t(0)),
                std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::BLAKE2Xb>(seed, std::size_t(0)),
                std::invalid_argument);
    }
    {
        petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::BLAKE2Xb, seed_byte_count);
        ASSERT_THROW(auto test_prng = prng_factory.create(std::size_t(0)), std::invalid_argument);
        EXPECT_NO_THROW(auto test_prng = prng_factory.create());
        std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create(seed);
        std::vector<petace::solo::Byte> output(8);
        ASSERT_THROW(prng->generate(output.size(), nullptr), std::invalid_argument);
        prng->generate(output.size(), output.data());

        std::shared_ptr<petace::solo::PRNG> prng_other = prng_factory.create(seed);
        std::vector<petace::solo::Byte> output_other(8);
        prng_other->generate(output_other.size(), output_other.data());

        for (std::size_t i = 0; i < 8; i++) {
            ASSERT_EQ(output[i], output_other[i]);
        }
    }
    {
        ASSERT_THROW(petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb, 0), std::invalid_argument);
        petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::BLAKE2Xb, seed_byte_count + 1);
        ASSERT_THROW(std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create(seed), std::invalid_argument);
    }
#ifdef SOLO_DEBUG
    {
        ASSERT_THROW(petace::solo::PRNGFactory prng_factory(
                             petace::solo::PRNGScheme::BLAKE2Xb, std::vector<petace::solo::Byte>(std::size_t(0))),
                std::invalid_argument);
        petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::BLAKE2Xb, seed);
        auto prng = prng_factory.create();
        ASSERT_EQ(prng->seed(), seed);
    }
#endif
    {
        ASSERT_THROW(
                petace::solo::PRNGImpl<petace::solo::PRNGScheme::SHAKE_128>(std::size_t(0)), std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::SHAKE_128>(seed_byte_count, std::size_t(0)),
                std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::SHAKE_128>(
                             std::vector<petace::solo::Byte>(std::size_t(0)), std::size_t(0)),
                std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::SHAKE_128>(seed, std::size_t(0)),
                std::invalid_argument);
    }
    {
        petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::SHAKE_128, seed_byte_count);
        ASSERT_THROW(auto test_prng = prng_factory.create(std::size_t(0)), std::invalid_argument);
        EXPECT_NO_THROW(auto test_prng = prng_factory.create());
        std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create(seed);
        std::vector<petace::solo::Byte> output(8);
        ASSERT_THROW(prng->generate(output.size(), nullptr), std::invalid_argument);
        prng->generate(output.size(), output.data());

        std::shared_ptr<petace::solo::PRNG> prng_other = prng_factory.create(seed);
        std::vector<petace::solo::Byte> output_other(8);
        prng_other->generate(output_other.size(), output_other.data());

        for (std::size_t i = 0; i < 8; i++) {
            ASSERT_EQ(output[i], output_other[i]);
        }
    }
    {
        ASSERT_THROW(petace::solo::PRNGFactory(petace::solo::PRNGScheme::SHAKE_128, 0), std::invalid_argument);
        petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::SHAKE_128, seed_byte_count + 1);
        ASSERT_THROW(std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create(seed), std::invalid_argument);
    }
#ifdef SOLO_DEBUG
    {
        ASSERT_THROW(petace::solo::PRNGFactory prng_factory(
                             petace::solo::PRNGScheme::SHAKE_128, std::vector<petace::solo::Byte>(std::size_t(0))),
                std::invalid_argument);
        petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::SHAKE_128, seed);
        auto prng = prng_factory.create();
        ASSERT_EQ(prng->seed(), seed);
    }
#endif
#ifdef SOLO_USE_AES_INTRIN
    {
        ASSERT_THROW(
                petace::solo::PRNGImpl<petace::solo::PRNGScheme::AES_ECB_CTR>(std::size_t(0)), std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::AES_ECB_CTR>(seed_byte_count, std::size_t(0)),
                std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::AES_ECB_CTR>(
                             std::vector<petace::solo::Byte>(std::size_t(0)), std::size_t(0)),
                std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGImpl<petace::solo::PRNGScheme::AES_ECB_CTR>(seed, std::size_t(0)),
                std::invalid_argument);
    }
    {
        petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::AES_ECB_CTR, seed_byte_count);
        ASSERT_THROW(auto test_prng = prng_factory.create(std::size_t(0)), std::invalid_argument);
        EXPECT_NO_THROW(auto test_prng = prng_factory.create());
        std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create(seed);
        std::vector<petace::solo::Byte> output(8);
        ASSERT_THROW(prng->generate(output.size(), nullptr), std::invalid_argument);
        prng->generate(output.size(), output.data());

        std::shared_ptr<petace::solo::PRNG> prng_other = prng_factory.create(seed);
        std::vector<petace::solo::Byte> output_other(8);
        prng_other->generate(output_other.size(), output_other.data());

        for (std::size_t i = 0; i < 8; i++) {
            ASSERT_EQ(output[i], output_other[i]);
        }
    }
    {
        ASSERT_THROW(petace::solo::PRNGFactory(petace::solo::PRNGScheme::AES_ECB_CTR, 0), std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::AES_ECB_CTR, seed_byte_count + 1),
                std::invalid_argument);
    }
#ifdef SOLO_DEBUG
    {
        ASSERT_THROW(petace::solo::PRNGFactory prng_factory(
                             petace::solo::PRNGScheme::AES_ECB_CTR, std::vector<petace::solo::Byte>(std::size_t(0))),
                std::invalid_argument);
        ASSERT_THROW(petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::AES_ECB_CTR,
                             std::vector<petace::solo::Byte>(std::size_t(seed_byte_count + 1))),
                std::invalid_argument);
        petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::AES_ECB_CTR, seed);
        auto prng = prng_factory.create();
        ASSERT_EQ(prng->seed(), seed);
    }
#endif
#endif
}
