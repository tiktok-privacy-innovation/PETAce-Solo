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

#include "solo/simple_hashing.h"

#include <cmath>

#include <array>

#include "gtest/gtest.h"

TEST(SimpleHashingTest, Constructor) {
    std::vector<petace::solo::Byte> seed(16, petace::solo::Byte(0));
    std::vector<petace::solo::Byte> seed_invalid(8, petace::solo::Byte(0));
    {
        petace::solo::SimpleHashing<8>(std::size_t(1 << 16));
        petace::solo::SimpleHashing<8>(std::size_t(1 << 16), seed);
        ASSERT_THROW(petace::solo::SimpleHashing<8>(std::size_t(1 << 16), seed_invalid), std::invalid_argument);
    }
    {
        petace::solo::SimpleHashing<16>(std::size_t(1 << 16));
        petace::solo::SimpleHashing<16>(std::size_t(1 << 16), seed);
        ASSERT_THROW(petace::solo::SimpleHashing<16>(std::size_t(1 << 16), seed_invalid), std::invalid_argument);
    }
}

TEST(SimpleHashingTest, Default) {
    petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::SHAKE_128);
    auto prng = prng_factory.create();
    std::vector<petace::solo::Byte> seed(16, petace::solo::Byte(0));
    {
        double epsilon = 1.27f;
        std::vector<std::array<petace::solo::Byte, 8>> elements(1024);
        std::for_each(elements.begin(), elements.end(),
                [&prng](std::array<petace::solo::Byte, 8>& element) { prng->generate(8, element.data()); });
        std::size_t num_of_bins = static_cast<std::size_t>(std::ceil(1024 * epsilon));
        petace::solo::SimpleHashing<8> simple_hash(num_of_bins, seed);
        simple_hash.insert(elements);
        simple_hash.set_num_of_hash_functions(3);
        simple_hash.map_elements();
        simple_hash.set_maximum_bin_size(simple_hash.get_max_observed_bin_size());
        ASSERT_EQ(simple_hash.obtain_entry_values().size(), 3 * 1024);
        ASSERT_EQ(
                simple_hash.obtain_entry_values_padded().size(), simple_hash.get_max_observed_bin_size() * num_of_bins);
        ASSERT_EQ(simple_hash.obtain_bin_entry_values().size(), num_of_bins);
        ASSERT_EQ(simple_hash.obtain_bin_entry_ids().size(), num_of_bins);
        ASSERT_EQ(simple_hash.obtain_bin_entry_function_ids().size(), num_of_bins);
        auto num_of_elements_in_bins = simple_hash.get_num_of_elements_in_bins();
        std::size_t sum_elements = 0;
        std::for_each(num_of_elements_in_bins.begin(), num_of_elements_in_bins.end(),
                [&sum_elements](std::size_t n) { sum_elements += n; });
        ASSERT_EQ(sum_elements, 3 * 1024);
        simple_hash.insert(elements[0]);
    }
    {
        double epsilon = 1.27f;
        std::vector<std::array<petace::solo::Byte, 16>> elements(1024);
        std::for_each(elements.begin(), elements.end(),
                [&prng](std::array<petace::solo::Byte, 16>& element) { prng->generate(16, element.data()); });
        std::size_t num_of_bins = static_cast<std::size_t>(std::ceil(1024 * epsilon));
        petace::solo::SimpleHashing<16> simple_hash(num_of_bins, seed);
        simple_hash.insert(elements);
        simple_hash.set_num_of_hash_functions(3);
        simple_hash.map_elements();
        simple_hash.set_maximum_bin_size(simple_hash.get_max_observed_bin_size());
        ASSERT_EQ(simple_hash.obtain_entry_values().size(), 3 * 1024);
        ASSERT_EQ(
                simple_hash.obtain_entry_values_padded().size(), simple_hash.get_max_observed_bin_size() * num_of_bins);
        ASSERT_EQ(simple_hash.obtain_bin_entry_values().size(), num_of_bins);
        ASSERT_EQ(simple_hash.obtain_bin_entry_ids().size(), num_of_bins);
        ASSERT_EQ(simple_hash.obtain_bin_entry_function_ids().size(), num_of_bins);
        auto num_of_elements_in_bins = simple_hash.get_num_of_elements_in_bins();
        std::size_t sum_elements = 0;
        std::for_each(num_of_elements_in_bins.begin(), num_of_elements_in_bins.end(),
                [&sum_elements](std::size_t n) { sum_elements += n; });
        ASSERT_EQ(sum_elements, 3 * 1024);
        simple_hash.insert(elements[0]);
    }
    {
        double epsilon = 1.27f;
        std::vector<std::array<petace::solo::Byte, 8>> elements(1024);
        std::for_each(elements.begin(), elements.end(),
                [&prng](std::array<petace::solo::Byte, 8>& element) { prng->generate(8, element.data()); });
        std::size_t num_of_bins = static_cast<std::size_t>(std::ceil(1024 * epsilon));
        petace::solo::SimpleHashing<8> simple_hash(num_of_bins, seed);
        simple_hash.insert(elements);
        simple_hash.set_num_of_hash_functions(3);
        simple_hash.map_elements();
        simple_hash.set_maximum_bin_size(simple_hash.get_max_observed_bin_size());
        ASSERT_EQ(simple_hash.obtain_entry_values().size(), 3 * 1024);
        ASSERT_EQ(
                simple_hash.obtain_entry_values_padded().size(), simple_hash.get_max_observed_bin_size() * num_of_bins);
        ASSERT_EQ(simple_hash.obtain_bin_entry_values().size(), num_of_bins);
        ASSERT_EQ(simple_hash.obtain_bin_entry_ids().size(), num_of_bins);
        ASSERT_EQ(simple_hash.obtain_bin_entry_function_ids().size(), num_of_bins);
        auto num_of_elements_in_bins = simple_hash.get_num_of_elements_in_bins();
        std::size_t sum_elements = 0;
        std::for_each(num_of_elements_in_bins.begin(), num_of_elements_in_bins.end(),
                [&sum_elements](std::size_t n) { sum_elements += n; });
        ASSERT_EQ(sum_elements, 3 * 1024);
        simple_hash.insert(elements[0]);
    }
}
