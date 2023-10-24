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

#include "solo/cuckoo_hashing.h"

#include <cmath>

#include <array>

#include "gtest/gtest.h"

TEST(CuckooHashingTest, Constructor) {
    std::vector<petace::solo::Byte> seed(16, petace::solo::Byte(0));
    std::vector<petace::solo::Byte> seed_invalid(8, petace::solo::Byte(0));
    {
        petace::solo::CuckooHashing<8>(std::size_t(1 << 16));
        petace::solo::CuckooHashing<8>(std::size_t(1 << 16), seed);
        ASSERT_THROW(petace::solo::CuckooHashing<8>(std::size_t(1 << 16), seed_invalid), std::invalid_argument);
    }
    {
        petace::solo::CuckooHashing<16>(std::size_t(1 << 16));
        petace::solo::CuckooHashing<16>(std::size_t(1 << 16), seed);
        ASSERT_THROW(petace::solo::CuckooHashing<16>(std::size_t(1 << 16), seed_invalid), std::invalid_argument);
    }
}

TEST(CuckooHashingTest, Default) {
    petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::SHAKE_128);
    auto prng = prng_factory.create();
    std::vector<petace::solo::Byte> seed(16, petace::solo::Byte(0));
    {
        double epsilon = 1.27f;
        std::vector<std::array<petace::solo::Byte, 8>> elements(1024);
        std::for_each(elements.begin(), elements.end(),
                [&prng](std::array<petace::solo::Byte, 8>& element) { prng->generate(8, element.data()); });
        std::size_t num_of_bins = static_cast<std::size_t>(std::ceil(1024 * epsilon));
        petace::solo::CuckooHashing<8> cuckoo_hash(num_of_bins, seed);
        cuckoo_hash.insert(elements);
        cuckoo_hash.set_num_of_hash_functions(3);
        cuckoo_hash.set_recursive_insertion_limiter(200);
        cuckoo_hash.map_elements();
        ASSERT_EQ(cuckoo_hash.obtain_entry_values().size(), num_of_bins);
        ASSERT_EQ(cuckoo_hash.obtain_entry_source_values().size(), num_of_bins);
        ASSERT_EQ(cuckoo_hash.obtain_entry_ids().size(), num_of_bins);
        ASSERT_EQ(cuckoo_hash.obtain_entry_function_ids().size(), num_of_bins);

        auto bin_occupancy = cuckoo_hash.obtain_bin_occupancy();
        auto bin_occupancy_sum = std::count_if(bin_occupancy.begin(), bin_occupancy.end(), [](bool a) { return a; });
        ASSERT_EQ(bin_occupancy_sum, 1024);

        std::vector<std::size_t> num_elements_in_bins = cuckoo_hash.get_num_of_elements_in_bins();
        std::size_t num_elements_sum = 0;
        std::for_each(num_elements_in_bins.begin(), num_elements_in_bins.end(),
                [&num_elements_sum](std::size_t i) { num_elements_sum += i; });
        ASSERT_EQ(num_elements_sum, 1024);

        ASSERT_EQ(cuckoo_hash.get_stash_size(), 0);
        cuckoo_hash.insert(elements[0]);
    }
    {
        double epsilon = 1.27f;
        std::vector<std::array<petace::solo::Byte, 8>> elements(1024);
        std::for_each(elements.begin(), elements.end(),
                [&prng](std::array<petace::solo::Byte, 8>& element) { prng->generate(8, element.data()); });
        std::size_t num_of_bins = static_cast<std::size_t>(std::ceil(1024 * epsilon));
        petace::solo::CuckooHashing<8> cuckoo_hash(num_of_bins, seed);
        cuckoo_hash.insert(elements);
        cuckoo_hash.set_num_of_hash_functions(3);
        auto element_addresses = cuckoo_hash.get_element_addresses();
        ASSERT_EQ(element_addresses.size(), 1024 * 3);
    }
    {
        double epsilon = 1.27f;
        std::vector<std::array<petace::solo::Byte, 16>> elements(1024);
        std::for_each(elements.begin(), elements.end(),
                [&prng](std::array<petace::solo::Byte, 16>& element) { prng->generate(16, element.data()); });
        std::size_t num_of_bins = static_cast<std::size_t>(std::ceil(1024 * epsilon));
        petace::solo::CuckooHashing<16> cuckoo_hash(num_of_bins, seed);
        cuckoo_hash.insert(elements);
        cuckoo_hash.set_num_of_hash_functions(3);
        cuckoo_hash.set_recursive_insertion_limiter(200);
        cuckoo_hash.map_elements();
        ASSERT_EQ(cuckoo_hash.obtain_entry_values().size(), num_of_bins);
        ASSERT_EQ(cuckoo_hash.obtain_entry_source_values().size(), num_of_bins);
        ASSERT_EQ(cuckoo_hash.obtain_entry_ids().size(), num_of_bins);
        ASSERT_EQ(cuckoo_hash.obtain_entry_function_ids().size(), num_of_bins);

        auto bin_occupancy = cuckoo_hash.obtain_bin_occupancy();
        auto bin_occupancy_sum = std::count_if(bin_occupancy.begin(), bin_occupancy.end(), [](bool a) { return a; });
        ASSERT_EQ(bin_occupancy_sum, 1024);

        std::vector<std::size_t> num_elements_in_bins = cuckoo_hash.get_num_of_elements_in_bins();
        std::size_t num_elements_sum = 0;
        std::for_each(num_elements_in_bins.begin(), num_elements_in_bins.end(),
                [&num_elements_sum](std::size_t i) { num_elements_sum += i; });
        ASSERT_EQ(num_elements_sum, 1024);

        ASSERT_EQ(cuckoo_hash.get_stash_size(), 0);
        cuckoo_hash.insert(elements[0]);
    }
    {
        double epsilon = 1.27f;
        std::vector<std::array<petace::solo::Byte, 16>> elements(1024);
        std::for_each(elements.begin(), elements.end(),
                [&prng](std::array<petace::solo::Byte, 16>& element) { prng->generate(16, element.data()); });
        std::size_t num_of_bins = static_cast<std::size_t>(std::ceil(1024 * epsilon));
        petace::solo::CuckooHashing<16> cuckoo_hash(num_of_bins, seed);
        cuckoo_hash.insert(elements);
        cuckoo_hash.set_num_of_hash_functions(3);
        auto element_addresses = cuckoo_hash.get_element_addresses();
        ASSERT_EQ(element_addresses.size(), 1024 * 3);
    }
    {
        double epsilon = 1.27f;
        std::vector<std::array<petace::solo::Byte, 8>> elements(1024);
        std::for_each(elements.begin(), elements.end(),
                [&prng](std::array<petace::solo::Byte, 8>& element) { prng->generate(8, element.data()); });
        std::size_t num_of_bins = static_cast<std::size_t>(std::ceil(1024 * epsilon));
        petace::solo::CuckooHashing<8> cuckoo_hash(num_of_bins, seed);
        cuckoo_hash.insert(elements);
        cuckoo_hash.set_num_of_hash_functions(3);
        cuckoo_hash.set_recursive_insertion_limiter(200);
        cuckoo_hash.map_elements();
        ASSERT_EQ(cuckoo_hash.obtain_entry_values().size(), num_of_bins);
        ASSERT_EQ(cuckoo_hash.obtain_entry_source_values().size(), num_of_bins);
        ASSERT_EQ(cuckoo_hash.obtain_entry_ids().size(), num_of_bins);
        ASSERT_EQ(cuckoo_hash.obtain_entry_function_ids().size(), num_of_bins);

        auto bin_occupancy = cuckoo_hash.obtain_bin_occupancy();
        auto bin_occupancy_sum = std::count_if(bin_occupancy.begin(), bin_occupancy.end(), [](bool a) { return a; });
        ASSERT_EQ(bin_occupancy_sum, 1024);

        std::vector<std::size_t> num_elements_in_bins = cuckoo_hash.get_num_of_elements_in_bins();
        std::size_t num_elements_sum = 0;
        std::for_each(num_elements_in_bins.begin(), num_elements_in_bins.end(),
                [&num_elements_sum](std::size_t i) { num_elements_sum += i; });
        ASSERT_EQ(num_elements_sum, 1024);

        ASSERT_EQ(cuckoo_hash.get_stash_size(), 0);
        cuckoo_hash.insert(elements[0]);
    }
}
