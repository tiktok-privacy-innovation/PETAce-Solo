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

#include "solo/util/hash_table_entry.h"

#include <array>

#include "gtest/gtest.h"

TEST(HashTableEntryTest, Constructor) {
    {
        petace::solo::util::HashTableEntry<8> hash_table_entry;
        ASSERT_EQ(hash_table_entry.get_global_id(), petace::solo::util::kHashTableDummyElement);
        std::array<petace::solo::Byte, 8> dummy_value;
        std::fill_n(dummy_value.begin(), 8, petace::solo::Byte(0xFF));
        ASSERT_EQ(hash_table_entry.get_element(), dummy_value);
    }
    {
        petace::solo::util::HashTableEntry<16> hash_table_entry;
        ASSERT_EQ(hash_table_entry.get_global_id(), petace::solo::util::kHashTableDummyElement);
        std::array<petace::solo::Byte, 16> dummy_value;
        std::fill_n(dummy_value.begin(), 16, petace::solo::Byte(0xFF));
        ASSERT_EQ(hash_table_entry.get_element(), dummy_value);
    }
    {
        petace::solo::util::HashTableEntry<8> hash_table_entry;
        petace::solo::util::HashTableEntry<8> hash_table_entry_copy(hash_table_entry);
        ASSERT_EQ(hash_table_entry_copy.get_global_id(), petace::solo::util::kHashTableDummyElement);
        std::array<petace::solo::Byte, 8> dummy_value;
        std::fill_n(dummy_value.begin(), 8, petace::solo::Byte(0xFF));
        ASSERT_EQ(hash_table_entry_copy.get_element(), dummy_value);
    }
    {
        petace::solo::util::HashTableEntry<16> hash_table_entry;
        petace::solo::util::HashTableEntry<16> hash_table_entry_copy(hash_table_entry);
        ASSERT_EQ(hash_table_entry_copy.get_global_id(), petace::solo::util::kHashTableDummyElement);
        std::array<petace::solo::Byte, 16> dummy_value;
        std::fill_n(dummy_value.begin(), 16, petace::solo::Byte(0xFF));
        ASSERT_EQ(hash_table_entry_copy.get_element(), dummy_value);
    }
    {
        std::array<petace::solo::Byte, 8> value = {petace::solo::Byte(0), petace::solo::Byte(1)};
        petace::solo::util::HashTableEntry<8> hash_table_entry(value, 1, 3, 10);
        ASSERT_EQ(hash_table_entry.get_global_id(), 1);
        ASSERT_EQ(hash_table_entry.get_element(), value);
    }
    {
        std::array<petace::solo::Byte, 16> value = {petace::solo::Byte(0), petace::solo::Byte(1)};
        petace::solo::util::HashTableEntry<16> hash_table_entry(value, 1, 3, 10);
        ASSERT_EQ(hash_table_entry.get_global_id(), 1);
        ASSERT_EQ(hash_table_entry.get_element(), value);
    }
}

TEST(HashTableEntryTest, Default) {
    {
        std::array<petace::solo::Byte, 8> value = {petace::solo::Byte(0), petace::solo::Byte(1)};
        petace::solo::util::HashTableEntry<8> hash_table_entry(value, 1, 3, 10);
        ASSERT_EQ(hash_table_entry.get_global_id(), 1);
        ASSERT_EQ(hash_table_entry.get_element(), value);
        hash_table_entry.set_current_function_id(0);
        std::vector<std::uint64_t> addresses = {22, 33, 44};
        auto addresses_copy = addresses;
        hash_table_entry.set_possible_addresses(std::move(addresses));
        ASSERT_EQ(hash_table_entry.get_address_at(0), 2);
        ASSERT_EQ(hash_table_entry.get_address_at(1), 3);
        ASSERT_EQ(hash_table_entry.get_address_at(2), 4);
        ASSERT_EQ(hash_table_entry.get_current_function_id(), 0);
        ASSERT_EQ(hash_table_entry.get_current_address(), 2);
        ASSERT_EQ(hash_table_entry.get_possible_addresses(), addresses_copy);
        ASSERT_EQ(hash_table_entry.is_empty(), false);
        hash_table_entry.iterate_function_number();
        ASSERT_EQ(hash_table_entry.get_current_address(), 3);

        std::array<petace::solo::Byte, 8> value_swap = {petace::solo::Byte(1), petace::solo::Byte(0)};
        std::vector<std::uint64_t> addresses_swap = {44, 33, 22};
        auto addresses_swap_copy = addresses_swap;
        petace::solo::util::HashTableEntry<8> hash_table_entry_swap(value_swap, 2, 3, 50);
        hash_table_entry_swap.set_possible_addresses(std::move(addresses_swap));
        petace::solo::util::swap(hash_table_entry, hash_table_entry_swap);
        ASSERT_EQ(hash_table_entry.get_element(), value_swap);
        ASSERT_EQ(hash_table_entry.get_global_id(), 2);
        ASSERT_EQ(hash_table_entry.get_possible_addresses(), addresses_swap_copy);
    }
    {
        std::array<petace::solo::Byte, 16> value = {petace::solo::Byte(0), petace::solo::Byte(1)};
        petace::solo::util::HashTableEntry<16> hash_table_entry(value, 1, 3, 10);
        ASSERT_EQ(hash_table_entry.get_global_id(), 1);
        ASSERT_EQ(hash_table_entry.get_element(), value);
        hash_table_entry.set_current_function_id(0);
        std::vector<std::uint64_t> addresses = {22, 33, 44};
        auto addresses_copy = addresses;
        hash_table_entry.set_possible_addresses(std::move(addresses));
        ASSERT_EQ(hash_table_entry.get_address_at(0), 2);
        ASSERT_EQ(hash_table_entry.get_address_at(1), 3);
        ASSERT_EQ(hash_table_entry.get_address_at(2), 4);
        ASSERT_EQ(hash_table_entry.get_current_function_id(), 0);
        ASSERT_EQ(hash_table_entry.get_current_address(), 2);
        ASSERT_EQ(hash_table_entry.get_possible_addresses(), addresses_copy);
        ASSERT_EQ(hash_table_entry.is_empty(), false);
        hash_table_entry.iterate_function_number();
        ASSERT_EQ(hash_table_entry.get_current_address(), 3);

        std::array<petace::solo::Byte, 16> value_swap = {petace::solo::Byte(1), petace::solo::Byte(0)};
        std::vector<std::uint64_t> addresses_swap = {44, 33, 22};
        auto addresses_swap_copy = addresses_swap;
        petace::solo::util::HashTableEntry<16> hash_table_entry_swap(value_swap, 2, 3, 50);
        hash_table_entry_swap.set_possible_addresses(std::move(addresses_swap));
        petace::solo::util::swap(hash_table_entry, hash_table_entry_swap);
        ASSERT_EQ(hash_table_entry.get_element(), value_swap);
        ASSERT_EQ(hash_table_entry.get_global_id(), 2);
        ASSERT_EQ(hash_table_entry.get_possible_addresses(), addresses_swap_copy);
    }
}
