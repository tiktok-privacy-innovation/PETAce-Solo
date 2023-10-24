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

// \file cuckoo_hashing.cpp
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
// \copyright The MIT License. Copyright 2019
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// This file may have been modified by PETAce-Solo Authors. (“PETAce-Solo Modifications”).
// All PETAce-Solo Modifications are Copyright 2023 PETAce-Solo Authors.

#include "solo/cuckoo_hashing.h"

#include <cmath>

#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace petace {
namespace solo {

template <std::size_t item_byte_count>
void CuckooHashing<item_byte_count>::insert(Item element) noexcept {
    elements_.push_back(element);
}

template <std::size_t item_byte_count>
void CuckooHashing<item_byte_count>::insert(const std::vector<Item>& elements) noexcept {
    elements_.insert(elements_.end(), elements.begin(), elements.end());
}

template <std::size_t item_byte_count>
void CuckooHashing<item_byte_count>::set_num_of_hash_functions(std::size_t n) {
    if (n <= 1) {
        throw std::invalid_argument("Must have at least 2 hash functions");
    }
    num_of_hash_functions_ = n;
}

template <std::size_t item_byte_count>
void CuckooHashing<item_byte_count>::set_recursive_insertion_limiter(std::size_t limiter) noexcept {
    recursion_limiter_ = limiter;
}

template <std::size_t item_byte_count>
void CuckooHashing<item_byte_count>::map_elements() noexcept {
    allocate_table();
    map_elements_to_table();
    mapped_ = true;
}

template <std::size_t item_byte_count>
bool CuckooHashing<item_byte_count>::map_elements_to_table() {
    allocate_luts();
    generate_luts();

    for (std::size_t element_id = 0; element_id < elements_.size(); ++element_id) {
        util::HashTableEntry<item_byte_count> current_entry(
                elements_.at(element_id), element_id, num_of_hash_functions_, num_bins_);

        // find the new element's mappings and put them to the corresponding std::vector
        auto addresses = hash_to_position(elements_.at(element_id));
        current_entry.set_possible_addresses(std::move(addresses));
        current_entry.set_current_function_id(0);

        util::swap(current_entry, hash_table_.at(current_entry.get_current_address()));

        for (std::size_t recursion_step = 0; !current_entry.is_empty(); ++recursion_step) {
            if (recursion_step > recursion_limiter_) {
                stash_.push_back(current_entry);
                break;
            } else {
                current_entry.iterate_function_number();
                current_entry.get_current_address();
                util::swap(current_entry, hash_table_.at(current_entry.get_current_address()));
            }
        }
    }

    mapped_ = true;

    return true;
}

template <std::size_t item_byte_count>
std::vector<std::uint64_t> CuckooHashing<item_byte_count>::get_element_addresses() noexcept {
    std::vector<std::uint64_t> hash_addresses;
    hash_addresses.resize(elements_.size() * num_of_hash_functions_);

    allocate_luts();
    generate_luts();
    for (std::size_t i = 0; i < elements_.size(); ++i) {
        util::HashTableEntry<item_byte_count> current_entry(elements_.at(i), i, num_of_hash_functions_, num_bins_);
        auto addresses = hash_to_position(elements_.at(i));
        current_entry.set_possible_addresses(std::move(addresses));
        for (std::size_t j = 0; j < num_of_hash_functions_; ++j) {
            hash_addresses[i * num_of_hash_functions_ + j] = current_entry.get_address_at(j);
        }
    }
    return hash_addresses;
}

template <std::size_t item_byte_count>
std::vector<std::array<Byte, item_byte_count>> CuckooHashing<item_byte_count>::obtain_entry_values() const noexcept {
    std::vector<Item> raw_table;
    raw_table.reserve(num_bins_);

    for (std::size_t i = 0; i < num_bins_; ++i) {
        std::uint8_t current_function_id = static_cast<std::uint8_t>(hash_table_.at(i).get_current_function_id());
        Item element = hash_table_.at(i).get_element();
        element[0] ^= Byte(current_function_id);
        raw_table.push_back(element);
    }

    return raw_table;
}

template <std::size_t item_byte_count>
std::vector<std::array<Byte, item_byte_count>> CuckooHashing<item_byte_count>::obtain_entry_source_values()
        const noexcept {
    std::vector<Item> raw_table;
    raw_table.reserve(num_bins_);

    for (std::size_t i = 0; i < num_bins_; ++i) {
        Item element = hash_table_.at(i).get_element();
        raw_table.push_back(element);
    }

    return raw_table;
}

template <std::size_t item_byte_count>
std::vector<std::uint8_t> CuckooHashing<item_byte_count>::obtain_entry_function_ids() const noexcept {
    std::vector<std::uint8_t> funtion_id_table;
    funtion_id_table.reserve(num_bins_);

    for (std::size_t i = 0; i < num_bins_; ++i) {
        std::uint8_t current_function_id = static_cast<std::uint8_t>(hash_table_.at(i).get_current_function_id());
        funtion_id_table.push_back(current_function_id);
    }

    return funtion_id_table;
}

template <std::size_t item_byte_count>
std::vector<std::uint64_t> CuckooHashing<item_byte_count>::obtain_entry_ids() const noexcept {
    std::vector<std::uint64_t> id_table;
    id_table.reserve(num_bins_);

    for (std::size_t i = 0; i < num_bins_; ++i) {
        id_table.push_back(hash_table_.at(i).get_global_id());
    }

    return id_table;
}

template <std::size_t item_byte_count>
std::vector<bool> CuckooHashing<item_byte_count>::obtain_bin_occupancy() const noexcept {
    // Shows whether the entry is not empty
    std::vector<bool> occ_table;
    occ_table.reserve(num_bins_);

    for (std::size_t i = 0; i < num_bins_; ++i) {
        occ_table.push_back(!hash_table_.at(i).is_empty());
    }

    return occ_table;
}

template <std::size_t item_byte_count>
std::vector<std::size_t> CuckooHashing<item_byte_count>::get_num_of_elements_in_bins() const noexcept {
    std::vector<std::uint64_t> num_elements_in_bins(hash_table_.size(), 0);
    for (std::size_t i = 0; i < hash_table_.size(); ++i) {
        if (!hash_table_.at(i).is_empty()) {
            ++num_elements_in_bins.at(i);
        }
    }
    return num_elements_in_bins;
}

template <std::size_t item_byte_count>
CuckooHashing<item_byte_count>::CuckooHashing(double epsilon, std::size_t num_of_bins, const std::vector<Byte>& seed) {
    epsilon_ = epsilon;
    num_bins_ = num_of_bins;

    if (seed.empty()) {
        seed_.resize(16);
        for (std::size_t i = 0; i < 16; i++) {
            seed_[i] = (Byte)0;
        }
    } else {
        if (seed.size() != 16) {
            throw std::invalid_argument("The seed length must be 16.");
        }
        seed_ = seed;
    }

    solo::PRNGFactory prng_factory(solo::PRNGScheme::AES_ECB_CTR);
    generator_ = prng_factory.create(seed_);
}

template <std::size_t item_byte_count>
bool CuckooHashing<item_byte_count>::allocate_table() {
    if (num_bins_ == 0 && epsilon_ == 0.0f) {
        throw std::invalid_argument("Either the number of bins or epsilon must be non-zero.");
    } else if (epsilon_ < 0.0f) {
        throw std::invalid_argument("Epsilon cannot be negative.");
    }

    if (epsilon_ > 0.0f) {
        num_bins_ = static_cast<std::size_t>(std::ceil(static_cast<double>(elements_.size()) * epsilon_));
    }
    hash_table_.resize(num_bins_);
    return true;
}

template <std::size_t item_byte_count>
bool CuckooHashing<item_byte_count>::allocate_luts() {
    luts_.resize(num_of_hash_functions_);
    for (auto& luts : luts_) {
        luts.resize(num_of_luts_);
        for (auto& entry : luts) {
            entry.resize(num_of_tables_in_lut_);
        }
    }
    return true;
}

template <std::size_t item_byte_count>
bool CuckooHashing<item_byte_count>::generate_luts() {
    for (std::size_t i = 0; i < num_of_hash_functions_; ++i) {
        for (std::size_t j = 0; j < num_of_luts_; ++j) {
            for (std::size_t k = 0; k < num_of_tables_in_lut_; k++) {
                generator_->generate(sizeof(std::uint64_t), reinterpret_cast<solo::Byte*>(&luts_.at(i).at(j).at(k)));
            }
        }
    }

    return true;
}

template <std::size_t item_byte_count>
std::vector<std::uint64_t> CuckooHashing<item_byte_count>::hash_to_position(const Item& element) const {
    std::vector<std::uint64_t> addresses;
    for (std::size_t func_i = 0; func_i < num_of_hash_functions_; ++func_i) {
        std::uint64_t address = 0;
        for (std::size_t lut_i = 0; lut_i < num_of_luts_; ++lut_i) {
            address ^= luts_.at(func_i).at(lut_i).at(static_cast<std::size_t>(element[lut_i]));
        }
        addresses.push_back(address);
    }
    return addresses;
}

template class CuckooHashing<16>;
template class CuckooHashing<8>;

}  // namespace solo
}  // namespace petace
