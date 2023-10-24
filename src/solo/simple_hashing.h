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

// \file simple_hashing.h
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

#pragma once

#include <array>
#include <memory>
#include <vector>

#include "solo/prng.h"
#include "solo/util/hash_table_entry.h"

namespace petace {
namespace solo {

/**
 * @brief Provides a simple hashing table template that supports an arbitrary item size.
 */
template <std::size_t item_byte_count = 16>
class SimpleHashing {
public:
    using Item = std::array<Byte, item_byte_count>;

    SimpleHashing() = delete;

    /**
     * @brief Constructs an empty simple hashing table with a given #bins.
     *
     * @param[in] num_of_bins The #bins
     */
    explicit SimpleHashing(std::size_t num_of_bins) noexcept : SimpleHashing(0.0f, num_of_bins, std::vector<Byte>()) {
    }

    /**
     * @brief Constructs an empty simple hashing table with a given #bins and a seed.
     *
     * @param[in] num_of_bins The #bins
     * @param[in] seed The seed to create hash functions
     * @throws std::invalid_argument if the seed is not 16 bytes
     */
    SimpleHashing(std::size_t num_of_bins, const std::vector<Byte>& seed) : SimpleHashing(0.0f, num_of_bins, seed) {
    }

    /**
     * @brief Destructor.
     */
    ~SimpleHashing() {
    }

    /**
     * @brief Registers an element to be added to the hashing table.
     *
     * @param[in] element The element
     */
    void insert(const Item& element) noexcept;

    /**
     * @brief Registers a vector of elements to be added to the hashing table.
     *
     * @param[in] elements The vector of elements
     */
    void insert(const std::vector<Item>& elements) noexcept;

    /**
     * @brief Sets the number of hash functions.
     *
     * @param[in] n The number of hash functions
     * @throws std::invalid_argument if n is 0
     */
    void set_num_of_hash_functions(std::size_t n);

    /**
     * @brief Maps registered elements to a simple hashing table.
     * Returns true, if success.
     */
    void map_elements() noexcept;

    /**
     * @brief Set a maximum bin size to pad to.
     *
     * @param[in] size The maximum bin size
     */
    void set_maximum_bin_size(std::size_t size) noexcept;

    /**
     * @brief Returns all hash table entries XORed with the function ID.
     */
    SOLO_NODISCARD std::vector<Item> obtain_entry_values() const noexcept;

    /**
     * @brief Returns all hash table entries including padded entries.
     */
    SOLO_NODISCARD std::vector<Item> obtain_entry_values_padded() const noexcept;

    /**
     * @brief Returns all hash table bin entries.
     */
    SOLO_NODISCARD std::vector<std::vector<Item>> obtain_bin_entry_values() const noexcept;

    /**
     * @brief Returns all hash table entries' function IDs.
     */
    SOLO_NODISCARD std::vector<std::vector<std::uint64_t>> obtain_bin_entry_function_ids() const noexcept;

    /**
     * @brief Returns all hash table entries' registration IDs.
     */
    SOLO_NODISCARD std::vector<std::vector<std::uint64_t>> obtain_bin_entry_ids() const noexcept;

    /**
     * @brief Returns the number of elements stored in bins.
     */
    SOLO_NODISCARD std::vector<std::size_t> get_num_of_elements_in_bins() const noexcept;

    /**
     * @brief Returns the maximum number elements in a bin.
     */
    SOLO_NODISCARD auto get_max_observed_bin_size() const noexcept {
        return max_observed_bin_size_;
    }

private:
    SimpleHashing(double epsilon, std::size_t num_of_bins, const std::vector<Byte>& seed);

    bool allocate_table();

    bool map_elements_to_table();

    bool allocate_luts();

    bool generate_luts();

    std::vector<std::uint64_t> hash_to_position(const Item& element) const;

    std::vector<Item> elements_;
    std::vector<std::vector<util::HashTableEntry<item_byte_count>>> hash_table_;

    // binning
    double epsilon_ = 1.2f;
    std::size_t num_bins_ = 0;
    std::size_t num_of_hash_functions_ = 2;

    // randomness
    std::vector<Byte> seed_{};
    std::shared_ptr<solo::PRNG> generator_;

    // LUTs
    static constexpr std::size_t num_of_luts_ = item_byte_count;
    static constexpr std::size_t num_of_tables_in_lut_ = 256;
    std::vector<std::vector<std::vector<std::uint64_t>>> luts_{};

    bool mapped_ = false;

    std::size_t maximum_bin_size_ = 20;
    bool pad_to_maximum_bin_size = false;

    // < the maximum number of elements in a single bin
    std::size_t max_observed_bin_size_ = 0;
};

}  // namespace solo
}  // namespace petace
