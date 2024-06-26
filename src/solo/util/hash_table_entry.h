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

// \file hash_table_entry.h
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
// \copyright The MIT License. Copyright 2019

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

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include "solo/util/defines.h"

namespace petace {
namespace solo {
namespace util {

extern const std::size_t kHashTableDummyElement;

template <std::size_t item_byte_count = 16>
class HashTableEntry {
public:
    using Item = std::array<Byte, item_byte_count>;

    HashTableEntry() {
        global_id_ = kHashTableDummyElement;
        std::fill_n(value_.begin(), item_byte_count, Byte(0xFF));
    }

    HashTableEntry(Item value, std::size_t global_id, std::size_t num_of_functions, std::size_t num_of_bins);

    HashTableEntry(const HashTableEntry& other);

    void set_current_function_id(std::size_t function_id) {
        current_function_id_ = function_id;
    }

    void set_possible_addresses(std::vector<std::uint64_t>&& addresses) {
        possible_addresses_ = std::move(addresses);
    }

    std::uint64_t get_address_at(std::size_t function_id) const {
        return possible_addresses_.at(function_id) % num_of_bins_;
    }

    std::size_t get_current_function_id() const {
        return current_function_id_;
    }

    std::uint64_t get_current_address() const {
        return possible_addresses_.at(current_function_id_) % num_of_bins_;
    }

    const std::vector<std::uint64_t> get_possible_addresses() const {
        return possible_addresses_;
    }

    bool is_empty() const {
        return std::all_of(value_.begin(), value_.end(), [](Byte i) { return i == Byte(0xFF); });
    }

    std::size_t get_global_id() const {
        return global_id_;
    }

    Item get_element() const {
        return value_;
    }

    void iterate_function_number() {
        current_function_id_ = (current_function_id_ + 1) % num_of_hash_functions_;
    }

    template <std::size_t count>
    friend void swap(HashTableEntry<count>& a, HashTableEntry<count>& b) noexcept;

private:
    std::size_t num_of_hash_functions_ = 0;
    std::size_t num_of_bins_ = 0;
    std::size_t global_id_ = 0;
    Item value_{};
    std::size_t current_function_id_ = 0;
    std::vector<std::uint64_t> possible_addresses_{};
};

template <std::size_t item_byte_count>
void swap(HashTableEntry<item_byte_count>& a, HashTableEntry<item_byte_count>& b) noexcept;

}  // namespace util
}  // namespace solo
}  // namespace petace
