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

#include "solo/util/hash_table_entry.h"

#include <cstdint>
#include <limits>

namespace petace {
namespace solo {
namespace util {

const std::size_t kHashTableDummyElement = std::numeric_limits<std::size_t>::max();

template <std::size_t item_byte_count>
HashTableEntry<item_byte_count>::HashTableEntry(
        Item value, std::size_t global_id, std::size_t num_of_functions, std::size_t num_of_bins) {
    value_ = value;
    global_id_ = global_id;
    num_of_hash_functions_ = num_of_functions;
    num_of_bins_ = num_of_bins;
}

template <std::size_t item_byte_count>
HashTableEntry<item_byte_count>::HashTableEntry(const HashTableEntry& other) {
    num_of_hash_functions_ = other.num_of_hash_functions_;
    num_of_bins_ = other.num_of_bins_;
    global_id_ = other.global_id_;

    value_ = other.value_;
    current_function_id_ = other.current_function_id_;
    possible_addresses_ = other.possible_addresses_;
}

template <std::size_t item_byte_count>
void swap(HashTableEntry<item_byte_count>& a, HashTableEntry<item_byte_count>& b) noexcept {
    std::swap(a.value_, b.value_);
    std::swap(a.global_id_, b.global_id_);
    std::swap(a.possible_addresses_, b.possible_addresses_);
    std::swap(a.current_function_id_, b.current_function_id_);
    std::swap(a.num_of_bins_, b.num_of_bins_);
    std::swap(a.num_of_hash_functions_, b.num_of_hash_functions_);
}

template class HashTableEntry<16>;
template class HashTableEntry<8>;

template void swap<8>(HashTableEntry<8>&, HashTableEntry<8>&);
template void swap<16>(HashTableEntry<16>&, HashTableEntry<16>&);

}  // namespace util
}  // namespace solo
}  // namespace petace
