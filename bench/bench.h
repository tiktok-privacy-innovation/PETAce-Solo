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

#if (SOLO_COMPILER == SOLO_COMPILER_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#elif (SOLO_COMPILER == SOLO_COMPILER_CLANG)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#endif
#include "benchmark/benchmark.h"
#if (SOLO_COMPILER == SOLO_COMPILER_GCC)
#pragma GCC diagnostic pop
#elif (SOLO_COMPILER == SOLO_COMPILER_CLANG)
#pragma clang diagnostic pop
#endif

#include "solo/solo.h"

// Hash benchmark cases
void bm_hash_sha_256(benchmark::State& state, petace::solo::Byte value);
void bm_hash_sha3_256(benchmark::State& state, petace::solo::Byte value);
void bm_hash_blake2(benchmark::State& state, petace::solo::Byte value);
// PRNG benchmark cases
void bm_prng_shake_128(benchmark::State& state, std::size_t byte_count);
void bm_prng_blake2x(benchmark::State& state, std::size_t byte_count);
#ifdef SOLO_USE_AES_INTRIN
void bm_prng_aes_ctr(benchmark::State& state, std::size_t byte_count);
#endif
// Sampling benchmark cases
void bm_sample_uniform_byte_array_shake_128(benchmark::State& state, std::size_t byte_count);
void bm_sample_uniform_byte_array_blake2x(benchmark::State& state, std::size_t byte_count);
#ifdef SOLO_USE_AES_INTRIN
void bm_sample_uniform_byte_array_aes_ctr(benchmark::State& state, std::size_t byte_count);
#endif
// EC OpenSSL benchmark cases
void bm_ec_hash_to_curve(benchmark::State& state, petace::solo::Byte value);
void bm_ec_encrypt(benchmark::State& state, petace::solo::Byte value);
void bm_ec_decrypt(benchmark::State& state, petace::solo::Byte value);
void bm_ec_switch_key(benchmark::State& state, petace::solo::Byte value);
