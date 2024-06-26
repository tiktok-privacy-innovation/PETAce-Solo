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

#include "bench.h"

#include "solo/solo.h"

#define PETACE_REG_BENCH(category, name, func, ...)                                                             \
    benchmark::RegisterBenchmark(                                                                               \
            (std::string(#category " / " #name)).c_str(), [=](benchmark::State& st) { func(st, __VA_ARGS__); }) \
            ->Unit(benchmark::kMicrosecond)                                                                     \
            ->Iterations(10);

int main(int argc, char** argv) {
    PETACE_REG_BENCH(Hash, SHA_256, bm_hash_sha_256, petace::solo::Byte(0));
    PETACE_REG_BENCH(Hash, SHA3_256, bm_hash_sha3_256, petace::solo::Byte(0));
    PETACE_REG_BENCH(Hash, BLAKE2, bm_hash_blake2, petace::solo::Byte(0));
    PETACE_REG_BENCH(petace::solo::PRNG, SHAKE_128, bm_prng_shake_128, std::size_t(4096));
    PETACE_REG_BENCH(petace::solo::PRNG, BLAKE2X, bm_prng_blake2x, std::size_t(4096));
#ifdef SOLO_USE_AES_INTRIN
    PETACE_REG_BENCH(petace::solo::PRNG, AES_ECB_CTR, bm_prng_aes_ctr, std::size_t(4096));
#endif
    PETACE_REG_BENCH(Sampling, UNIFORM_BYTE_ARRAY_SHAKE_128, bm_sample_uniform_byte_array_shake_128, std::size_t(4096));
    PETACE_REG_BENCH(Sampling, UNIFORM_BYTE_ARRAY_BLAKE2X, bm_sample_uniform_byte_array_blake2x, std::size_t(4096));
#ifdef SOLO_USE_AES_INTRIN
    PETACE_REG_BENCH(Sampling, UNIFORM_BYTE_ARRAY_AES_ECB_CTR, bm_sample_uniform_byte_array_aes_ctr, std::size_t(4096));
#endif
    PETACE_REG_BENCH(EC_OpenSSL, hash_to_curve, bm_ec_hash_to_curve, petace::solo::Byte(0));
    PETACE_REG_BENCH(EC_OpenSSL, encrypt, bm_ec_encrypt, petace::solo::Byte(0));
    PETACE_REG_BENCH(EC_OpenSSL, decrypt, bm_ec_decrypt, petace::solo::Byte(0));
    PETACE_REG_BENCH(EC_OpenSSL, switch_key, bm_ec_switch_key, petace::solo::Byte(0));

    benchmark::Initialize(&argc, argv);

    benchmark::RunSpecifiedBenchmarks();
}
