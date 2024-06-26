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

#include "solo/prng.h"

static const std::size_t kSeedByteCount = 16;

void bm_prng_shake_128(benchmark::State& state, std::size_t byte_count) {
    std::vector<petace::solo::Byte> output(byte_count);
    petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::SHAKE_128, kSeedByteCount);
    std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create();
    for (auto _ : state) {
        state.PauseTiming();
        prng = prng_factory.create();
        state.ResumeTiming();
        prng->generate(byte_count, output.data());
    }
}

void bm_prng_blake2x(benchmark::State& state, std::size_t byte_count) {
    std::vector<petace::solo::Byte> output(byte_count);
    petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::BLAKE2Xb, kSeedByteCount);
    std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create();
    for (auto _ : state) {
        state.PauseTiming();
        prng = prng_factory.create();
        state.ResumeTiming();
        prng->generate(byte_count, output.data());
    }
}

#ifdef SOLO_USE_AES_INTRIN
void bm_prng_aes_ctr(benchmark::State& state, std::size_t byte_count) {
    std::vector<petace::solo::Byte> output(byte_count);
    petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::AES_ECB_CTR, kSeedByteCount);
    std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create();
    for (auto _ : state) {
        state.PauseTiming();
        prng = prng_factory.create();
        state.ResumeTiming();
        prng->generate(byte_count, output.data());
    }
}
#endif
