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

#include "solo/ec_openssl.h"

void bm_ec_hash_to_curve(benchmark::State& state, petace::solo::Byte value) {
    std::array<petace::solo::Byte, 64> input;
    using EC = petace::solo::ECOpenSSL;
    int curve_id = 415;
    EC ec(curve_id, petace::solo::HashScheme::SHA_256);
    EC::Point point(ec);

    for (auto _ : state) {
        state.PauseTiming();
        for (auto& i : input)
            i = value;
        state.ResumeTiming();
        ec.hash_to_curve(input.data(), 64, point);
    }
}

void bm_ec_encrypt(benchmark::State& state, petace::solo::Byte value) {
    std::array<petace::solo::Byte, 64> input;
    for (auto& i : input)
        i = value;
    using EC = petace::solo::ECOpenSSL;
    int curve_id = 415;
    EC ec(curve_id, petace::solo::HashScheme::SHA_256);
    EC::Point pt(ec);
    ec.hash_to_curve(input.data(), 64, pt);
    EC::Point ct(ec);
    EC::SecretKey sk;
    ec.create_secret_key(petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb).create(), sk);

    for (auto _ : state) {
        state.PauseTiming();
        state.ResumeTiming();
        ec.encrypt(pt, sk, ct);
    }
}

void bm_ec_decrypt(benchmark::State& state, petace::solo::Byte value) {
    std::array<petace::solo::Byte, 64> input;
    for (auto& i : input)
        i = value;
    using EC = petace::solo::ECOpenSSL;
    int curve_id = 415;
    EC ec(curve_id, petace::solo::HashScheme::SHA_256);
    EC::Point pt(ec);
    ec.hash_to_curve(input.data(), 64, pt);
    EC::Point ct(ec);
    EC::SecretKey sk;
    ec.create_secret_key(petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb).create(), sk);
    EC::Point pt_other(ec);
    ec.encrypt(pt, sk, ct);

    for (auto _ : state) {
        state.PauseTiming();
        state.ResumeTiming();
        ec.decrypt(ct, sk, pt_other);
    }
}

void bm_ec_switch_key(benchmark::State& state, petace::solo::Byte value) {
    std::array<petace::solo::Byte, 64> input;
    for (auto& i : input)
        i = value;
    using EC = petace::solo::ECOpenSSL;
    int curve_id = 415;
    EC ec(curve_id, petace::solo::HashScheme::SHA_256);
    EC::Point pt(ec);
    ec.hash_to_curve(input.data(), 64, pt);
    EC::Point ct(ec);
    EC::SecretKey sk;
    auto prng = petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb).create();
    ec.create_secret_key(prng, sk);
    EC::SecretKey sk_new;
    ec.create_secret_key(prng, sk_new);
    ec.encrypt(pt, sk, ct);
    EC::Point ct_other(ec);

    for (auto _ : state) {
        state.PauseTiming();
        state.ResumeTiming();
        ec.switch_key(ct, sk, sk_new, ct_other);
    }
}
