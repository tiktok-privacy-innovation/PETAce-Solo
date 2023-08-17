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

#include "solo/util/config.h"
#ifdef SOLO_USE_AES_INTRIN

#include <wmmintrin.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>

#include "solo/util/aes_ecb_ctr.h"

namespace petace {
namespace solo {
namespace util {
namespace aes {
Block key_gen_helper(Block key, Block key_rcon) {
    key_rcon = _mm_shuffle_epi32(key_rcon, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, key_rcon);
}

void set_round_key(const Block& key, RoundKey& round_key) {
    round_key[0] = key;
    round_key[1] = key_gen_helper(round_key[0], _mm_aeskeygenassist_si128(round_key[0], 0x01));
    round_key[2] = key_gen_helper(round_key[1], _mm_aeskeygenassist_si128(round_key[1], 0x02));
    round_key[3] = key_gen_helper(round_key[2], _mm_aeskeygenassist_si128(round_key[2], 0x04));
    round_key[4] = key_gen_helper(round_key[3], _mm_aeskeygenassist_si128(round_key[3], 0x08));
    round_key[5] = key_gen_helper(round_key[4], _mm_aeskeygenassist_si128(round_key[4], 0x10));
    round_key[6] = key_gen_helper(round_key[5], _mm_aeskeygenassist_si128(round_key[5], 0x20));
    round_key[7] = key_gen_helper(round_key[6], _mm_aeskeygenassist_si128(round_key[6], 0x40));
    round_key[8] = key_gen_helper(round_key[7], _mm_aeskeygenassist_si128(round_key[7], 0x80));
    round_key[9] = key_gen_helper(round_key[8], _mm_aeskeygenassist_si128(round_key[8], 0x1B));
    round_key[10] = key_gen_helper(round_key[9], _mm_aeskeygenassist_si128(round_key[9], 0x36));
}

void encrypt_ecb_ctr(const RoundKey& round_key, std::uint64_t counter, Block* out, std::size_t out_block_count) {
    Block counter_block = _mm_set_epi64x(0, static_cast<int64_t>(counter));

    const std::size_t step = 8;
    std::size_t length = out_block_count - out_block_count % step;
    const Block b0 = _mm_set_epi64x(0, 0);
    const Block b1 = _mm_set_epi64x(0, 1ull);
    const Block b2 = _mm_set_epi64x(0, 2ull);
    const Block b3 = _mm_set_epi64x(0, 3ull);
    const Block b4 = _mm_set_epi64x(0, 4ull);
    const Block b5 = _mm_set_epi64x(0, 5ull);
    const Block b6 = _mm_set_epi64x(0, 6ull);
    const Block b7 = _mm_set_epi64x(0, 7ull);
    Block temp[8];

    std::size_t idx = 0;
    for (; idx < length; idx += step) {
        temp[0] = (counter_block + b0) ^ round_key[0];
        temp[1] = (counter_block + b1) ^ round_key[0];
        temp[2] = (counter_block + b2) ^ round_key[0];
        temp[3] = (counter_block + b3) ^ round_key[0];
        temp[4] = (counter_block + b4) ^ round_key[0];
        temp[5] = (counter_block + b5) ^ round_key[0];
        temp[6] = (counter_block + b6) ^ round_key[0];
        temp[7] = (counter_block + b7) ^ round_key[0];
        counter_block = counter_block + _mm_set_epi64x(0, step);

        temp[0] = _mm_aesenc_si128(temp[0], round_key[1]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key[1]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key[1]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key[1]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key[1]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key[1]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key[1]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key[1]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key[2]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key[2]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key[2]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key[2]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key[2]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key[2]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key[2]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key[2]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key[3]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key[3]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key[3]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key[3]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key[3]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key[3]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key[3]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key[3]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key[4]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key[4]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key[4]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key[4]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key[4]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key[4]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key[4]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key[4]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key[5]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key[5]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key[5]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key[5]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key[5]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key[5]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key[5]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key[5]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key[6]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key[6]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key[6]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key[6]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key[6]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key[6]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key[6]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key[6]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key[7]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key[7]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key[7]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key[7]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key[7]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key[7]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key[7]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key[7]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key[8]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key[8]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key[8]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key[8]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key[8]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key[8]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key[8]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key[8]);

        temp[0] = _mm_aesenc_si128(temp[0], round_key[9]);
        temp[1] = _mm_aesenc_si128(temp[1], round_key[9]);
        temp[2] = _mm_aesenc_si128(temp[2], round_key[9]);
        temp[3] = _mm_aesenc_si128(temp[3], round_key[9]);
        temp[4] = _mm_aesenc_si128(temp[4], round_key[9]);
        temp[5] = _mm_aesenc_si128(temp[5], round_key[9]);
        temp[6] = _mm_aesenc_si128(temp[6], round_key[9]);
        temp[7] = _mm_aesenc_si128(temp[7], round_key[9]);

        temp[0] = _mm_aesenclast_si128(temp[0], round_key[10]);
        temp[1] = _mm_aesenclast_si128(temp[1], round_key[10]);
        temp[2] = _mm_aesenclast_si128(temp[2], round_key[10]);
        temp[3] = _mm_aesenclast_si128(temp[3], round_key[10]);
        temp[4] = _mm_aesenclast_si128(temp[4], round_key[10]);
        temp[5] = _mm_aesenclast_si128(temp[5], round_key[10]);
        temp[6] = _mm_aesenclast_si128(temp[6], round_key[10]);
        temp[7] = _mm_aesenclast_si128(temp[7], round_key[10]);

        memcpy(out + idx, temp, sizeof(temp));
    }

    for (; idx < out_block_count; idx++) {
        auto left = counter_block ^ round_key[0];
        counter_block = counter_block + _mm_set_epi64x(0, 1);
        left = _mm_aesenc_si128(left, round_key[1]);
        left = _mm_aesenc_si128(left, round_key[2]);
        left = _mm_aesenc_si128(left, round_key[3]);
        left = _mm_aesenc_si128(left, round_key[4]);
        left = _mm_aesenc_si128(left, round_key[5]);
        left = _mm_aesenc_si128(left, round_key[6]);
        left = _mm_aesenc_si128(left, round_key[7]);
        left = _mm_aesenc_si128(left, round_key[8]);
        left = _mm_aesenc_si128(left, round_key[9]);
        left = _mm_aesenclast_si128(left, round_key[10]);

        memcpy(out + idx, &left, sizeof(left));
    }
}

}  // namespace aes
}  // namespace util
}  // namespace solo
}  // namespace petace
#endif
