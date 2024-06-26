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
#include "solo/util/aes_ecb_ctr.h"
#endif
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <stdexcept>
#include <vector>

#include "openssl/err.h"
#include "openssl/evp.h"

#include "solo/prng.h"
#include "solo/util/blake2.h"
#include "solo/util/defines.h"

namespace petace {
namespace solo {

PRNG::PRNG(std::size_t seed_byte_count, std::size_t buffer_byte_count) {
    if (seed_byte_count == 0) {
        throw std::invalid_argument("seed_byte_count is zero");
    }
    if (buffer_byte_count == 0) {
        throw std::invalid_argument("buffer_byte_count is zero");
    }
    seed_.resize(seed_byte_count);
    get_random_byte_array(seed_.size(), seed_.data());
    buffer_.resize(buffer_byte_count);
    buffer_head_ = buffer_.end();
}

PRNG::PRNG(const std::vector<Byte>& seed, std::size_t buffer_byte_count) {
    if (seed.size() == 0) {
        throw std::invalid_argument("seed is empty");
    }
    if (buffer_byte_count == 0) {
        throw std::invalid_argument("buffer_byte_count is zero");
    }
    seed_.resize(seed.size());
    std::copy_n(seed.cbegin(), seed.size(), seed_.begin());
    buffer_.resize(buffer_byte_count);
    buffer_head_ = buffer_.end();
}

void PRNG::generate(std::size_t out_byte_count, Byte* out) {
    if (out == nullptr && out_byte_count != 0) {
        throw std::invalid_argument("out is nullptr");
    }
    while (out_byte_count) {
        std::size_t current_byte_count =
                std::min(out_byte_count, static_cast<std::size_t>(distance(buffer_head_, buffer_.end())));
        std::copy_n(buffer_head_, current_byte_count, out);
        buffer_head_ += static_cast<ptrdiff_t>(current_byte_count);
        out += current_byte_count;
        out_byte_count -= current_byte_count;

        if (buffer_head_ == buffer_.end()) {
            refill_buffer();
            buffer_head_ = buffer_.begin();
        }
    }
}

void PRNG::get_random_byte_array(std::size_t out_byte_count, Byte* out) {
    if (out_byte_count == 0) {
        return;
    }
    if (out_byte_count != 0 && out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    std::random_device rd("/dev/urandom");
    while (out_byte_count >= 4) {
        *reinterpret_cast<uint32_t*>(out) = rd();
        out += 4;
        out_byte_count -= 4;
    }
    if (out_byte_count) {
        std::uint32_t last = rd();
        memcpy(out, &last, out_byte_count);
    }
}

template <>
void PRNGImpl<PRNGScheme::SHAKE_128>::refill_buffer() {
    EVP_MD_CTX* ctx(EVP_MD_CTX_new());
    std::vector<Byte> seed_ext(seed_.size() + sizeof(counter_));
    auto seed_ext_tail = std::copy_n(seed_.cbegin(), seed_.size(), seed_ext.begin());
    std::copy_n(reinterpret_cast<Byte*>(&counter_), sizeof(counter_), seed_ext_tail);
    if (EVP_DigestInit_ex(ctx, EVP_shake128(), nullptr) == 0) {
        throw std::runtime_error("openssl error: EVP_DigestInit_ex " + std::to_string(ERR_get_error()));
    }
    if (EVP_DigestUpdate(ctx, seed_ext.data(), seed_ext.size()) == 0) {
        throw std::runtime_error("openssl error: EVP_DigestUpdate " + std::to_string(ERR_get_error()));
    }
    if (EVP_DigestFinalXOF(ctx, reinterpret_cast<unsigned char*>(buffer_.data()), buffer_.size()) == 0) {
        throw std::runtime_error("openssl error: EVP_DigestFinalXOF " + std::to_string(ERR_get_error()));
    }
    EVP_MD_CTX_free(ctx);
    counter_++;
}

template <>
void PRNGImpl<PRNGScheme::BLAKE2Xb>::refill_buffer() {
    if (blake2xb(buffer_.data(), buffer_.size(), &counter_, sizeof(counter_), seed_.data(),
                seed_.size() * sizeof(Byte)) != 0) {
        throw std::runtime_error("blake2xb failed");
    }
    counter_++;
}

#ifdef SOLO_USE_AES_INTRIN
template <>
void PRNGImpl<PRNGScheme::AES_ECB_CTR>::refill_buffer() {
    util::aes::Block aes_key;
    std::copy_n(seed_.data(), sizeof(aes_key), reinterpret_cast<Byte*>(&aes_key));
    util::aes::RoundKey aes_round_key;
    util::aes::set_round_key(aes_key, aes_round_key);
    util::aes::encrypt_ecb_ctr(aes_round_key, counter_, reinterpret_cast<util::aes::Block*>(buffer_.data()),
            buffer_.size() / sizeof(util::aes::Block));
    counter_ += buffer_.size() / sizeof(util::aes::Block);
}
#endif

PRNGFactory::PRNGFactory(petace::solo::PRNGScheme scheme, std::size_t seed_byte_count)
        : scheme_(scheme), seed_byte_count_(seed_byte_count) {
    if (seed_byte_count == 0) {
        throw std::invalid_argument("seed_byte_count is zero");
    }
    if (scheme != PRNGScheme::SHAKE_128 && scheme != PRNGScheme::BLAKE2Xb
#ifdef SOLO_USE_AES_INTRIN
            && scheme != PRNGScheme::AES_ECB_CTR
#endif
    ) {
        throw std::invalid_argument("unsupported PRNGScheme");
    }
#ifdef SOLO_USE_AES_INTRIN
    if (scheme == PRNGScheme::AES_ECB_CTR && seed_byte_count != 16) {
        throw std::invalid_argument("PRNGScheme::AES_ECB_CTR requires a 128-bit seed");
    }
#endif
}

std::shared_ptr<PRNG> petace::solo::PRNGFactory::create(std::size_t buffer_byte_count) {
#ifdef SOLO_DEBUG
    if (use_fixed_seed_) {
        switch (scheme_) {
            case PRNGScheme::SHAKE_128:
                return std::make_shared<PRNGImpl<PRNGScheme::SHAKE_128>>(fixed_seed_, buffer_byte_count);
            case PRNGScheme::BLAKE2Xb:
                return std::make_shared<PRNGImpl<PRNGScheme::BLAKE2Xb>>(fixed_seed_, buffer_byte_count);
#ifdef SOLO_USE_AES_INTRIN
            case PRNGScheme::AES_ECB_CTR:
                return std::make_shared<PRNGImpl<PRNGScheme::AES_ECB_CTR>>(fixed_seed_, buffer_byte_count);
#endif
        }
    }
#endif
    switch (scheme_) {
        case PRNGScheme::SHAKE_128:
            return std::make_shared<PRNGImpl<PRNGScheme::SHAKE_128>>(seed_byte_count_, buffer_byte_count);
        case PRNGScheme::BLAKE2Xb:
            return std::make_shared<PRNGImpl<PRNGScheme::BLAKE2Xb>>(seed_byte_count_, buffer_byte_count);
#ifdef SOLO_USE_AES_INTRIN
        case PRNGScheme::AES_ECB_CTR:
            return std::make_shared<PRNGImpl<PRNGScheme::AES_ECB_CTR>>(seed_byte_count_, buffer_byte_count);
#endif
    }
    return nullptr;
}

std::shared_ptr<PRNG> petace::solo::PRNGFactory::create(const std::vector<Byte>& seed, std::size_t buffer_byte_count) {
    if (seed.size() != seed_byte_count_) {
        throw std::invalid_argument("seed.size() does not match seed_byte_count_");
    }
    switch (scheme_) {
        case PRNGScheme::SHAKE_128:
            return std::make_shared<PRNGImpl<PRNGScheme::SHAKE_128>>(seed, buffer_byte_count);
        case PRNGScheme::BLAKE2Xb:
            return std::make_shared<PRNGImpl<PRNGScheme::BLAKE2Xb>>(seed, buffer_byte_count);
#ifdef SOLO_USE_AES_INTRIN
        case PRNGScheme::AES_ECB_CTR:
            return std::make_shared<PRNGImpl<PRNGScheme::AES_ECB_CTR>>(seed, buffer_byte_count);
#endif
    }
    return nullptr;
}

#ifdef SOLO_DEBUG
PRNGFactory::PRNGFactory(petace::solo::PRNGScheme scheme, const std::vector<Byte>& seed) : scheme_(scheme) {
    if (seed.size() == 0) {
        throw std::invalid_argument("seed is empty");
    }
#ifdef SOLO_USE_AES_INTRIN
    if (scheme == PRNGScheme::AES_ECB_CTR && seed.size() != 16) {
        throw std::invalid_argument("PRNGScheme::AES_ECB_CTR requires a 128-bit seed");
    }
#endif
    seed_byte_count_ = seed.size();
    use_fixed_seed_ = true;
    fixed_seed_.resize(seed_byte_count_);
    std::copy_n(seed.cbegin(), seed_byte_count_, fixed_seed_.begin());
}
#endif

}  // namespace solo
}  // namespace petace
