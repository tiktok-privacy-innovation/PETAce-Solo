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

#include "solo/hash.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "openssl/err.h"
#include "openssl/evp.h"

namespace petace {
namespace solo {

SOLO_NODISCARD std::shared_ptr<Hash> Hash::create(HashScheme scheme) {
    switch (scheme) {
        case HashScheme::SHA_256:
            return std::make_shared<HashSHA_256>();
        case HashScheme::SHA3_256:
            return std::make_shared<HashSHA3_256>();
        case HashScheme::BLAKE2b:
            return std::make_shared<HashBLAKE2b>();
        default:
            throw std::invalid_argument("invalid scheme");
    }
}

SOLO_NODISCARD std::shared_ptr<HashFactory> HashFactory::create_factory(HashScheme scheme) {
    switch (scheme) {
        case HashScheme::SHA_256:
            return std::make_shared<HashFactorySHA_256>();
        case HashScheme::SHA3_256:
            return std::make_shared<HashFactorySHA3_256>();
        case HashScheme::BLAKE2b:
            return std::make_shared<HashFactoryBLAKE2b>();
        default:
            throw std::invalid_argument("invalid scheme");
    }
}

HashSHA_256::HashSHA_256() : ctx_(EVP_MD_CTX_new()), md_(EVP_sha256()) {
    if (ctx_ == nullptr) {
        throw std::invalid_argument("ctx_ is nullptr");
    }
}

HashSHA_256::~HashSHA_256() {
    if (ctx_ != nullptr) {
        EVP_MD_CTX_free(ctx_);
    }
}

constexpr std::size_t HashSHA_256::kHashByteCount;

void HashSHA_256::compute(const Byte* in, std::size_t in_byte_count, Byte* out, std::size_t out_byte_count) {
    if (in_byte_count == 0 || out_byte_count == 0) {
        return;
    }
    if (in == nullptr && in_byte_count != 0) {
        throw std::invalid_argument("in is nullptr");
    }
    if (out == nullptr && out_byte_count != 0) {
        throw std::invalid_argument("out is nullptr");
    }
    if (out_byte_count > kHashByteCount) {
        throw std::invalid_argument("out_byte_count is too large");
    }
    if (EVP_DigestInit_ex(ctx_, md_, nullptr) == 0) {
        throw std::runtime_error("openssl error: EVP_DigestInit_ex " + std::to_string(ERR_get_error()));
    }
    if (EVP_DigestUpdate(ctx_, in, in_byte_count) == 0) {
        throw std::runtime_error("openssl error: EVP_DigestUpdate " + std::to_string(ERR_get_error()));
    }
    if (out_byte_count == kHashByteCount) {
        if (EVP_DigestFinal_ex(ctx_, reinterpret_cast<unsigned char*>(out), NULL) == 0) {
            throw std::runtime_error("openssl error: EVP_DigestFinal_ex " + std::to_string(ERR_get_error()));
        }
    } else {
        std::array<Byte, 32> buf_;
        if (EVP_DigestFinal_ex(ctx_, reinterpret_cast<unsigned char*>(buf_.data()), NULL) == 0) {
            throw std::runtime_error("openssl error: EVP_DigestFinal_ex " + std::to_string(ERR_get_error()));
        }
        std::copy_n(buf_.data(), out_byte_count, out);
    }
}

HashSHA3_256::HashSHA3_256() : ctx_(EVP_MD_CTX_new()), md_(EVP_sha3_256()) {
    if (ctx_ == nullptr) {
        throw std::invalid_argument("ctx_ is nullptr");
    }
}

HashSHA3_256::~HashSHA3_256() {
    if (ctx_ != nullptr) {
        EVP_MD_CTX_free(ctx_);
    }
}

constexpr std::size_t HashSHA3_256::kHashByteCount;

void HashSHA3_256::compute(const Byte* in, std::size_t in_byte_count, Byte* out, std::size_t out_byte_count) {
    if (in_byte_count == 0 || out_byte_count == 0) {
        return;
    }
    if (in == nullptr && in_byte_count != 0) {
        throw std::invalid_argument("in is nullptr");
    }
    if (out == nullptr && out_byte_count != 0) {
        throw std::invalid_argument("out is nullptr");
    }
    if (out_byte_count > kHashByteCount) {
        throw std::invalid_argument("out_byte_count is too large");
    }
    if (EVP_DigestInit_ex(ctx_, md_, nullptr) == 0) {
        throw std::runtime_error("openssl error: EVP_DigestInit_ex " + std::to_string(ERR_get_error()));
    }
    if (EVP_DigestUpdate(ctx_, in, in_byte_count) == 0) {
        throw std::runtime_error("openssl error: EVP_DigestUpdate " + std::to_string(ERR_get_error()));
    }
    if (out_byte_count == kHashByteCount) {
        if (EVP_DigestFinal_ex(ctx_, reinterpret_cast<unsigned char*>(out), NULL) == 0) {
            throw std::runtime_error("openssl error: EVP_DigestFinal_ex " + std::to_string(ERR_get_error()));
        }
    } else {
        std::array<Byte, 32> buf_;
        if (EVP_DigestFinal_ex(ctx_, reinterpret_cast<unsigned char*>(buf_.data()), NULL) == 0) {
            throw std::runtime_error("openssl error: EVP_DigestFinal_ex " + std::to_string(ERR_get_error()));
        }
        std::copy_n(buf_.data(), out_byte_count, out);
    }
}

HashBLAKE2b::HashBLAKE2b() : ctx_(EVP_MD_CTX_new()), md_(EVP_blake2b512()) {
    if (ctx_ == nullptr) {
        throw std::invalid_argument("ctx_ is nullptr");
    }
}

HashBLAKE2b::~HashBLAKE2b() {
    if (ctx_ != nullptr) {
        EVP_MD_CTX_free(ctx_);
    }
}

constexpr std::size_t HashBLAKE2b::kHashByteCount;

void HashBLAKE2b::compute(const Byte* in, std::size_t in_byte_count, Byte* out, std::size_t out_byte_count) {
    if (in_byte_count == 0 || out_byte_count == 0) {
        return;
    }
    if (in == nullptr && in_byte_count != 0) {
        throw std::invalid_argument("in is nullptr");
    }
    if (out == nullptr && out_byte_count != 0) {
        throw std::invalid_argument("out is nullptr");
    }
    if (out_byte_count > kHashByteCount) {
        throw std::invalid_argument("out_byte_count is too large");
    }
    if (EVP_DigestInit_ex(ctx_, md_, nullptr) == 0) {
        throw std::runtime_error("openssl error: EVP_DigestInit_ex " + std::to_string(ERR_get_error()));
    }
    if (EVP_DigestUpdate(ctx_, in, in_byte_count) == 0) {
        throw std::runtime_error("openssl error: EVP_DigestUpdate " + std::to_string(ERR_get_error()));
    }
    if (out_byte_count == kHashByteCount) {
        if (EVP_DigestFinal_ex(ctx_, reinterpret_cast<unsigned char*>(out), NULL) == 0) {
            throw std::runtime_error("openssl error: EVP_DigestFinal_ex " + std::to_string(ERR_get_error()));
        }
    } else {
        std::array<Byte, 32> buf_;
        if (EVP_DigestFinal_ex(ctx_, reinterpret_cast<unsigned char*>(buf_.data()), NULL) == 0) {
            throw std::runtime_error("openssl error: EVP_DigestFinal_ex " + std::to_string(ERR_get_error()));
        }
        std::copy_n(buf_.data(), out_byte_count, out);
    }
}

}  // namespace solo
}  // namespace petace
