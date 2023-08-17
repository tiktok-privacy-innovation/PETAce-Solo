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

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "openssl/evp.h"

#include "solo/util/defines.h"

namespace petace {
namespace solo {

/**
 * @brief Describes the hash algorithm to use.
 */
enum class HashScheme : std::uint8_t { SHA_256 = 0, SHA3_256 = 3, BLAKE2b = 6 };

/**
 * @brief Provides the base class for a hash function.
 */
class Hash {
public:
    Hash() = default;

    virtual ~Hash() = default;

    /**
     * @brief Create a shared pointer of a hash function from the algorithm chosen.
     *
     * @param[in] scheme A hash algorithm.
     * @throws std::invalid_argument if the algorithm is not supported.
     */
    SOLO_NODISCARD static std::shared_ptr<Hash> create(HashScheme scheme);

    virtual std::size_t hash_byte_count() const = 0;

    virtual void compute(const Byte* in, std::size_t in_byte_count, Byte* out, std::size_t out_byte_count) = 0;

    /**
     * @brief Compute the hash of an input byte array without truncating the hash.
     *
     * @param[in] in The pointer of the input byte array.
     * @param[in] in_byte_count The number of bytes in the input byte array.
     * @param[out] out The pointer of the output byte array.
     * @throws std::invalid_argumment if either in or out is nullptr with non-zero byte count.
     */
    void compute(const Byte* in, std::size_t in_byte_count, Byte* out) {
        compute(in, in_byte_count, out, hash_byte_count());
    }
};

/**
 * @brief Provides the base class for a hash function factory.
 */
class HashFactory {
public:
    virtual ~HashFactory() = default;

    /**
     * @brief Creates a shared pointer of a hash function factory from the algorithm chosen.
     *
     * A hash function factory is designed to provide keyed hash functions in a future release.
     *
     * @param[in] scheme A hash algorithm.
     * @throws std::invalid_argument if the algorithm is not supported.
     */
    SOLO_NODISCARD static std::shared_ptr<HashFactory> create_factory(HashScheme scheme);

    /**
     * @brief Creates a shared pointer of a hash function from the algorithm chosen.
     *
     * @param[in] scheme A hash algorithm.
     * @throws std::invalid_argument if the algorithm is not supported.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    SOLO_NODISCARD std::shared_ptr<Hash> create(HashScheme scheme) {
        return Hash::create(scheme);
    }

    SOLO_NODISCARD virtual std::shared_ptr<Hash> create() = 0;
};

/**
 * @brief Implements a SHA-256 hash function.
 */
class HashSHA_256 : public Hash {
public:
    HashSHA_256();

    ~HashSHA_256();

    /**
     * @brief The default number of bytes in a SHA-256 hash.
     */
    static constexpr std::size_t kHashByteCount = 32;

    /**
     * @brief Creates a shared pointer of a SHA-256 hash function.
     */
    SOLO_NODISCARD static std::shared_ptr<Hash> create() {
        return std::make_shared<HashSHA_256>();
    }

    /**
     * @brief Returns the default number of bytes in a SHA-256 hash.
     */
    std::size_t hash_byte_count() const override {
        return kHashByteCount;
    }

    /**
     * @brief Compute the SHA-256 hash of an input byte array and truncate output to out_byte_count bytes.
     *
     * @param[in] in The pointer of the input byte array.
     * @param[in] in_byte_count The number of bytes in the input byte array.
     * @param[out] out The pointer of the output byte array.
     * @param[in] out_byte_count The number of bytes expected in the out byte array.
     * @throws std::invalid_argumment if either in or out is nullptr with non-zero byte count or if out_byte_count is
     * larger than kHashByteCount.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void compute(const Byte* in, std::size_t in_byte_count, Byte* out, std::size_t out_byte_count) override;

private:
    EVP_MD_CTX* ctx_;
    const EVP_MD* md_;
};

/**
 * @brief Implements a SHA-256 hash function factory.
 */
class HashFactorySHA_256 : public HashFactory {
public:
    /**
     * @brief Creates a shared pointer of a SHA-256 hash function.
     */
    SOLO_NODISCARD std::shared_ptr<Hash> create() override {
        return HashSHA_256::create();
    }
};

/**
 * @brief Implements a SHA3-256 hash function.
 */
class HashSHA3_256 : public Hash {
public:
    HashSHA3_256();

    ~HashSHA3_256();

    /**
     * @brief The default number of bytes in a SHA3-256 hash.
     */
    static constexpr std::size_t kHashByteCount = 32;

    /**
     * @brief Creates a shared pointer of a SHA3-256 hash function.
     */
    SOLO_NODISCARD static std::shared_ptr<Hash> create() {
        return std::make_shared<HashSHA3_256>();
    }

    /**
     * @brief Returns the default number of bytes in a SHA3-256 hash.
     */
    std::size_t hash_byte_count() const override {
        return kHashByteCount;
    }

    /**
     * @brief Compute the SHA3-256 hash of an input byte array and truncate output to out_byte_count bytes.
     *
     * @param[in] in The pointer of the input byte array.
     * @param[in] in_byte_count The number of bytes in the input byte array.
     * @param[out] out The pointer of the output byte array.
     * @param[in] out_byte_count The number of bytes expected in the out byte array.
     * @throws std::invalid_argumment if either in or out is nullptr with non-zero byte count or if out_byte_count is
     * larger than kHashByteCount.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void compute(const Byte* in, std::size_t in_byte_count, Byte* out, std::size_t out_byte_count) override;

private:
    EVP_MD_CTX* ctx_;
    const EVP_MD* md_;
};

/**
 * @brief Implements a SHA3-256 hash function factory.
 */
class HashFactorySHA3_256 : public HashFactory {
public:
    /**
     * @brief Creates a shared pointer of a SHA3-256 hash function.
     */
    SOLO_NODISCARD std::shared_ptr<Hash> create() override {
        return HashSHA3_256::create();
    }
};

/**
 * @brief Implements a BLAKE2b hash function.
 */
class HashBLAKE2b : public Hash {
public:
    HashBLAKE2b();

    ~HashBLAKE2b();

    /**
     * @brief The default number of bytes in a BLAKE2b hash.
     */
    static constexpr std::size_t kHashByteCount = 64;

    /**
     * @brief Creates a shared pointer of a BLAKE2b hash function.
     */
    SOLO_NODISCARD static std::shared_ptr<Hash> create() {
        return std::make_shared<HashBLAKE2b>();
    }

    /**
     * @brief Returns the default number of bytes in a BLAKE2b hash.
     */
    std::size_t hash_byte_count() const override {
        return kHashByteCount;
    }

    /**
     * @brief Compute the BLAKE2b hash of an input byte array and truncate output to out_byte_count bytes.
     *
     * @param[in] in The pointer of the input byte array.
     * @param[in] in_byte_count The number of bytes in the input byte array.
     * @param[out] out The pointer of the output byte array.
     * @param[in] out_byte_count The number of bytes expected in the out byte array.
     * @throws std::invalid_argumment if either in or out is nullptr with non-zero byte count or if out_byte_count is
     * larger than kHashByteCount.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void compute(const Byte* in, std::size_t in_byte_count, Byte* out, std::size_t out_byte_count) override;

private:
    EVP_MD_CTX* ctx_;
    const EVP_MD* md_;
};

/**
 * @brief Implements a BLAKE2b hash function factory.
 */
class HashFactoryBLAKE2b : public HashFactory {
public:
    /**
     * @brief Creates a shared pointer of a BLAKE2b hash function.
     */
    SOLO_NODISCARD std::shared_ptr<Hash> create() override {
        return HashBLAKE2b::create();
    }
};

}  // namespace solo
}  // namespace petace
