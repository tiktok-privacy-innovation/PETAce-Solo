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

#include "solo/util/config.h"
#ifdef SOLO_USE_AES_INTRIN
#include "solo/util/aes_ecb_ctr.h"
#endif
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <vector>

#include "solo/util/defines.h"

namespace petace {
namespace solo {

/**
 * @brief Describes the pseudorandom number generator algorithm to use.
 */
enum class PRNGScheme : std::uint8_t {
    SHAKE_128 = 0,
    BLAKE2Xb = 1,
#ifdef SOLO_USE_AES_INTRIN
    AES_ECB_CTR = 2
#endif
};

/**
 * @brief Provides the base class for a pseudorandom number generator.
 */
class PRNG {
public:
    PRNG() = delete;

    /**
     * @brief Constructs a pseudorandom number generator and set the byte size of a seed and refill buffer.
     *
     * @param[in] seed_byte_count The byte size of a seed.
     * @param[in] buffer_byte_count The byte size of the refill buffer.
     * @throws std::invalid_argument if either input is zero.
     */
    explicit PRNG(std::size_t seed_byte_count = 16, std::size_t buffer_byte_count = 512);

    /**
     * @brief Constructs a pseudorandom number generator and set a seed and the byte size of refill buffer.
     *
     * @param[in] seed The seed for the random number generator.
     * @param[in] buffer_byte_count The byte size of the refill buffer.
     * @throws std::invalid_argument if the byte size of the refill buffer is zero or if the seed is empty.
     */
    explicit PRNG(const std::vector<Byte>& seed, std::size_t buffer_byte_count = 512);

    virtual ~PRNG() = default;

    /**
     * @brief Generate a requested number of bytes of randomness to a given buffer.
     *
     * @param[in] out_byte_count The number of bytes of randomness requested.
     * @param[out] out The buffer that stores the generated randomness.
     * @throws std::invalid_argument if non-zero number of bytes is requested and the buffer is nullptr.
     */
    void generate(std::size_t out_byte_count, Byte* out);

    /**
     * @brief Returns the byte size of the seed.
     */
    SOLO_NODISCARD std::size_t seed_byte_count() const noexcept {
        return seed_.size();
    }

    /**
     * @brief Returns the seed.
     */
    SOLO_NODISCARD const std::vector<Byte>& seed() const noexcept {
        return seed_;
    }

    /**
     * @brief Obtain a given number of bytes of randomness from /dev/urandom and store them in a given buffer.
     *
     * @param[in] out_byte_count The number of bytes of randomness requested.
     * @param[out] out The buffer that stores the generated randomness.
     * @throws std::invalid_argument if non-zero number of bytes is requested and the buffer is nullptr.
     */
    static void get_random_byte_array(std::size_t out_byte_count, Byte* out);

protected:
    virtual void refill_buffer() = 0;

    SOLO_NODISCARD std::size_t buffer_byte_count() noexcept {
        return buffer_.size();
    }

    std::vector<Byte> seed_{};

    std::vector<Byte> buffer_{};

    std::vector<Byte>::iterator buffer_head_;

    std::uint64_t counter_ = 0;
};

/**
 * @brief Wraps a PRNG object as a randomness source in C++ standard random number generators.
 */
class PRNGStandard {
public:
    using result_type = std::uint64_t;

    /**
    Creates a new PRNGStandard from a PRNG.

    @param[in] prng A PRNG.
    @throws std::invalid_argument if prng is nullptr.
    */
    PRNGStandard(std::shared_ptr<PRNG> prng) : prng_(prng) {
        if (prng_ == nullptr) {
            throw std::invalid_argument("prng is nullptr");
        }
    }

    /**
    @brief Returns the smallest possible output value.
    */
    SOLO_NODISCARD inline static constexpr result_type min() noexcept {
        return std::numeric_limits<result_type>::min();
    }

    /**
    @brief Returns the largest possible output value.
    */
    SOLO_NODISCARD static constexpr result_type max() noexcept {
        return std::numeric_limits<result_type>::max();
    }

    /**
    @brief Returns a new random number.
    */
    SOLO_NODISCARD result_type operator()() {
        result_type out;
        prng_->generate(sizeof(out), reinterpret_cast<Byte*>(&out));
        return out;
    }

private:
    std::shared_ptr<PRNG> prng_;
};

template <PRNGScheme scheme>
class PRNGImpl : public PRNG {
public:
    explicit PRNGImpl(std::size_t seed_byte_count = 16, std::size_t buffer_byte_count = 512)
            : PRNG(seed_byte_count, buffer_byte_count) {
    }

    explicit PRNGImpl(const std::vector<Byte>& seed, std::size_t buffer_byte_count = 512)
            : PRNG(seed, buffer_byte_count) {
    }

    ~PRNGImpl() = default;

protected:
    void refill_buffer() override;
};

/**
 * @brief Implements a PRNG factory.
 */
class PRNGFactory {
public:
    /**
     * @brief Creates a PRNG factory from the algorithm chosen and a seed's byte size.
     *
     * @param[in] scheme A PRNG algorithm.
     * @param[in] seed_byte_count The byte size of a seed.
     * @throws std::invalid_argument if the byte size of a seed is zero or if the algorithm is not supported.
     * @throws std::invalid_argument if AES_ECB_CTR is chosen and the byte size of a seed is not 16.
     */
    explicit PRNGFactory(PRNGScheme scheme, std::size_t seed_byte_count = 16);

    /**
     * @brief Creates a shared pointer of a PRNG from a refill buffer's byte size.
     *
     * @param[in] buffer_byte_count The byte size of a refill buffer.
     * @throws std::invalid_argument if the refill buffer's byte size is zero.
     */
    SOLO_NODISCARD std::shared_ptr<PRNG> create(std::size_t buffer_byte_count = 512);

    /**
     * @brief Creates a shared pointer of a PRNG from a given seed and a refill buffer's byte size.
     *
     * @param[in] seed The seed of PRNG.
     * @param[in] buffer_byte_count The byte size of a refill buffer.
     * @throws std::invalid_argument if the given seed's byte size does not match the factory's seed's byte size or if
     * the refill buffer's byte size is zero.
     */
    SOLO_NODISCARD std::shared_ptr<PRNG> create(const std::vector<Byte>& seed, std::size_t buffer_byte_count = 512);

private:
    PRNGScheme scheme_;

    std::size_t seed_byte_count_ = 0;

#ifdef SOLO_DEBUG
public:
    PRNGFactory(PRNGScheme scheme, const std::vector<Byte>& seed);

private:
    bool use_fixed_seed_ = false;

    std::vector<Byte> fixed_seed_{};
#endif
};

}  // namespace solo
}  // namespace petace
