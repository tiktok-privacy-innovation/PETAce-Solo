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

#include "solo/util/defines.h"

#ifdef SOLO_USE_IPCL

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "ipcl/ipcl.hpp"

namespace petace {
namespace solo {
namespace ahepaillier {

using SecretKey = ipcl::PrivateKey;
using PublicKey = ipcl::PublicKey;
using BigNum = BigNumber;

/**
 * @brief Provides methods to serialize Paillier cryptosystem objects.
 */
class Serialization {
public:
    /**
     * @brief Creates a serialization instance.
     *
     * @param[in] key_length The length of key in bits
     * @param[in] enable_djn Enable the Damgard-Jurik-Nielsen scheme
     * @throws std::invalid_argument if key_length is not 1024 or 2048
     */
    Serialization(std::size_t key_length, bool enable_djn = true);

    /**
     * @brief Converts a big number into an array of bytes.
     *
     * @param[in] in The big number to be converted
     * @param[out] out The pointer of byte array to write to
     * @param[out] out_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if out is nullptr
     */
    static void bn_to_bytes(const BigNum& in, Byte* out, std::size_t out_byte_count);

    /**
     * @brief Creates a big number from an array of bytes.
     *
     * @param[in] in The pointer of the byte array to read from.
     * @param[in] in_byte_count The number of bytes allocated in the byte array.
     * @param[out] out The big number to write to.
     * @throws std::invalid_argument if in is nullptr
     */
    static void bn_from_bytes(const Byte* in, std::size_t in_byte_count, BigNum& out);

    /**
     * @brief Returns the number of bytes in a public key.
     */
    std::size_t public_key_byte_count() const noexcept;

    /**
     * @brief Returns the number of bytes in a secret key.
     */
    std::size_t secret_key_byte_count() const noexcept;

    /**
     * @brief Serializes a public key into an array of bytes.
     *
     * @param[in] pk The public key to be serialized
     * @param[out] out The pointer of byte array to write to
     * @param[out] out_byte_count The number of bytes allocated in the byte array
     * @throws std::invalid_argument if pk or out is nullptr or if out_byte_count is not equal to public_key_byte_count
     */
    void serialize_public_key_to_bytes(
            const std::shared_ptr<PublicKey>& pk, Byte* out, std::size_t out_byte_count) const;

    /**
     * @brief Serializes a secret key into an array of bytes.
     *
     * @param[in] sk The secret key to be serialized
     * @param[out] out The pointer of byte array to write to
     * @param[out] out_byte_count The number of bytes allocated in the byte array
     * @throws std::invalid_argument if sk or out is nullptr or if out_byte_count is not equal to secret_key_byte_count
     */
    void serialize_secret_key_to_bytes(
            const std::shared_ptr<SecretKey>& sk, Byte* out, std::size_t out_byte_count) const;

    /**
     * @brief Creates a public key from an array of bytes.
     *
     * @param[in] in The pointer of the byte array to read from
     * @param[in] in_byte_count The number of bytes allocated in the byte array
     * @param[out] pk The public key to write to
     * @throws std::invalid_argument if in is nullptr or in_byte_count is not equal to public_key_byte_count
     */
    void deserialize_public_key_from_bytes(
            const Byte* in, std::size_t in_byte_count, std::shared_ptr<PublicKey>& pk) const;

    /**
     * @brief Creates a secret key from an array of bytes.
     *
     * @param[in] in The pointer of the byte array to read from
     * @param[in] in_byte_count The number of bytes allocated in the byte array
     * @param[out] sk The secret key to write to
     * @throws std::invalid_argument if in is nullptr or in_byte_count is not equal to secret_key_byte_count
     */
    void deserialize_secret_key_from_bytes(
            const Byte* in, std::size_t in_byte_count, std::shared_ptr<SecretKey>& sk) const;

private:
    std::size_t key_length_ = 0;
    std::size_t n_byte_count_ = 0;
    bool enable_djn_ = false;
};

/**
 * @brief An array of plaintexts in Paillier cryptosystem.
 */
class Plaintext : public ipcl::PlainText {
public:
    /**
     * @brief Default constructor.
     */
    Plaintext() = default;

    /**
     * @brief Constructs a Plaintext from a vector of BigNumber elements.
     *
     * @param[in] bn_v The vector of BigNumber elements
     */
    explicit Plaintext(const std::vector<BigNumber>& bn_v) : ipcl::PlainText(bn_v) {
    }

    /**
     * @brief Copies a Plaintext from an ipcl::PlainText.
     *
     * @param[in] other The ipcl::PlainText to copy from
     */
    Plaintext& operator=(const ipcl::PlainText& other) noexcept;

    /**
     * @brief Converts a Plaintext into a vector of BigNumber elements.
     */
    operator std::vector<BigNumber>() const;

    /**
     * @brief Returns the number of plaintexts stored in this Plaintext.
     */
    std::size_t slot_count() const noexcept;
};

/**
 * @brief An array of ciphertexts in Paillier cryptosystem.
 */
class Ciphertext : public ipcl::CipherText {
public:
    /**
     * @brief Default constructor.
     */
    Ciphertext() = default;

    /**
     * @brief Constructs a Ciphertext from a vector of BigNumber elements and a public key.
     *
     * @param[in] pk The public key
     * @param[in] bn_vec The vector of BigNumber elements
     */
    explicit Ciphertext(const PublicKey& pk, const std::vector<BigNumber>& bn_vec) : ipcl::CipherText(pk, bn_vec) {
    }

    /**
     * @brief Copies a Ciphertext from an ipcl::CipherText.
     *
     * @param[in] other The ipcl::CipherText to copy from
     */
    Ciphertext& operator=(const ipcl::CipherText& other) noexcept;

    /**
     * @brief Converts a Ciphertext into a vector of BigNumber elements.
     */
    operator std::vector<BigNumber>() const;

    /**
     * @brief Returns the number of ciphertexts stored in this Ciphertext.
     */
    std::size_t slot_count() const noexcept;
};

/**
 * @brief Provides methods to encode/decode one or multiple integers to/from a Plaintext.
 */
class Encoder {
public:
    /**
     * @brief Default constructor.
     */
    Encoder() {
    }

    /**
     * @brief Encodes one integer to a Plaintext.
     *
     * @param[in] in The integer
     * @param[out] out The Plaintext to write to
     */
    void encode(std::uint64_t in, Plaintext& out) const noexcept;

    /**
     * @brief Returns the integer decoded from a Plaintext.
     *
     * @param[in] in The Plaintext
     */
    std::uint64_t decode(const Plaintext& in) const noexcept;

    /**
     * @brief Encodes a vector of integers to a Plaintext.
     *
     * @param[in] in The integer vector
     * @param[out] out The Plaintext to write to
     */
    void encode(const std::vector<std::uint64_t>& in, Plaintext& out) const noexcept;

    /**
     * @brief Decodes a vector of integers from a Plaintext.
     *
     * @param[in] in The Plaintext
     * @param[out] out The integer vector to write to
     */
    void decode(const Plaintext& in, std::vector<std::uint64_t>& out) const noexcept;
};

/**
 * @brief Provides methods to generate keys.
 */
class KeyGenerator {
public:
    /**
     * @brief Constructs a key generator for a given key length.
     *
     * @param[in] key_length The key length in bits
     * @throws std::invalid_argument if key_length is less than 1024 or greater than 2048
     */
    explicit KeyGenerator(std::size_t key_length) : key_length_(key_length) {
        if (key_length < 1024) {
            throw std::invalid_argument("key length is less than 1024");
        }
        if (key_length > 2048) {
            throw std::invalid_argument("key length is greater than 2048");
        }
    }

    /**
     * @brief Creates a pair of keys.
     *
     * @param[out] sk The secret key
     * @param[out] pk The public key
     * @param[in] enable_djn Enable the Damgard-Jurik-Nielsen scheme
     */
    void get_key_pair(
            std::shared_ptr<SecretKey>& sk, std::shared_ptr<PublicKey>& pk, bool enable_djn = true) const noexcept;

private:
    std::size_t key_length_ = 0;
};

/**
 * @brief Provides methods that encrypt a plaintext into a ciphertext.
 */
class Encryptor {
public:
    /**
     * @brief Constructs an encryptor with a public key.
     *
     * @param[in] pk The public key
     * @param[in] enable_djn
     * @throws std::invalid_argument if pk is nullptr
     */
    explicit Encryptor(const std::shared_ptr<PublicKey>& pk, bool enable_djn = true);

    /**
     * @brief Encrypts a plaintext into a ciphertext.
     *
     * @param[in] in The plaintext
     * @param[out] out The resulting ciphertext
     */
    void encrypt(const Plaintext& in, Ciphertext& out) const noexcept;

private:
    std::shared_ptr<PublicKey> pk_ = nullptr;
};

/**
 * @brief Provides methods that decrypt a ciphertext into a plaintext.
 */
class Decryptor {
public:
    /**
     * @brief Constructs an decryptor with a secret key.
     *
     * @param[in] sk The secret key
     * @throws std::invalid_argument if sk is nullptr
     */
    explicit Decryptor(const std::shared_ptr<SecretKey>& sk);

    /**
     * @brief Decrypts a ciphertext into a plaintext.
     *
     * @param[in] in The ciphertext
     * @param[out] out The resulting plaintext
     */
    void decrypt(const Ciphertext& in, Plaintext& out) const noexcept;

private:
    std::shared_ptr<SecretKey> sk_ = nullptr;
};

/**
 * @brief Provides methods that evaluates arithmetic operations on ciphertexts.
 */
class Evaluator {
public:
    /**
     * @brief Default constructor.
     */
    Evaluator() {
    }

    /**
     * @brief Addition of two ciphertexts.
     *
     * @param[in] in_0 The first ciphertext to add
     * @param[in] in_1 The second ciphertext to add
     * @param[out] out The ciphertext to overwrite with the addition result
     */
    void add(const Ciphertext& in_0, const Ciphertext& in_1, Ciphertext& out) const noexcept;

    /**
     * @brief Addition of a ciphertext and a plaintext.
     *
     * @param[in] in_0 The ciphertext to add
     * @param[in] in_1 The plaintext to add
     * @param[out] out The ciphertext to overwrite with the addition result
     */
    void add(const Ciphertext& in_0, const Plaintext& in_1, Ciphertext& out) const noexcept;

    /**
     * @brief Multiplication of a ciphertext and a plaintext.
     *
     * @param[in] in_0 The ciphertext to multiply
     * @param[in] in_1 The plaintext to multiply
     * @param[out] out The ciphertext to overwrite with the multiplication result
     */
    void mul(const Ciphertext& in_0, const Plaintext& in_1, Ciphertext& out) const noexcept;
};

namespace utils {
/**
 * @brief Shifts a BigNum to the left.
 *
 * @param[in] in The BigNum
 * @param[in] bits The offset
 */
void bn_lshift(BigNum& in, std::size_t bits);

/**
 * @brief Returns a random BigNum.
 *
 * @param[in] bits The bitsize of the random BigNum
 */
BigNum get_random_bn(std::size_t bits);
}  // namespace utils

}  // namespace ahepaillier
}  // namespace solo
}  // namespace petace
#endif
