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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "solo/prng.h"
#include "solo/util/defines.h"

#ifdef SOLO_USE_IPCL
#include "ipcl/ipcl.hpp"
#else
#include <emmintrin.h>
#include <wmmintrin.h>

#include "gmp.h"
#include "gmpxx.h"
#endif

namespace petace {
namespace solo {
namespace ahepaillier {

/**
 * @brief PublicKey in the Paillier cryptosystem.
 */
class PublicKey {
public:
    /**
     * @brief Constructs an empty public key that can be later deserialized into.
     *
     * @param[in] key_length The length of key in bits.
     * @param[in] enable_djn Enable the Damgard-Jurik-Nielsen scheme.
     * @throws std::invalid_argument if key_length is not 1024 or 2048.
     */
    PublicKey(std::size_t key_length, bool enable_djn);

    /**
     * @brief Default constructor is deleted.
     */
    PublicKey() = delete;

#ifdef SOLO_USE_IPCL
    /**
     * @brief Constructs a public key in IPCL.
     *
     * @param[in] pk  public key in IPCL.
     * @throws std::invalid_argument if key_length is not 1024 or 2048.
     */
    explicit PublicKey(const ipcl::PublicKey& pk);
#else
    /**
     * @brief Constructs a public key with n, where n is an admissible RSA modulus n = pq.
     *
     * @param[in] n  n of public key in the Paillier scheme.
     * @throws std::invalid_argument if key_length is not 1024 or 2048.
     */
    explicit PublicKey(const mpz_class& n);

    /**
     * @brief Constructs a public key with n and hs.
     *
     * @param[in] n  n of public key in the Paillier scheme.
     * @param[in] hs hs of public key in the Damgard-Jurik-Nielsen Paillier scheme.
     * @throws std::invalid_argument if n is not 1024-bit or 2048-bit
     */
    PublicKey(const mpz_class& n, const mpz_class& hs);
#endif
    /**
     * @brief Serializes public key into an array of bytes.
     *
     * @param[out] out The pointer of byte array to write to.
     * @param[out] out_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if this public key is not set or out is nullptr or out_byte_count is not equal
     * to the number of bytes in this public key.
     */
    void serialize_to_bytes(Byte* out, std::size_t out_byte_count) const;

    /**
     * @brief Creates public key from an array of bytes.
     *
     * @param[in] in The pointer of the byte array to read from.
     * @param[in] in_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if this public key is set or in is nullptr or in_byte_count is not equal to
     * the number of bytes in this public key.
     */
    void deserialize_from_bytes(const Byte* in, std::size_t in_byte_count);

    /**
     * @brief Returns the number of bytes in a public key.
     */
    std::size_t public_key_byte_count() const noexcept;

    /**
     * @brief Returns the length of key in bits.
     */
    std::size_t key_length() const {
        return key_length_;
    }

    /**
     * @brief Returns enabled djn or not.
     */
    bool use_djn() const {
        return enable_djn_;
    }

#ifdef SOLO_USE_IPCL
    /**
     * @brief Returns the the pointer of pk.
     */
    std::shared_ptr<ipcl::PublicKey> pk() const {
        return pk_;
    }
#else
    /**
     * @brief Returns n of public key.
     */
    const mpz_class& n() const {
        return n_;
    }

    /**
     * @brief Returns generator of public key.
     */
    const mpz_class& g() const {
        return g_;
    }

    /**
     * @brief Returns n_square of public key.
     */
    const mpz_class& n_square() const {
        return n_square_;
    }

    /**
     * @brief Returns hs of public key.
     */
    const mpz_class& hs() const {
        return hs_;
    }
#endif

private:
#ifdef SOLO_USE_IPCL
    std::shared_ptr<ipcl::PublicKey> pk_ = nullptr;
#else
    mpz_class n_ = 0;
    mpz_class g_ = 0;
    mpz_class n_square_ = 0;
    mpz_class hs_ = 0;
#endif
    std::size_t key_length_ = 0;
    std::size_t n_byte_count_ = 0;
    const bool enable_djn_;
    bool pk_set_ = false;
};

/**
 * @brief SecretKey in the Paillier cryptosystem.
 */
class SecretKey {
public:
    /**
     * @brief Constructs an empty secret key that can be later deserialized into.
     *
     * @param[in] key_length The length of key in bits.
     */
    explicit SecretKey(std::size_t key_length);

    /**
     * @brief Default constructor is deleted.
     */
    SecretKey() = delete;

#ifdef SOLO_USE_IPCL
    /**
     * @brief Constructs a secret key in IPCL.
     *
     * @param[in] sk  secret key in IPCL.
     */
    explicit SecretKey(const ipcl::PrivateKey& sk);
#else
    /**
     * @brief Constructs a secret key with (n, p, q), where n is an admissible RSA modulus n = pq,  p, q are large odd
     * primes.
     *
     * @param[in] n  n of secret key in the Paillier scheme.
     * @param[in] p  p of secret key in the Paillier scheme.
     * @param[in] q  q of secret key in the Paillier scheme.
     * @throws std::invalid_argument if key_length is not 1024 or 2048.
     */
    SecretKey(const mpz_class& n, const mpz_class& p, const mpz_class& q);
#endif
    /**
     * @brief Serializes secret key into an array of bytes.
     *
     * @param[out] out The pointer of byte array to write to.
     * @param[out] out_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if this secret key is not set or out is nullptr orout_byte_count is not equal to
     * the number of bytes in this secret key.
     */
    void serialize_to_bytes(Byte* out, std::size_t out_byte_count) const;

    /**
     * @brief Creates secret key from an array of bytes.
     *
     * @param[in] in The pointer of the byte array to read from.
     * @param[in] in_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if this secret key is set or in is nullptr or in_byte_count is not equal to
     * the number of bytes in this secret key.
     */
    void deserialize_from_bytes(const Byte* in, std::size_t in_byte_count);

    /**
     * @brief Returns the number of bytes in a secret key.
     */
    std::size_t secret_key_byte_count() const noexcept;

    /**
     * @brief Returns the length of key in bits.
     */
    std::size_t key_length() const {
        return key_length_;
    }
#ifdef SOLO_USE_IPCL
    /**
     * @brief Returns the the pointer of sk.
     */
    std::shared_ptr<ipcl::PrivateKey> sk() const {
        return sk_;
    }
#else
    /**
     * @brief Decrypts a ciphertext.
     *
     * @param[in] in The ciphertext.
     * @param[in] out The decrypted result.
     */
    void decrypt(const mpz_class& in, mpz_class& out) const;

    /**
     * @brief Calculates base^exponent mod n^2 with CRT optimization.
     *
     * @param[in] base The base.
     * @param[in] exponent The exponent.
     * @param[in] out The result.
     */
    void powm_crt(const mpz_class& base, const mpz_class& exponent, mpz_class& out) const;

    /**
     * @brief Returns n of secret key.
     */
    const mpz_class& n() const {
        return n_;
    }

    /**
     * @brief Returns generator of secret key.
     */
    const mpz_class& g() const {
        return g_;
    }

    /**
     * @brief Returns n_square of secret key.
     */
    const mpz_class& n_square() const {
        return n_square_;
    }
#endif

private:
#ifdef SOLO_USE_IPCL
    std::shared_ptr<ipcl::PrivateKey> sk_ = nullptr;
#else
    void initilize_sk();

    mpz_class n_ = 0;
    mpz_class g_ = 0;
    mpz_class n_square_ = 0;

    mpz_class lambda_ = 0;
    mpz_class p_ = 0;
    mpz_class q_ = 0;
    mpz_class p_square_ = 0;
    mpz_class q_square_ = 0;

    mpz_class p_square_inv_ = 0;
    mpz_class q_square_inv_ = 0;

    mpz_class p_inv_ = 0;
    mpz_class q_inv_ = 0;

    mpz_class hp_ = 0;
    mpz_class hq_ = 0;
#endif
    std::size_t key_length_ = 0;
    std::size_t n_byte_count_ = 0;
    bool sk_set_ = false;
};

/**
 * @brief Provides methods to serialize big number objects.
 */
class Serialization {
public:
#ifdef SOLO_USE_IPCL
    /**
     * @brief Converts a big number into an array of bytes.
     *
     * @param[in] in The big number to be converted.
     * @param[out] out The pointer of byte array to write to.
     * @param[out] out_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if out is nullptr.
     */
    static void ipcl_bn_to_bytes(const BigNumber& in, Byte* out, std::size_t out_byte_count);

    /**
     * @brief Creates a big number from an array of bytes.
     *
     * @param[in] in The pointer of the byte array to read from.
     * @param[in] in_byte_count The number of bytes allocated in the byte array.
     * @param[out] out The big number to write to.
     * @throws std::invalid_argument if in is nullptr.
     */
    static void ipcl_bn_from_bytes(const Byte* in, std::size_t in_byte_count, BigNumber& out);
#else
    /**
     * @brief Converts a big number into an array of bytes.
     *
     * @param[in] in The big number to be converted.
     * @param[out] out The pointer of byte array to write to.
     * @param[out] out_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if out is nullptr.
     */
    static void mpz_bn_to_bytes(const mpz_class& in, Byte* out, std::size_t out_byte_count);
    /**
     * @brief Creates a big number from an array of bytes.
     *
     * @param[in] in The pointer of the byte array to read from.
     * @param[in] in_byte_count The number of bytes allocated in the byte array.
     * @param[out] out The big number to write to.
     * @throws std::invalid_argument if in is nullptr.
     */
    static void mpz_bn_from_bytes(const Byte* in, std::size_t in_byte_count, mpz_class& out);
#endif
};

/**
 * @brief Plaintext in the Paillier cryptosystem.
 */
class Plaintext {
public:
    /**
     * @brief Default constructor.
     */
    Plaintext() = default;

#ifdef SOLO_USE_IPCL
    /**
     * @brief Constructs a Plaintext from a BigNumber element.
     *
     * @param[in] bn BigNumber element.
     */
    explicit Plaintext(const BigNumber& bn) : pt_(bn) {
    }
#else
    /**
     * @brief Constructs a Plaintext from a mpz_class element.
     *
     * @param[in] bn  mpz_class element.
     */
    explicit Plaintext(const mpz_class& bn) : pt_(bn) {
    }
#endif

    /**
     * @brief Serializes plaintext into an array of bytes.
     *
     * @param[out] out The pointer of byte array to write to.
     * @param[out] out_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if out is nullptr.
     */
    void serialize_to_bytes(Byte* out, std::size_t out_byte_count) const;

    /**
     * @brief Creates plaintext from an array of bytes.
     *
     * @param[in] in The pointer of the byte array to read from.
     * @param[in] in_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if in is nullptr.
     */
    void deserialize_from_bytes(const Byte* in, std::size_t in_byte_count);

    /**
     * @brief Copies a Plaintext from an Plaintext.
     *
     * @param[in] other The Plaintext to copy from
     */
    Plaintext& operator=(const Plaintext& other) noexcept;

#ifdef SOLO_USE_IPCL
    /**
     * @brief Converts a Plaintext into a BigNumber element.
     */
    operator ipcl::PlainText() const;
#else
    /**
     * @brief Converts a Plaintext into a mpz_class element.
     */
    operator mpz_class() const;
#endif

private:
#ifdef SOLO_USE_IPCL
    ipcl::PlainText pt_;
#else
    mpz_class pt_ = 0;
#endif
};

/**
 * @brief Ciphertext in the Paillier cryptosystem.
 */
class Ciphertext {
public:
    /**
     * @brief Default constructor.
     */
    Ciphertext() = default;
#ifdef SOLO_USE_IPCL
    /**
     * @brief Constructs a Ciphertext from a BigNumber element and a public key.
     *
     * @param[in] pk The public key.
     * @param[in] bn BigNumber element.
     */
    Ciphertext(const ipcl::PublicKey& pk, const BigNumber& bn) : ct_(pk, bn) {
    }

    /**
     * @brief Constructs a Ciphertext from a ipcl::CipherText.
     *
     * @param[in] ct ipcl::CipherText.
     */
    explicit Ciphertext(const ipcl::CipherText ct) : ct_(ct) {
    }
#else
    /**
     * @brief Constructs a Ciphertext from a mpz_class element.
     *
     * @param[in] bn mpz_class element.
     */
    explicit Ciphertext(const mpz_class& bn) : ct_(bn) {
    }
#endif

    /**
     * @brief Serializes the big number of ciphertext into an array of bytes.
     *
     * @param[out] out The pointer of byte array to write to.
     * @param[out] out_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if out is nullptr.
     */
    void serialize_to_bytes(Byte* out, std::size_t out_byte_count) const;

    /**
     * @brief Creates ciphertext from public key and an array of bytes.
     *
     * @param[in] pk The public key.
     * @param[in] in The pointer of the byte array to read from.
     * @param[in] in_byte_count The number of bytes allocated in the byte array.
     * @throws std::invalid_argument if in is nullptr or pk is nullptr.
     */
    void deserialize_from_bytes(const std::shared_ptr<PublicKey>& pk, Byte* in, std::size_t in_byte_count);

    /**
     * @brief Copies a Ciphertext from a Ciphertext.
     *
     * @param[in] other The Ciphertext to copy from.
     */
    Ciphertext& operator=(const Ciphertext& other) noexcept;

#ifdef SOLO_USE_IPCL
    /**
     * @brief Converts a Ciphertext into a ipcl::CipherText.
     */
    operator ipcl::CipherText() const;
#else
    /**
     * @brief Converts a Ciphertext into a mpz_class element.
     */
    operator mpz_class() const;
#endif

private:
#ifdef SOLO_USE_IPCL
    ipcl::CipherText ct_;
#else
    mpz_class ct_ = 0;
#endif
};

/**
 * @brief Provides methods to encode/decode integer to/from Plaintext.
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
     * @param[in] in The integer.
     * @param[out] out The Plaintext to write to.
     */
    void encode(std::uint64_t in, Plaintext& out) const noexcept;

    /**
     * @brief Returns the integer decoded from a Plaintext.
     *
     * @param[in] in The Plaintext.
     */
    std::uint64_t decode(const Plaintext& in) const noexcept;

    /**
     * @brief Encodes a vector of integers to a vector of Plaintexts.
     *
     * @param[in] in The vector of integers.
     * @param[out] out The vector of Plaintexts to write to.
     */
    void encode(const std::vector<std::uint64_t>& in, std::vector<Plaintext>& out) const noexcept;

    /**
     * @brief Decodes a vector of integers from a vector of Plaintexts.
     *
     * @param[in] in The vector of Plaintexts.
     * @param[out] out The vector of integers to write to.
     */
    void decode(const std::vector<Plaintext>& in, std::vector<std::uint64_t>& out) const noexcept;
};

/**
 * @brief Provides methods to generate keys.
 */
class KeyGenerator {
public:
    /**
     * @brief Constructs a key generator for a given key length.
     *
     * @param[in] key_length The key length in bits.
     * @throws std::invalid_argument if key_length is less than 1024 or greater than 2048.
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
     * @param[out] sk The secret key.
     * @param[out] pk The public key.
     * @param[in] enable_djn Enable the Damgard-Jurik-Nielsen scheme.
     * @param[in] prng_scheme The prng scheme to decide which pseudorandom number generator to use. If SOLO_USE_IPCL is
     * ON, this parameter is ignored.
     */
    void get_key_pair(std::shared_ptr<SecretKey>& sk, std::shared_ptr<PublicKey>& pk, bool enable_djn = true,
            PRNGScheme prng_scheme = PRNGScheme::BLAKE2Xb) const noexcept;

private:
#ifndef SOLO_USE_IPCL
    static mpz_class generate_prime(std::size_t bit_count, std::shared_ptr<PRNG>& prng);

    static int prime_test(const mpz_class& in);

    static std::size_t miller_rabin_iteration_num(std::size_t prime_length);
#endif
    std::size_t key_length_ = 0;
};

/**
 * @brief Provides methods that encrypt plaintexts into ciphertexts.
 */
class Encryptor {
public:
    /**
     * @brief Constructs an encryptor with a public key.
     *
     * @param[in] pk The public key.
     * @param[in] prng_scheme The prng scheme to decide which pseudorandom number generator to use. If SOLO_USE_IPCL is
     * ON, this parameter is ignored.
     * @throws std::invalid_argument if pk is nullptr.
     */
    explicit Encryptor(const std::shared_ptr<PublicKey>& pk, PRNGScheme prng_scheme = PRNGScheme::BLAKE2Xb);

    /**
     * @brief Constructs an encryptor with a public key and a secret key.
     *
     *  Adding a secret key can accelerate encryption.
     *
     * @param[in] pk The public key.
     * @param[in] sk The secret key.
     * @param[in] prng_scheme The prng scheme to decide which pseudorandom number generator to use. If SOLO_USE_IPCL is
     * ON, this parameter is ignored.
     * @throws std::invalid_argument if pk is nullptr or sk is nullptr.
     */
    explicit Encryptor(const std::shared_ptr<PublicKey>& pk, const std::shared_ptr<SecretKey>& sk,
            PRNGScheme prng_scheme = PRNGScheme::BLAKE2Xb);

    /**
     * @brief Default constructor is deleted.
     */
    Encryptor() = delete;

    /**
     * @brief Encrypts a plaintext into a ciphertext.
     *
     * @param[in] in The plaintext.
     * @param[out] out The resulting ciphertext.
     */
    void encrypt(const Plaintext& in, Ciphertext& out) noexcept;

    /**
     * @brief Encrypts a vector of plaintexts into a vector of ciphertexts.
     *
     * @param[in] in The vector of plaintexts.
     * @param[in] num_threads The number of threads utilized to execute this function. If SOLO_USE_IPCL is ON, this
     * parameter is ignored.
     * @param[out] out The vector of resulting ciphertexts.
     */
    void encrypt_many(
            const std::vector<Plaintext>& in, std::vector<Ciphertext>& out, std::size_t num_threads = 1) noexcept;

private:
    std::shared_ptr<PublicKey> pk_ = nullptr;
    std::shared_ptr<SecretKey> sk_ = nullptr;
    bool sk_set_ = false;
#ifndef SOLO_USE_IPCL
    std::size_t r_bit_count_ = 0;
    std::shared_ptr<PRNG> prng_ = nullptr;
#endif
};

/**
 * @brief Provides methods that decrypt ciphertexts into plaintexts.
 */
class Decryptor {
public:
    /**
     * @brief Constructs a decryptor with a secret key.
     *
     * @param[in] sk The secret key.
     * @throws std::invalid_argument if sk is nullptr.
     */
    explicit Decryptor(const std::shared_ptr<SecretKey>& sk);

    /**
     * @brief Default constructor is deleted.
     */
    Decryptor() = delete;

    /**
     * @brief Decrypts a ciphertext into a plaintext.
     *
     * @param[in] in The ciphertext.
     * @param[out] out The resulting plaintext.
     */
    void decrypt(const Ciphertext& in, Plaintext& out) const noexcept;

    /**
     * @brief Decrypts a vector of ciphertexts into a vector of plaintexts.
     *
     * @param[in] in The vector of ciphertext
     * @param[in] num_threads The number of threads utilized to execute this function. If SOLO_USE_IPCL is ON, this
     * parameter is ignored.
     * @param[out] out The vector of resulting plaintexts.
     */
    void decrypt_many(
            const std::vector<Ciphertext>& in, std::vector<Plaintext>& out, std::size_t num_threads = 1) const noexcept;

private:
    std::shared_ptr<SecretKey> sk_ = nullptr;
};

/**
 * @brief Provides methods that evaluates arithmetic operations on ciphertexts.
 */
class Evaluator {
public:
    /**
     * @brief Constructs an evaluator with a public key.
     *
     * @param[in] pk The public key.
     * @throws std::invalid_argument if pk is nullptr.
     */
    explicit Evaluator(const std::shared_ptr<PublicKey>& pk);

    /**
     * @brief Constructs an evaluator with a public key.
     *
     * @param[in] pk The public key.
     * @param[in] sk The secret key.
     * @throws std::invalid_argument if pk is nullptr or sk is nullptr.
     */
    explicit Evaluator(const std::shared_ptr<PublicKey>& pk, const std::shared_ptr<SecretKey>& sk);

    /**
     * @brief Default constructor is deleted.
     */
    Evaluator() = delete;

    /**
     * @brief Addition of two ciphertexts.
     *
     * @param[in] in_0 The first ciphertext to add.
     * @param[in] in_1 The second ciphertext to add.
     * @param[out] out The ciphertext to overwrite with the addition result.
     */
    void add(const Ciphertext& in_0, const Ciphertext& in_1, Ciphertext& out) const noexcept;

    /**
     * @brief Element-wise addition of two vector of ciphertexts.
     *
     * @param[in] in_0 The first vector of ciphertexts to add.
     * @param[in] in_1 The second vector of ciphertexts to add.
     * @param[in] num_threads The number of threads utilized to execute this function. If SOLO_USE_IPCL is ON, this
     * parameter is ignored.
     * @param[out] out The vector of ciphertexts to overwrite with the addition result.
     */
    void add_many(const std::vector<Ciphertext>& in_0, const std::vector<Ciphertext>& in_1,
            std::vector<Ciphertext>& out, std::size_t num_threads = 1) const;

    /**
     * @brief Addition of a ciphertext and a plaintext.
     *
     * @param[in] in_0 The ciphertext to add.
     * @param[in] in_1 The plaintext to add.
     * @param[out] out The ciphertext to overwrite with the addition result.
     */
    void add(const Ciphertext& in_0, const Plaintext& in_1, Ciphertext& out) noexcept;

    /**
     * @brief Element-wise addition of a vector of ciphertexts and a vector of plaintexts.
     *
     * @param[in] in_0 The vector of ciphertexts to add
     * @param[in] in_1 The vector of plaintexts to add
     * @param[in] num_threads The number of threads utilized to execute this function. If SOLO_USE_IPCL is ON, this
     * parameter is ignored.
     * @param[out] out The vector of ciphertexts to overwrite with the addition result.
     */
    void add_many(const std::vector<Ciphertext>& in_0, const std::vector<Plaintext>& in_1, std::vector<Ciphertext>& out,
            std::size_t num_threads = 1);

    /**
     * @brief Multiplication of a ciphertext and a plaintext.
     *
     * @param[in] in_0 The ciphertext to multiply.
     * @param[in] in_1 The plaintext to multiply.
     * @param[out] out The ciphertext to overwrite with the multiplication result.
     */
    void mul(const Ciphertext& in_0, const Plaintext& in_1, Ciphertext& out) const noexcept;

    /**
     * @brief Element-wise multiplication of a vector of ciphertexts and a vector of plaintexts.
     *
     * @param[in] in_0 The vector of ciphertexts to multiply.
     * @param[in] in_1 The vector of plaintexts to multiply.
     * @param[in] num_threads The number of threads utilized to execute this function. If SOLO_USE_IPCL is ON, this
     * parameter is ignored.
     * @param[out] out The vector of ciphertexts to overwrite with the multiplication result.
     */
    void mul_many(const std::vector<Ciphertext>& in_0, const std::vector<Plaintext>& in_1, std::vector<Ciphertext>& out,
            std::size_t num_threads = 1) const;

private:
    std::shared_ptr<PublicKey> pk_ = nullptr;
    std::shared_ptr<SecretKey> sk_ = nullptr;
    std::shared_ptr<Encryptor> encryptor_ = nullptr;
    bool sk_set_ = false;
};

namespace utils {
#ifdef SOLO_USE_IPCL
/**
 * @brief Shifts a BigNumber to the left bits.
 *
 * @param[in] in The BigNumber.
 * @param[in] bits The offset.
 * @throws std::invalid_argument if bits is greater than 8192.
 */
void bn_lshift(BigNumber& in, std::size_t bits);

/**
 * @brief Returns a random BigNumber.
 *
 * @param[in] bits The bitsize of the random BigNumber.
 * @throws std::invalid_argument if bits is greater than 8192.
 */
BigNumber get_random_bn(std::size_t bits);
#else
/**
 * @brief Returns a random BigNum.
 *
 * @param[in] bits The bitsize of the random mpz_class.
 * @throws std::invalid_argument if bits is greater than 8192.
 */
mpz_class get_random_mpz(std::size_t bits, std::shared_ptr<PRNG>& prng);
#endif
}  // namespace utils

}  // namespace ahepaillier
}  // namespace solo
}  // namespace petace
