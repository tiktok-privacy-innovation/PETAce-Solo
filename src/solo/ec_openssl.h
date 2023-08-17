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

#include "openssl/bn.h"
#include "openssl/ec.h"

#include "solo/hash.h"
#include "solo/prng.h"
#include "solo/util/defines.h"

namespace petace {
namespace solo {

/**
 * @brief Provides basic support to Elliptic Curve cryptography using the OpenSSL library.
 */
class ECOpenSSL {
public:
    /**
     * @brief A SecretKey is an integer.
     */
    class SecretKey {
    public:
        /**
         * @brief Creates an empty SecretKey using a secure allocation.
         */
        SecretKey() : data_(BN_secure_new()) {
        }

        /**
         * @brief Securely wipes and deallocates a SecretKey.
         */
        ~SecretKey() {
            BN_clear_free(data_);
        }

        /**
         * @brief Returns a pointer to the SecretKey data.
         */
        BIGNUM* data() {
            return data_;
        }

        /**
         * @brief Returns a pointer to the SecretKey data.
         */
        const BIGNUM* data() const {
            return data_;
        }

    private:
        BIGNUM* data_;
    };

    /**
     * @brief A UInt is an unsigned integer.
     */
    class UInt {
    public:
        /**
         * @brief Creates an empty UInt.
         */
        UInt() : data_(BN_new()) {
        }

        /**
         * @brief Wipes and deallocates a SecretKey.
         */
        ~UInt() {
            BN_clear_free(data_);
        }

        /**
         * @brief Copies a UInt from another.
         *
         * @param[in] copy The UInt to copy from.
         * @throws std::runtime_error if an OpenSSL command fails.
         */
        UInt& operator=(const UInt& copy);

        /**
         * @brief Returns a pointer to the UInt data.
         */
        BIGNUM* data() {
            return data_;
        }

        /**
         * @brief Returns a pointer to the UInt data.
         */
        const BIGNUM* data() const {
            return data_;
        }

    private:
        BIGNUM* data_;
    };

    /**
     * @brief A Point is a point on a Elliptic Curve.
     */
    class Point {
    public:
        /**
         * @brief Creates an empty Point.
         *
         * @param[in] ec The container of Elliptic Curve parameters.
         */
        explicit Point(const ECOpenSSL& ec) : data_(EC_POINT_new(ec.group_)) {
        }

        /**
         * @brief Creates an empty Point.
         *
         * @param[in] ec_group The container of Elliptic Curve parameters.
         */
        explicit Point(EC_GROUP* ec_group) : data_(EC_POINT_new(ec_group)) {
        }

        /**
         * @brief Copies a Point from another.
         *
         * @param[in] copy The Point to copy from.
         * @throws std::runtime_error if an OpenSSL command fails.
         */
        Point& operator=(const Point& copy);

        /**
         * @brief Wipes and deallocates a Point.
         */
        ~Point() {
            EC_POINT_clear_free(data_);
        }

        /**
         * @brief Returns a pointer to the Point data.
         */
        EC_POINT* data() {
            return data_;
        }

        /**
         * @brief Returns a pointer to the Point data.
         */
        const EC_POINT* data() const {
            return data_;
        }

    private:
        EC_POINT* data_;
    };

    /**
     * @brief Creates a class of Elliptic Curve operations from a curve ID supported by OpenSSL and a hash algorithm.
     *
     * @param[in] curve_id A curve ID that defines an Elliptic Curve in OpenSSL.
     * @param[in] hash_scheme A hash algorithm that is used in the hash_to_curve operation.
     * @throws std::invalid_argument if the algorithm is not supported.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    ECOpenSSL(int curve_id, HashScheme hash_scheme);

    ~ECOpenSSL();

    /**
     * @brief Creates a random secret key from a given PRNG.
     *
     * @param[in] prng The PRNG to generate randomness from.
     * @param[out] out The secret key.
     * @throws std::invalid_argument if any function parameter is nullptr.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void create_secret_key(std::shared_ptr<PRNG> prng, SecretKey& out) const;

    /**
     * @brief Creates a public key from a given secret key.
     *
     * @param[in] key The secret key to generate a public key from.
     * @param[out] out The public key.
     * @throws std::invalid_argument if any function parameter is nullptr.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void create_public_key(const SecretKey& key, Point& out) const;

    /**
     * @brief Encrypts a plaintext point to a ciphertext point with a given secret key.
     *
     * @param[in] in The plaintext point.
     * @param[in] key The secret key.
     * @param[out] out The ciphertext point.
     * @throws std::invalid_argument if any function parameter is nullptr.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void encrypt(const Point& in, const SecretKey& key, Point& out) const;

    /**
     * @brief Re-encrypts a ciphertext point with a new secret key by decrypting it with the old secret key first.
     *
     * @param[in] in The ciphertext point decryptable with the old secret key.
     * @param[in] key_old The old secret key.
     * @param[in] key_new The new secret key.
     * @param[out] out The ciphertext point decryptable with the new secret key.
     * @throws std::invalid_argument if any function parameter is nullptr.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void switch_key(const Point& in, const SecretKey& key_old, const SecretKey& key_new, Point& out) const;

    /**
     * @brief Hash a number of bytes to a point on the defined Elliptic Curve.
     *
     * @param[in] in The pointer of bytes to be hashed.
     * @param[in] in_byte_count The number of bytes to be hashed.
     * @param[out] out The hash digest or the point on the Elliptic Curve.
     * @throws std::invalid_argument if the pointer of bytes or the output point is nullptr.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void hash_to_curve(const Byte* in, std::size_t in_byte_count, Point& out) const;

    /**
     * @brief Decrypts a ciphertext point to a plaintext point with a given secret key.
     *
     * @param[in] in The ciphertext point.
     * @param[in] key The secret key.
     * @param[out] out The plaintext point.
     * @throws std::invalid_argument if any function parameter is nullptr.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void decrypt(const Point& in, const SecretKey& key, Point& out) const;

    /**
     * @brief Returns true if two points are equal; returns false, otherwise.
     *
     * @param[in] in_0 A point.
     * @param[in] in_1 The other point.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    bool are_equal(const Point& in_0, const Point& in_1) const;

    /**
     * @brief Addition of two points defined by the Elliptic Curve group.
     *
     * @param[in] in_0 A point.
     * @param[in] in_1 The other point.
     * @param[out] out The sum of two points.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void add(const Point& in_0, const Point& in_1, Point& out) const;

    /**
     * @brief The inverse of a point defined by the Elliptic Curve group.
     *
     * @param[in] in A point.
     * @param[out] out The inverse of the point.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void invert(const Point& in, Point& out) const;

    /**
     * @brief Scalar multiplication of a point by a scalar defined by the Elliptic Curve group.
     *
     * @param[in] point A point.
     * @param[in] scalar A scalar.
     * @param[out] out The scalar multiplication result.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void mul(const Point& point, const UInt& scalar, Point& out) const;

    /**
     * @brief Scalar multiplication of the Elliptic Curve group's generator by a scalar.
     *
     * @param[in] scalar A scalar.
     * @param[out] out The scalar multiplication result.
     * @throws std::runtime_error if an OpenSSL command fails.
     */
    void mul_generator(const UInt& scalar, Point& out) const;

    /**
     * @brief Writes a point into a byte buffer and returns the number of bytes written (if the byte buffer is empty).
     *
     * @param[in] point The point to be written.
     * @param[in] out_byte_count The size of the output byte buffer.
     * @param[out] The byte buffer to write to.
     * @throws std::invalid_argument if the point is nullptr.
     * @throws std::runtime_error if an OpenSSL command fails or if the buffer is not large enough.
     */
    std::size_t point_to_bytes(const Point& point, std::size_t out_byte_count, Byte* out = nullptr) const;

    /**
     * @brief Reads a point from a byte buffer.
     *
     * @param[in] in The byte buffer to read from.
     * @param[in] in_byte_count The size of the input byte buffer.
     * @param[out] The point to write to.
     * @throws std::invalid_argument if the input buffer's byte size is zero or either input or output is nullptr.
     * @throws std::runtime_error if an OpenSSL command fails or if the buffer is not large enough.
     */
    void point_from_bytes(const Byte* in, std::size_t in_byte_count, Point& out) const;

private:
    void hash_to_field(
            std::shared_ptr<Hash> hash, const Byte* in, std::size_t in_byte_count, BIGNUM* out, BN_CTX* ctx) const;

    void compute_y_square(const BIGNUM* x, BIGNUM* y_square, BN_CTX* ctx) const;

    EC_GROUP* group_;

    BIGNUM* p_;

    BIGNUM* a_;

    BIGNUM* b_;

    BIGNUM* order_;

    BIGNUM* p_minus_one_over_two_;

    BIGNUM* three_;

    std::shared_ptr<HashFactory> hash_factory_;
};

}  // namespace solo
}  // namespace petace
