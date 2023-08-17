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

#include "solo/ec_openssl.h"

#include "gtest/gtest.h"

TEST(ECOpenSSLTest, ECScheme) {
    petace::solo::Byte input[64];
    for (std::size_t i = 0; i < 64; i++) {
        input[i] = static_cast<petace::solo::Byte>(i);
    }
    {
        using EC = petace::solo::ECOpenSSL;
        int curve_id = 415;
        EC ec(curve_id, petace::solo::HashScheme::SHA_256);
        EC::SecretKey sk;
        EC::SecretKey sk_new;
        EC::Point plaintext(ec);
        EC::Point plaintext_new(ec);
        EC::Point ciphertext(ec);
        EC::Point ciphertext_new(ec);
        petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::BLAKE2Xb);
        std::shared_ptr<petace::solo::PRNG> prng = prng_factory.create();
        ASSERT_THROW(ec.create_secret_key(nullptr, sk), std::invalid_argument);
        ec.create_secret_key(prng, sk);
        ec.create_secret_key(prng, sk_new);
        ASSERT_THROW(ec.hash_to_curve(nullptr, 64, plaintext), std::invalid_argument);
        ec.hash_to_curve(input, 64, plaintext);
        ec.encrypt(plaintext, sk, ciphertext);
        ec.switch_key(ciphertext, sk, sk_new, ciphertext_new);
        ec.decrypt(ciphertext_new, sk_new, plaintext_new);
        ASSERT_TRUE(ec.are_equal(plaintext_new, plaintext));

        EC::Point pk(ec);
        EC::Point pk_other(ec);
        EC::UInt scalar;
        EXPECT_NO_THROW(BN_copy(scalar.data(), sk.data()));
        ec.create_public_key(sk, pk);
        ASSERT_FALSE(ec.are_equal(pk, pk_other));
        ec.mul_generator(scalar, pk_other);
        ASSERT_TRUE(ec.are_equal(pk, pk_other));

        std::size_t pk_byte_count = ec.point_to_bytes(pk, 0, nullptr);
        std::vector<petace::solo::Byte> pk_byte_array(pk_byte_count);
        ASSERT_EQ(ec.point_to_bytes(pk, pk_byte_count, pk_byte_array.data()), pk_byte_count);
        ASSERT_THROW(ec.point_from_bytes(pk_byte_array.data(), 0, pk_other), std::invalid_argument);
        ASSERT_THROW(ec.point_from_bytes(nullptr, pk_byte_count, pk_other), std::invalid_argument);
        ASSERT_THROW(ec.point_from_bytes(pk_byte_array.data(), pk_byte_count + 1, pk_other), std::runtime_error);
        ASSERT_THROW(ec.point_from_bytes(pk_byte_array.data(), pk_byte_count - 1, pk_other), std::runtime_error);
        ec.point_from_bytes(pk_byte_array.data(), pk_byte_count, pk_other);
        ASSERT_TRUE(ec.are_equal(pk, pk_other));
    }
}
