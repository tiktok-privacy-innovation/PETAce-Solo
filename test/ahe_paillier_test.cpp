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

#include "solo/ahe_paillier.h"

#ifdef SOLO_USE_IPCL

#include <memory>

#include "gtest/gtest.h"

TEST(AHEPaillierTest, KeyGen) {
    {
        auto keygen = [](std::size_t key_length) { petace::solo::ahepaillier::KeyGenerator generator(key_length); };
        ASSERT_THROW(keygen(512), std::invalid_argument);
        ASSERT_THROW(keygen(3072), std::invalid_argument);
    }
    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk);
        ASSERT_NE(sk, nullptr);
        ASSERT_NE(pk, nullptr);
    }
    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(2048);
        generator.get_key_pair(sk, pk);
        ASSERT_NE(sk, nullptr);
        ASSERT_NE(pk, nullptr);
    }
}

TEST(AHEPaillierTest, Serialization) {
    {
        auto serialization_constructor = [](std::size_t key_length) {
            petace::solo::ahepaillier::Serialization serialization(key_length);
        };
        ASSERT_THROW(serialization_constructor(512), std::invalid_argument);
        ASSERT_THROW(serialization_constructor(3072), std::invalid_argument);
    }
    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk);
        petace::solo::ahepaillier::Serialization serialization(1024, true);
        ASSERT_EQ(serialization.public_key_byte_count(), 384);
        ASSERT_EQ(serialization.secret_key_byte_count(), 256);
        std::size_t public_key_byte_count = serialization.public_key_byte_count();
        std::vector<petace::solo::Byte> pk_bytes(public_key_byte_count);

        ASSERT_THROW(serialization.serialize_public_key_to_bytes(pk, nullptr, 0), std::invalid_argument);
        ASSERT_THROW(serialization.serialize_public_key_to_bytes(pk, nullptr, 383), std::invalid_argument);
        ASSERT_THROW(serialization.serialize_public_key_to_bytes(pk, pk_bytes.data(), 385), std::invalid_argument);
        serialization.serialize_public_key_to_bytes(pk, pk_bytes.data(), public_key_byte_count);

        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk_deserialized = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk_deserialized = nullptr;
        ASSERT_THROW(
                serialization.deserialize_public_key_from_bytes(nullptr, 0, pk_deserialized), std::invalid_argument);
        ASSERT_THROW(
                serialization.deserialize_public_key_from_bytes(nullptr, 383, pk_deserialized), std::invalid_argument);
        ASSERT_THROW(serialization.deserialize_public_key_from_bytes(pk_bytes.data(), 385, pk_deserialized),
                std::invalid_argument);
        serialization.deserialize_public_key_from_bytes(pk_bytes.data(), pk_bytes.size(), pk_deserialized);
        ASSERT_EQ(*(pk->getN()), *(pk_deserialized->getN()));
        ASSERT_EQ(pk->getHS(), pk_deserialized->getHS());

        std::size_t secret_key_byte_count = serialization.secret_key_byte_count();
        std::vector<petace::solo::Byte> sk_bytes(secret_key_byte_count);
        ASSERT_THROW(serialization.serialize_secret_key_to_bytes(sk, nullptr, 0), std::invalid_argument);
        ASSERT_THROW(serialization.serialize_secret_key_to_bytes(sk, nullptr, 255), std::invalid_argument);
        ASSERT_THROW(serialization.serialize_secret_key_to_bytes(sk, sk_bytes.data(), 257), std::invalid_argument);
        serialization.serialize_secret_key_to_bytes(sk, sk_bytes.data(), secret_key_byte_count);

        ASSERT_THROW(
                serialization.deserialize_secret_key_from_bytes(nullptr, 0, sk_deserialized), std::invalid_argument);
        ASSERT_THROW(
                serialization.deserialize_secret_key_from_bytes(nullptr, 255, sk_deserialized), std::invalid_argument);
        ASSERT_THROW(serialization.deserialize_secret_key_from_bytes(sk_bytes.data(), 257, sk_deserialized),
                std::invalid_argument);
        serialization.deserialize_secret_key_from_bytes(sk_bytes.data(), sk_bytes.size(), sk_deserialized);
        ASSERT_EQ(*(sk->getN()), *(sk_deserialized->getN()));
        ASSERT_EQ(*(sk->getP()), *(sk_deserialized->getP()));
        ASSERT_EQ(*(sk->getQ()), *(sk_deserialized->getQ()));
    }
    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk, false);
        petace::solo::ahepaillier::Serialization serialization(1024, false);
        ASSERT_EQ(serialization.public_key_byte_count(), 128);
        ASSERT_EQ(serialization.secret_key_byte_count(), 256);
        std::size_t public_key_byte_count = serialization.public_key_byte_count();
        std::vector<petace::solo::Byte> pk_bytes(public_key_byte_count);

        ASSERT_THROW(serialization.serialize_public_key_to_bytes(pk, nullptr, 0), std::invalid_argument);
        ASSERT_THROW(serialization.serialize_public_key_to_bytes(pk, nullptr, 127), std::invalid_argument);
        ASSERT_THROW(serialization.serialize_public_key_to_bytes(pk, pk_bytes.data(), 129), std::invalid_argument);
        serialization.serialize_public_key_to_bytes(pk, pk_bytes.data(), public_key_byte_count);

        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk_deserialized = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk_deserialized = nullptr;
        ASSERT_THROW(
                serialization.deserialize_public_key_from_bytes(nullptr, 0, pk_deserialized), std::invalid_argument);
        ASSERT_THROW(
                serialization.deserialize_public_key_from_bytes(nullptr, 127, pk_deserialized), std::invalid_argument);
        ASSERT_THROW(serialization.deserialize_public_key_from_bytes(pk_bytes.data(), 129, pk_deserialized),
                std::invalid_argument);
        serialization.deserialize_public_key_from_bytes(pk_bytes.data(), pk_bytes.size(), pk_deserialized);
        ASSERT_EQ(*(pk->getN()), *(pk_deserialized->getN()));

        std::size_t secret_key_byte_count = serialization.secret_key_byte_count();
        std::vector<petace::solo::Byte> sk_bytes(secret_key_byte_count);
        ASSERT_THROW(serialization.serialize_secret_key_to_bytes(sk, nullptr, 0), std::invalid_argument);
        ASSERT_THROW(serialization.serialize_secret_key_to_bytes(sk, nullptr, 255), std::invalid_argument);
        ASSERT_THROW(serialization.serialize_secret_key_to_bytes(sk, sk_bytes.data(), 257), std::invalid_argument);
        serialization.serialize_secret_key_to_bytes(sk, sk_bytes.data(), secret_key_byte_count);

        ASSERT_THROW(
                serialization.deserialize_secret_key_from_bytes(nullptr, 0, sk_deserialized), std::invalid_argument);
        ASSERT_THROW(
                serialization.deserialize_secret_key_from_bytes(nullptr, 255, sk_deserialized), std::invalid_argument);
        ASSERT_THROW(serialization.deserialize_secret_key_from_bytes(sk_bytes.data(), 257, sk_deserialized),
                std::invalid_argument);
        serialization.deserialize_secret_key_from_bytes(sk_bytes.data(), sk_bytes.size(), sk_deserialized);
        ASSERT_EQ(*(sk->getN()), *(sk_deserialized->getN()));
        ASSERT_EQ(*(sk->getP()), *(sk_deserialized->getP()));
        ASSERT_EQ(*(sk->getQ()), *(sk_deserialized->getQ()));
    }
    {
        const std::vector<int> bits_vec = {2, 31, 32, 480, 511, 512, 994, 1023, 1024, 2018, 2047, 2048};
        for (std::size_t i = 0; i < bits_vec.size(); ++i) {
            petace::solo::ahepaillier::BigNum bn = petace::solo::ahepaillier::utils::get_random_bn(bits_vec[i]);
            std::vector<petace::solo::Byte> bn_bytes((bits_vec[i] + 7) / 8);
            petace::solo::ahepaillier::Serialization::bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            petace::solo::ahepaillier::BigNum bn_deserialized;
            petace::solo::ahepaillier::Serialization::bn_from_bytes(bn_bytes.data(), bn_bytes.size(), bn_deserialized);
            ASSERT_EQ(bn, bn_deserialized);
        }
    }
    {
        const std::vector<int> bits_vec = {2, 31, 32, 482, 511, 512, 994, 1023, 1024, 2018, 2047, 2048};
        for (std::size_t i = 0; i < bits_vec.size(); ++i) {
            petace::solo::ahepaillier::BigNum bn = petace::solo::ahepaillier::utils::get_random_bn(bits_vec[i]);
            std::vector<petace::solo::Byte> bn_bytes((bits_vec[i] + 7) / 8 + 1);
            petace::solo::ahepaillier::Serialization::bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            petace::solo::ahepaillier::BigNum bn_deserialized;
            petace::solo::ahepaillier::Serialization::bn_from_bytes(bn_bytes.data(), bn_bytes.size(), bn_deserialized);
            ASSERT_EQ(bn, bn_deserialized);
        }
    }
}

TEST(AHEPaillierTest, Encode) {
    {
        std::uint64_t in = 1234;
        petace::solo::ahepaillier::Encoder encoder;
        petace::solo::ahepaillier::Plaintext pt;
        encoder.encode(in, pt);
        std::uint64_t out = encoder.decode(pt);
        ASSERT_EQ(in, out);
        ASSERT_EQ(pt.slot_count(), 1);
        ASSERT_EQ(pt[0], petace::solo::ahepaillier::BigNum(1234));
    }
    {
        std::vector<std::uint64_t> in = {1, 2, 3, 4, 5, 6, 7, 8};
        petace::solo::ahepaillier::Encoder encoder;
        petace::solo::ahepaillier::Plaintext pt;
        encoder.encode(in, pt);
        std::vector<std::uint64_t> out;
        encoder.decode(pt, out);
        ASSERT_EQ(in, out);
        ASSERT_EQ(pt.slot_count(), 8);
        ASSERT_EQ(pt[0], petace::solo::ahepaillier::BigNum(1));
    }
    {
        std::vector<petace::solo::ahepaillier::BigNum> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        petace::solo::ahepaillier::Encoder encoder;
        petace::solo::ahepaillier::Plaintext pt(in);
        std::vector<petace::solo::ahepaillier::BigNum> out(pt);
        ASSERT_EQ(in, out);
        ASSERT_EQ(pt.slot_count(), 16);
        ASSERT_EQ(pt[0], petace::solo::ahepaillier::BigNum(1));
    }
    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk, true);
        petace::solo::ahepaillier::Encryptor encryptor(pk, true);

        std::vector<std::uint64_t> in = {1, 2, 3, 4, 5, 6, 7, 8};
        petace::solo::ahepaillier::Encoder encoder;
        petace::solo::ahepaillier::Plaintext pt;
        petace::solo::ahepaillier::Ciphertext ct;
        encoder.encode(in, pt);
        encryptor.encrypt(pt, ct);
        std::vector<petace::solo::ahepaillier::BigNum> bn_ct(ct);
        petace::solo::ahepaillier::Ciphertext ct_check(*(pk.get()), bn_ct);
        for (std::size_t i = 0; i < ct.slot_count(); ++i) {
            ASSERT_EQ(ct[i], ct_check[i]);
        }
    }
    {
        std::uint64_t in = 1ull << 33;
        petace::solo::ahepaillier::Encoder encoder;
        petace::solo::ahepaillier::Plaintext pt;
        encoder.encode(in, pt);
        encoder.decode(pt);
    }
}

TEST(AHEPaillierTest, Encrypt) {
    std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
    std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
    petace::solo::ahepaillier::KeyGenerator generator(1024);
    generator.get_key_pair(sk, pk, true);
    petace::solo::ahepaillier::Encryptor encryptor(pk, true);
    petace::solo::ahepaillier::Decryptor decryptor(sk);
    petace::solo::ahepaillier::Encoder encoder;
    {
        std::uint64_t in = 1234;
        petace::solo::ahepaillier::Plaintext pt;
        petace::solo::ahepaillier::Ciphertext ct;
        encoder.encode(in, pt);
        encryptor.encrypt(pt, ct);
        ASSERT_EQ(ct.slot_count(), 1);
        ct[0];

        petace::solo::ahepaillier::Plaintext pt_check;
        decryptor.decrypt(ct, pt_check);
        std::uint64_t out = encoder.decode(pt_check);
        ASSERT_EQ(in, out);
    }
    {
        std::vector<std::uint64_t> in = {1, 2, 3, 4, 5, 6, 7, 8};
        petace::solo::ahepaillier::Plaintext pt;
        petace::solo::ahepaillier::Ciphertext ct;
        encoder.encode(in, pt);
        encryptor.encrypt(pt, ct);
        ASSERT_EQ(ct.slot_count(), 8);
        ct[0];

        petace::solo::ahepaillier::Plaintext pt_check;
        decryptor.decrypt(ct, pt_check);
        std::vector<std::uint64_t> out;
        encoder.decode(pt_check, out);
        ASSERT_EQ(in, out);
    }
    {
        std::vector<petace::solo::ahepaillier::BigNum> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        petace::solo::ahepaillier::Plaintext pt(in);
        petace::solo::ahepaillier::Ciphertext ct;
        encryptor.encrypt(pt, ct);
        ASSERT_EQ(ct.slot_count(), 16);
        ct[0];

        petace::solo::ahepaillier::Plaintext pt_check;
        decryptor.decrypt(ct, pt_check);
        std::vector<petace::solo::ahepaillier::BigNum> out(pt_check);
        ASSERT_EQ(in, out);
    }
    { ASSERT_THROW(petace::solo::ahepaillier::Encryptor(nullptr, true), std::invalid_argument); }
    { ASSERT_THROW(petace::solo::ahepaillier::Decryptor(nullptr), std::invalid_argument); }
}

TEST(AHEPaillierTest, Evaluator) {
    std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
    std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
    petace::solo::ahepaillier::KeyGenerator generator(1024);
    generator.get_key_pair(sk, pk, true);
    petace::solo::ahepaillier::Encryptor encryptor(pk, true);
    petace::solo::ahepaillier::Decryptor decryptor(sk);
    petace::solo::ahepaillier::Encoder encoder;
    petace::solo::ahepaillier::Evaluator evaluator;
    {
        std::vector<std::uint64_t> in_0 = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<std::uint64_t> in_1 = {8, 7, 6, 5, 4, 3, 2, 1};
        std::vector<std::uint64_t> in_sum = {9, 9, 9, 9, 9, 9, 9, 9};
        std::vector<std::uint64_t> in_check;
        petace::solo::ahepaillier::Plaintext pt_0;
        petace::solo::ahepaillier::Plaintext pt_1;
        petace::solo::ahepaillier::Plaintext pt_check;
        petace::solo::ahepaillier::Ciphertext ct_0;
        petace::solo::ahepaillier::Ciphertext ct_1;
        petace::solo::ahepaillier::Ciphertext ct_out;

        encoder.encode(in_0, pt_0);
        encoder.encode(in_1, pt_1);
        encryptor.encrypt(pt_0, ct_0);
        encryptor.encrypt(pt_1, ct_1);

        evaluator.add(ct_0, ct_1, ct_out);
        decryptor.decrypt(ct_out, pt_check);
        encoder.decode(pt_check, in_check);
        ASSERT_EQ(in_check, in_sum);
    }
    {
        std::vector<std::uint64_t> in_0 = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<std::uint64_t> in_1 = {8, 7, 6, 5, 4, 3, 2, 1};
        std::vector<std::uint64_t> in_sum = {9, 9, 9, 9, 9, 9, 9, 9};
        std::vector<std::uint64_t> in_check;
        petace::solo::ahepaillier::Plaintext pt_0;
        petace::solo::ahepaillier::Plaintext pt_1;
        petace::solo::ahepaillier::Plaintext pt_check;
        petace::solo::ahepaillier::Ciphertext ct_0;
        petace::solo::ahepaillier::Ciphertext ct_1;
        petace::solo::ahepaillier::Ciphertext ct_out;

        encoder.encode(in_0, pt_0);
        encoder.encode(in_1, pt_1);
        encryptor.encrypt(pt_0, ct_0);

        evaluator.add(ct_0, pt_1, ct_out);
        decryptor.decrypt(ct_out, pt_check);
        encoder.decode(pt_check, in_check);
        ASSERT_EQ(in_check, in_sum);
    }
    {
        std::vector<std::uint64_t> in_0 = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<std::uint64_t> in_1 = {8, 7, 6, 5, 4, 3, 2, 1};
        std::vector<std::uint64_t> in_mul = {8, 14, 18, 20, 20, 18, 14, 8};
        std::vector<std::uint64_t> in_check;
        petace::solo::ahepaillier::Plaintext pt_0;
        petace::solo::ahepaillier::Plaintext pt_1;
        petace::solo::ahepaillier::Plaintext pt_check;
        petace::solo::ahepaillier::Ciphertext ct_0;
        petace::solo::ahepaillier::Ciphertext ct_1;
        petace::solo::ahepaillier::Ciphertext ct_out;

        encoder.encode(in_0, pt_0);
        encoder.encode(in_1, pt_1);
        encryptor.encrypt(pt_0, ct_0);

        evaluator.mul(ct_0, pt_1, ct_out);
        decryptor.decrypt(ct_out, pt_check);
        encoder.decode(pt_check, in_check);
        ASSERT_EQ(in_check, in_mul);
    }
}

TEST(AHEPaillierTest, Utils) {
    const std::vector<int> bits_vec = {2, 31, 32, 482, 511, 512, 994, 1023, 1024, 2018, 2047, 2048};
    for (std::size_t i = 0; i < bits_vec.size(); ++i) {
        auto bn = petace::solo::ahepaillier::BigNum::One();
        petace::solo::ahepaillier::utils::bn_lshift(bn, bits_vec[i]);
    }
}

#endif
