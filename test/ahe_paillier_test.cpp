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
        ASSERT_THROW(petace::solo::ahepaillier::PublicKey(512, true), std::invalid_argument);
        ASSERT_THROW(petace::solo::ahepaillier::PublicKey(3072, true), std::invalid_argument);
        ASSERT_THROW(petace::solo::ahepaillier::PublicKey(512, false), std::invalid_argument);
        ASSERT_THROW(petace::solo::ahepaillier::PublicKey(3072, false), std::invalid_argument);
        ASSERT_THROW(petace::solo::ahepaillier::PublicKey(512, true), std::invalid_argument);
        ASSERT_THROW(petace::solo::ahepaillier::PublicKey(3072, true), std::invalid_argument);
        ASSERT_THROW(petace::solo::ahepaillier::PublicKey(512, false), std::invalid_argument);
        ASSERT_THROW(petace::solo::ahepaillier::PublicKey(3072, false), std::invalid_argument);
    }

    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk);
        ASSERT_EQ(pk->public_key_byte_count(), 384);
        ASSERT_EQ(sk->secret_key_byte_count(), 256);
        std::size_t public_key_byte_count = pk->public_key_byte_count();
        std::vector<petace::solo::Byte> pk_bytes(public_key_byte_count);

        ASSERT_THROW(pk->serialize_to_bytes(nullptr, 0), std::invalid_argument);
        ASSERT_THROW(pk->serialize_to_bytes(nullptr, 383), std::invalid_argument);
        ASSERT_THROW(pk->serialize_to_bytes(pk_bytes.data(), 385), std::invalid_argument);
        pk->serialize_to_bytes(pk_bytes.data(), public_key_byte_count);

        auto sk_deserialized = std::make_shared<petace::solo::ahepaillier::SecretKey>(1024);
        auto pk_deserialized = std::make_shared<petace::solo::ahepaillier::PublicKey>(1024, true);

        ASSERT_THROW(pk_deserialized->deserialize_from_bytes(nullptr, 0), std::invalid_argument);
        ASSERT_THROW(pk_deserialized->deserialize_from_bytes(nullptr, 383), std::invalid_argument);
        ASSERT_THROW(pk_deserialized->deserialize_from_bytes(pk_bytes.data(), 385), std::invalid_argument);
        ASSERT_THROW(
                pk_deserialized->serialize_to_bytes(pk_bytes.data(), public_key_byte_count), std::invalid_argument);
        pk_deserialized->deserialize_from_bytes(pk_bytes.data(), pk_bytes.size());
        ASSERT_THROW(pk_deserialized->deserialize_from_bytes(pk_bytes.data(), pk_bytes.size()), std::invalid_argument);
#ifdef SOLO_USE_IPCL
        ASSERT_EQ(BigNumber(1), BigNumber(1));
        ASSERT_EQ(*(pk->pk()->getN()), *(pk_deserialized->pk()->getN()));
        ASSERT_EQ(pk->pk()->getHS(), pk_deserialized->pk()->getHS());
#else
        ASSERT_EQ(pk->n(), pk_deserialized->n());
        ASSERT_EQ(pk->g(), pk_deserialized->g());
        ASSERT_EQ(pk->n_square(), pk_deserialized->n_square());
        ASSERT_EQ(pk->hs(), pk_deserialized->hs());
#endif
        std::size_t secret_key_byte_count = sk->secret_key_byte_count();
        std::vector<petace::solo::Byte> sk_bytes(secret_key_byte_count);
        ASSERT_THROW(sk->serialize_to_bytes(nullptr, 0), std::invalid_argument);
        ASSERT_THROW(sk->serialize_to_bytes(nullptr, 255), std::invalid_argument);
        ASSERT_THROW(sk->serialize_to_bytes(sk_bytes.data(), 257), std::invalid_argument);
        sk->serialize_to_bytes(sk_bytes.data(), secret_key_byte_count);

        ASSERT_THROW(sk_deserialized->deserialize_from_bytes(nullptr, 0), std::invalid_argument);
        ASSERT_THROW(sk_deserialized->deserialize_from_bytes(nullptr, 255), std::invalid_argument);
        ASSERT_THROW(sk_deserialized->deserialize_from_bytes(sk_bytes.data(), 257), std::invalid_argument);
        ASSERT_THROW(
                sk_deserialized->serialize_to_bytes(sk_bytes.data(), secret_key_byte_count), std::invalid_argument);
        sk_deserialized->deserialize_from_bytes(sk_bytes.data(), sk_bytes.size());
        ASSERT_THROW(sk_deserialized->deserialize_from_bytes(sk_bytes.data(), sk_bytes.size()), std::invalid_argument);
#ifdef SOLO_USE_IPCL
        ASSERT_EQ(*(sk->sk()->getN()), *(sk_deserialized->sk()->getN()));
        ASSERT_EQ(*(sk->sk()->getP()), *(sk_deserialized->sk()->getP()));
        ASSERT_EQ(*(sk->sk()->getQ()), *(sk_deserialized->sk()->getQ()));
#else
        ASSERT_EQ(sk->n(), sk_deserialized->n());
        ASSERT_EQ(sk->g(), sk_deserialized->g());
        ASSERT_EQ(sk->n_square(), sk_deserialized->n_square());
#endif
    }

    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk, false);
        ASSERT_EQ(pk->public_key_byte_count(), 128);
        ASSERT_EQ(sk->secret_key_byte_count(), 256);
        std::size_t public_key_byte_count = pk->public_key_byte_count();
        std::vector<petace::solo::Byte> pk_bytes(public_key_byte_count);

        ASSERT_THROW(pk->serialize_to_bytes(nullptr, 0), std::invalid_argument);
        ASSERT_THROW(pk->serialize_to_bytes(nullptr, 127), std::invalid_argument);
        ASSERT_THROW(pk->serialize_to_bytes(pk_bytes.data(), 129), std::invalid_argument);
        pk->serialize_to_bytes(pk_bytes.data(), public_key_byte_count);

        auto sk_deserialized = std::make_shared<petace::solo::ahepaillier::SecretKey>(1024);
        auto pk_deserialized = std::make_shared<petace::solo::ahepaillier::PublicKey>(1024, false);

        ASSERT_THROW(pk_deserialized->deserialize_from_bytes(nullptr, 0), std::invalid_argument);
        ASSERT_THROW(pk_deserialized->deserialize_from_bytes(nullptr, 127), std::invalid_argument);
        ASSERT_THROW(pk_deserialized->deserialize_from_bytes(pk_bytes.data(), 129), std::invalid_argument);
        pk_deserialized->deserialize_from_bytes(pk_bytes.data(), pk_bytes.size());
#ifdef SOLO_USE_IPCL
        ASSERT_EQ(*(pk->pk()->getN()), *(pk_deserialized->pk()->getN()));
        ASSERT_EQ(pk->pk()->getHS(), pk_deserialized->pk()->getHS());
#else
        ASSERT_EQ(pk->n(), pk_deserialized->n());
        ASSERT_EQ(pk->g(), pk_deserialized->g());
        ASSERT_EQ(pk->n_square(), pk_deserialized->n_square());
        ASSERT_EQ(pk->hs(), pk_deserialized->hs());
#endif
        std::size_t secret_key_byte_count = sk->secret_key_byte_count();
        std::vector<petace::solo::Byte> sk_bytes(secret_key_byte_count);
        ASSERT_THROW(sk->serialize_to_bytes(nullptr, 0), std::invalid_argument);
        ASSERT_THROW(sk->serialize_to_bytes(nullptr, 255), std::invalid_argument);
        ASSERT_THROW(sk->serialize_to_bytes(sk_bytes.data(), 257), std::invalid_argument);
        sk->serialize_to_bytes(sk_bytes.data(), secret_key_byte_count);

        ASSERT_THROW(sk_deserialized->deserialize_from_bytes(nullptr, 0), std::invalid_argument);
        ASSERT_THROW(sk_deserialized->deserialize_from_bytes(nullptr, 255), std::invalid_argument);
        ASSERT_THROW(sk_deserialized->deserialize_from_bytes(sk_bytes.data(), 257), std::invalid_argument);
        sk_deserialized->deserialize_from_bytes(sk_bytes.data(), sk_bytes.size());
#ifdef SOLO_USE_IPCL
        ASSERT_EQ(*(sk->sk()->getN()), *(sk_deserialized->sk()->getN()));
        ASSERT_EQ(*(sk->sk()->getP()), *(sk_deserialized->sk()->getP()));
        ASSERT_EQ(*(sk->sk()->getQ()), *(sk_deserialized->sk()->getQ()));
#else
        ASSERT_EQ(sk->n(), sk_deserialized->n());
        ASSERT_EQ(sk->g(), sk_deserialized->g());
        ASSERT_EQ(sk->n_square(), sk_deserialized->n_square());
#endif
    }

    {
        const std::vector<int> bits_vec = {2, 31, 32, 480, 511, 512, 994, 1023, 1024, 2018, 2047, 2048};
#ifndef SOLO_USE_IPCL
        petace::solo::PRNGFactory prng_factory = petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb);
        auto prng = prng_factory.create();
#endif
        for (std::size_t i = 0; i < bits_vec.size(); ++i) {
#ifdef SOLO_USE_IPCL
            BigNumber bn = petace::solo::ahepaillier::utils::get_random_bn(bits_vec[i]);
            std::vector<petace::solo::Byte> bn_bytes((bits_vec[i] + 7) / 8);
            petace::solo::ahepaillier::Serialization::ipcl_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            BigNumber bn_deserialized;
            petace::solo::ahepaillier::Serialization::ipcl_bn_from_bytes(
                    bn_bytes.data(), bn_bytes.size(), bn_deserialized);
#else
            mpz_class bn = petace::solo::ahepaillier::utils::get_random_mpz(bits_vec[i], prng);
            std::vector<petace::solo::Byte> bn_bytes((bits_vec[i] + 7) / 8);
            petace::solo::ahepaillier::Serialization::mpz_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            mpz_class bn_deserialized;
            petace::solo::ahepaillier::Serialization::mpz_bn_from_bytes(
                    bn_bytes.data(), bn_bytes.size(), bn_deserialized);
#endif
            ASSERT_EQ(bn, bn_deserialized);
        }
    }

    {
        const std::vector<int> bits_vec = {2, 31, 32, 480, 511, 512, 994, 1023, 1024, 2018, 2047, 2048};
#ifndef SOLO_USE_IPCL
        petace::solo::PRNGFactory prng_factory = petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb);
        auto prng = prng_factory.create();
#endif
        for (std::size_t i = 0; i < bits_vec.size(); ++i) {
#ifdef SOLO_USE_IPCL
            BigNumber bn = petace::solo::ahepaillier::utils::get_random_bn(bits_vec[i]);
            std::vector<petace::solo::Byte> bn_bytes((bits_vec[i] + 7) / 8 + 1);
            petace::solo::ahepaillier::Serialization::ipcl_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            BigNumber bn_deserialized;
            petace::solo::ahepaillier::Serialization::ipcl_bn_from_bytes(
                    bn_bytes.data(), bn_bytes.size(), bn_deserialized);
#else
            mpz_class bn = petace::solo::ahepaillier::utils::get_random_mpz(bits_vec[i], prng);
            std::vector<petace::solo::Byte> bn_bytes(((bits_vec[i] + 7) / 8 + 1));
            petace::solo::ahepaillier::Serialization::mpz_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            mpz_class bn_deserialized;
            petace::solo::ahepaillier::Serialization::mpz_bn_from_bytes(
                    bn_bytes.data(), bn_bytes.size(), bn_deserialized);
#endif
            ASSERT_EQ(bn, bn_deserialized);
        }
    }
    {
        petace::solo::PRNGFactory prng_factory = petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb);
        auto prng = prng_factory.create();
        std::size_t illegal_bits = 8200;
        std::size_t illegal_byte_count = 1025;
        std::vector<petace::solo::Byte> bn_bytes(illegal_byte_count);
        prng->generate(illegal_byte_count, bn_bytes.data());
#ifdef SOLO_USE_IPCL
        ASSERT_THROW(petace::solo::ahepaillier::utils::get_random_bn(illegal_bits), std::invalid_argument);
        BigNumber bn = ipcl::getRandomBN(static_cast<int>(illegal_bits));
        ASSERT_THROW(petace::solo::ahepaillier::Serialization::ipcl_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size()),
                std::invalid_argument);
        BigNumber bn_deserialized;
        ASSERT_THROW(petace::solo::ahepaillier::Serialization::ipcl_bn_from_bytes(
                             bn_bytes.data(), bn_bytes.size(), bn_deserialized),
                std::invalid_argument);
#else
        ASSERT_THROW(petace::solo::ahepaillier::utils::get_random_mpz(illegal_bits, prng), std::invalid_argument);
        mpz_class bn;
        mpz_import(bn.get_mpz_t(), bn_bytes.size(), 1, 1, 0, 0, bn_bytes.data());
        ASSERT_THROW(petace::solo::ahepaillier::Serialization::mpz_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
                     , std::invalid_argument);
        mpz_class bn_deserialized;
        ASSERT_THROW(petace::solo::ahepaillier::Serialization::mpz_bn_from_bytes(
                bn_bytes.data(), bn_bytes.size(), bn_deserialized);
                     , std::invalid_argument);
#endif
    }
    {
        const std::vector<int> bits_vec = {2, 31, 32, 480, 511, 512, 994, 1023, 1024, 2018, 2047, 2048};
#ifndef SOLO_USE_IPCL
        petace::solo::PRNGFactory prng_factory = petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb);
        auto prng = prng_factory.create();
#endif
        for (std::size_t i = 0; i < bits_vec.size(); ++i) {
#ifdef SOLO_USE_IPCL
            BigNumber bn = petace::solo::ahepaillier::utils::get_random_bn(bits_vec[i]);
            std::vector<petace::solo::Byte> bn_bytes((bits_vec[i] + 7) / 8);
            petace::solo::ahepaillier::Serialization::ipcl_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            petace::solo::ahepaillier::Plaintext pt;
            pt.deserialize_from_bytes(bn_bytes.data(), bn_bytes.size());
            ASSERT_EQ(bn, BigNumber(ipcl::PlainText(pt)));

            pt.serialize_to_bytes(bn_bytes.data(), bn_bytes.size());
            BigNumber bn_deserialized;
            petace::solo::ahepaillier::Serialization::ipcl_bn_from_bytes(
                    bn_bytes.data(), bn_bytes.size(), bn_deserialized);
#else
            mpz_class bn = petace::solo::ahepaillier::utils::get_random_mpz(bits_vec[i], prng);
            std::vector<petace::solo::Byte> bn_bytes((bits_vec[i] + 7) / 8);
            petace::solo::ahepaillier::Serialization::mpz_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            petace::solo::ahepaillier::Plaintext pt;
            pt.deserialize_from_bytes(bn_bytes.data(), bn_bytes.size());
            ASSERT_EQ(bn, mpz_class(pt));

            pt.serialize_to_bytes(bn_bytes.data(), bn_bytes.size());
            mpz_class bn_deserialized;
            petace::solo::ahepaillier::Serialization::mpz_bn_from_bytes(
                    bn_bytes.data(), bn_bytes.size(), bn_deserialized);
#endif
            ASSERT_EQ(bn, bn_deserialized);
        }
    }
    {
        const std::vector<int> bits_vec = {2, 31, 32, 480, 511, 512, 994, 1023, 1024, 2018, 2047, 2048};
#ifndef SOLO_USE_IPCL
        petace::solo::PRNGFactory prng_factory = petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb);
        auto prng = prng_factory.create();
#endif
        for (std::size_t i = 0; i < bits_vec.size(); ++i) {
#ifdef SOLO_USE_IPCL
            BigNumber bn = petace::solo::ahepaillier::utils::get_random_bn(bits_vec[i]);
            std::vector<petace::solo::Byte> bn_bytes((bits_vec[i] + 7) / 8 + 1);
            petace::solo::ahepaillier::Serialization::ipcl_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            petace::solo::ahepaillier::Plaintext pt;
            pt.deserialize_from_bytes(bn_bytes.data(), bn_bytes.size());
            ASSERT_EQ(bn, BigNumber(ipcl::PlainText(pt)));

            pt.serialize_to_bytes(bn_bytes.data(), bn_bytes.size());
            BigNumber bn_deserialized;
            petace::solo::ahepaillier::Serialization::ipcl_bn_from_bytes(
                    bn_bytes.data(), bn_bytes.size(), bn_deserialized);
#else
            mpz_class bn = petace::solo::ahepaillier::utils::get_random_mpz(bits_vec[i], prng);
            std::vector<petace::solo::Byte> bn_bytes((bits_vec[i] + 7) / 8 + 1);
            petace::solo::ahepaillier::Serialization::mpz_bn_to_bytes(bn, bn_bytes.data(), bn_bytes.size());
            petace::solo::ahepaillier::Plaintext pt;
            pt.deserialize_from_bytes(bn_bytes.data(), bn_bytes.size());
            ASSERT_EQ(bn, mpz_class(pt));

            pt.serialize_to_bytes(bn_bytes.data(), bn_bytes.size());
            mpz_class bn_deserialized;
            petace::solo::ahepaillier::Serialization::mpz_bn_from_bytes(
                    bn_bytes.data(), bn_bytes.size(), bn_deserialized);
#endif
            ASSERT_EQ(bn, bn_deserialized);
        }
    }
    {
        petace::solo::PRNGFactory prng_factory = petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb);
        auto prng = prng_factory.create();
        std::size_t illegal_byte_count = 1025;
        std::vector<petace::solo::Byte> bn_bytes(illegal_byte_count);
        prng->generate(illegal_byte_count, bn_bytes.data());
        petace::solo::ahepaillier::Plaintext pt;
        ASSERT_THROW(pt.deserialize_from_bytes(bn_bytes.data(), bn_bytes.size()), std::invalid_argument);
        pt.deserialize_from_bytes(bn_bytes.data(), bn_bytes.size() - 1);
        ASSERT_THROW(pt.serialize_to_bytes(bn_bytes.data(), bn_bytes.size() - 2), std::invalid_argument);
    }
    {
        petace::solo::PRNGFactory prng_factory = petace::solo::PRNGFactory(petace::solo::PRNGScheme::BLAKE2Xb);
        auto prng = prng_factory.create();
        std::size_t illegal_byte_count = 1025;
        std::vector<petace::solo::Byte> bn_bytes(illegal_byte_count);
        prng->generate(illegal_byte_count, bn_bytes.data());
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk, true);
        petace::solo::ahepaillier::Ciphertext ct;
        ASSERT_THROW(ct.deserialize_from_bytes(pk, bn_bytes.data(), bn_bytes.size()), std::invalid_argument);
        ct.deserialize_from_bytes(pk, bn_bytes.data(), bn_bytes.size() - 1);
        ASSERT_THROW(ct.serialize_to_bytes(bn_bytes.data(), bn_bytes.size() - 2), std::invalid_argument);
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
#ifdef SOLO_USE_IPCL
        ASSERT_EQ(BigNumber(ipcl::PlainText(pt)), BigNumber(1234));
#else
        ASSERT_EQ(mpz_class(pt), 1234);
#endif
    }
#ifdef SOLO_USE_IPCL
    {
        BigNumber in = 16;
        petace::solo::ahepaillier::Plaintext pt(in);
        auto out = BigNumber(ipcl::PlainText(pt));
        ASSERT_EQ(in, out);
    }
#else
    {
        mpz_class in = 16;
        petace::solo::ahepaillier::Plaintext pt(in);
        mpz_class out(pt);
        ASSERT_EQ(in, out);
    }
#endif
    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk, true);
        petace::solo::ahepaillier::Encryptor encryptor(pk);

        std::vector<std::uint64_t> in = {1, 2, 3, 4, 5, 6, 7, 8};
        petace::solo::ahepaillier::Encoder encoder;
        std::vector<petace::solo::ahepaillier::Plaintext> pt;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct;
        encoder.encode(in, pt);

        encryptor.encrypt_many(pt, ct);
#ifdef SOLO_USE_IPCL
        for (std::size_t i = 0; i < ct.size(); ++i) {
            BigNumber bn_ct(ipcl::CipherText(ct[i])[0]);
            petace::solo::ahepaillier::Ciphertext ct_check(*(pk->pk()), bn_ct);
            ASSERT_EQ(bn_ct, ipcl::CipherText(ct_check)[0]);
        }
#else
        for (std::size_t i = 0; i < ct.size(); ++i) {
            mpz_class bn_ct(ct[i]);
            petace::solo::ahepaillier::Ciphertext ct_check(bn_ct);
            ASSERT_EQ(bn_ct, mpz_class(ct_check));
        }
#endif
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
    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk, true);
        petace::solo::ahepaillier::Encryptor encryptor(pk);
        petace::solo::ahepaillier::Encryptor encryptor_with_sk(pk, sk);
        petace::solo::ahepaillier::Decryptor decryptor(sk);
        petace::solo::ahepaillier::Encoder encoder;
        {
            std::uint64_t in = 1234;
            petace::solo::ahepaillier::Plaintext pt;
            petace::solo::ahepaillier::Ciphertext ct;
            encoder.encode(in, pt);
            encryptor.encrypt(pt, ct);

            petace::solo::ahepaillier::Plaintext pt_check;
            decryptor.decrypt(ct, pt_check);
            std::uint64_t out = encoder.decode(pt_check);
            ASSERT_EQ(in, out);
        }
        {
            std::uint64_t in = 1234;
            petace::solo::ahepaillier::Plaintext pt;
            petace::solo::ahepaillier::Ciphertext ct;
            encoder.encode(in, pt);
            encryptor_with_sk.encrypt(pt, ct);

            petace::solo::ahepaillier::Plaintext pt_check;
            decryptor.decrypt(ct, pt_check);
            std::uint64_t out = encoder.decode(pt_check);
            ASSERT_EQ(in, out);
        }
        {
            std::vector<std::uint64_t> in = {1, 2, 3, 4, 5, 6, 7, 8};
            std::vector<petace::solo::ahepaillier::Plaintext> pt;
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;

            encoder.encode(in, pt);
            encryptor.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<std::uint64_t> out;

            encoder.decode(pt_check, out);

            ASSERT_EQ(in, out);
        }
        {
            std::vector<std::uint64_t> in = {1, 2, 3, 4, 5, 6, 7, 8};
            std::vector<petace::solo::ahepaillier::Plaintext> pt;
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encoder.encode(in, pt);

            encryptor_with_sk.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<std::uint64_t> out;

            encoder.decode(pt_check, out);

            ASSERT_EQ(in, out);
        }
#ifdef SOLO_USE_IPCL
        {
            std::vector<BigNumber> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<BigNumber> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = BigNumber(ipcl::PlainText(pt_check[i]));
            }
            ASSERT_EQ(in, out);
        }
        {
            std::vector<BigNumber> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor_with_sk.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<BigNumber> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = BigNumber(ipcl::PlainText(pt_check[i]));
            }
            ASSERT_EQ(in, out);
        }
        {
            std::vector<BigNumber> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor.encrypt_many(pt, ct);

            std::size_t n_square_byte_count = ((pk->key_length() + 7) / 8) * 2;
            std::vector<petace::solo::Byte> ct_bytes(ct.size() * n_square_byte_count);
            for (std::size_t i = 0; i < ct.size(); ++i) {
                ct[i].serialize_to_bytes(ct_bytes.data() + i * n_square_byte_count, n_square_byte_count);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct_deserialized(ct.size());
            for (std::size_t i = 0; i < ct.size(); ++i) {
                ct_deserialized[i].deserialize_from_bytes(
                        pk, ct_bytes.data() + i * n_square_byte_count, n_square_byte_count);
            }
            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct_deserialized, pt_check);
            std::vector<BigNumber> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = BigNumber(ipcl::PlainText(pt_check[i]));
            }
            ASSERT_EQ(in, out);
        }
#else
        {
            std::vector<mpz_class> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<mpz_class> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = mpz_class(pt_check[i]);
            }
            ASSERT_EQ(in, out);
        }
        {
            std::vector<mpz_class> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor_with_sk.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<mpz_class> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = mpz_class(pt_check[i]);
            }
            ASSERT_EQ(in, out);
        }
        {
            std::vector<mpz_class> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor.encrypt_many(pt, ct);
            std::size_t n_square_byte_count = ((pk->key_length() + 7) / 8) * 2;
            std::vector<petace::solo::Byte> ct_bytes(ct.size() * n_square_byte_count);
            for (std::size_t i = 0; i < ct.size(); ++i) {
                ct[i].serialize_to_bytes(ct_bytes.data() + i * n_square_byte_count, n_square_byte_count);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct_deserialized(ct.size());
            for (std::size_t i = 0; i < ct.size(); ++i) {
                ct_deserialized[i].deserialize_from_bytes(
                        pk, ct_bytes.data() + i * n_square_byte_count, n_square_byte_count);
            }
            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct_deserialized, pt_check);
            std::vector<mpz_class> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = mpz_class(pt_check[i]);
            }
            ASSERT_EQ(in, out);
        }
#endif
        { ASSERT_THROW(petace::solo::ahepaillier::Encryptor(nullptr), std::invalid_argument); }
        { ASSERT_THROW(petace::solo::ahepaillier::Encryptor(nullptr, nullptr), std::invalid_argument); }
        { ASSERT_THROW(petace::solo::ahepaillier::Decryptor(nullptr), std::invalid_argument); }
    }
    {
        std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
        std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
        petace::solo::ahepaillier::KeyGenerator generator(1024);
        generator.get_key_pair(sk, pk, false);
        petace::solo::ahepaillier::Encryptor encryptor(pk);
        petace::solo::ahepaillier::Encryptor encryptor_with_sk(pk, sk);
        petace::solo::ahepaillier::Decryptor decryptor(sk);
        petace::solo::ahepaillier::Encoder encoder;
        {
            std::uint64_t in = 1234;
            petace::solo::ahepaillier::Plaintext pt;
            petace::solo::ahepaillier::Ciphertext ct;
            encoder.encode(in, pt);
            encryptor.encrypt(pt, ct);

            petace::solo::ahepaillier::Plaintext pt_check;
            decryptor.decrypt(ct, pt_check);
            std::uint64_t out = encoder.decode(pt_check);
            ASSERT_EQ(in, out);
        }
        {
            std::uint64_t in = 1234;
            petace::solo::ahepaillier::Plaintext pt;
            petace::solo::ahepaillier::Ciphertext ct;
            encoder.encode(in, pt);
            encryptor_with_sk.encrypt(pt, ct);

            petace::solo::ahepaillier::Plaintext pt_check;
            decryptor.decrypt(ct, pt_check);
            std::uint64_t out = encoder.decode(pt_check);
            ASSERT_EQ(in, out);
        }
        {
            std::vector<std::uint64_t> in = {1, 2, 3, 4, 5, 6, 7, 8};
            std::vector<petace::solo::ahepaillier::Plaintext> pt;
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;

            encoder.encode(in, pt);
            encryptor.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<std::uint64_t> out;

            encoder.decode(pt_check, out);

            ASSERT_EQ(in, out);
        }
        {
            std::vector<std::uint64_t> in = {1, 2, 3, 4, 5, 6, 7, 8};
            std::vector<petace::solo::ahepaillier::Plaintext> pt;
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;

            encoder.encode(in, pt);
            encryptor_with_sk.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<std::uint64_t> out;
            encoder.decode(pt_check, out);
            ASSERT_EQ(in, out);
        }
#ifdef SOLO_USE_IPCL
        {
            std::vector<BigNumber> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<BigNumber> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = BigNumber(ipcl::PlainText(pt_check[i]));
            }
            ASSERT_EQ(in, out);
        }
        {
            std::vector<BigNumber> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor_with_sk.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<BigNumber> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = BigNumber(ipcl::PlainText(pt_check[i]));
            }
            ASSERT_EQ(in, out);
        }
        {
            std::vector<BigNumber> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor.encrypt_many(pt, ct);

            std::size_t n_square_byte_count = ((pk->key_length() + 7) / 8) * 2;
            std::vector<petace::solo::Byte> ct_bytes(ct.size() * n_square_byte_count);
            for (std::size_t i = 0; i < ct.size(); ++i) {
                ct[i].serialize_to_bytes(ct_bytes.data() + i * n_square_byte_count, n_square_byte_count);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct_deserialized(ct.size());
            for (std::size_t i = 0; i < ct.size(); ++i) {
                ct_deserialized[i].deserialize_from_bytes(
                        pk, ct_bytes.data() + i * n_square_byte_count, n_square_byte_count);
            }
            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct_deserialized, pt_check);
            std::vector<BigNumber> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = BigNumber(ipcl::PlainText(pt_check[i]));
            }
            ASSERT_EQ(in, out);
        }
#else
        {
            std::vector<mpz_class> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<mpz_class> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = mpz_class(pt_check[i]);
            }
            ASSERT_EQ(in, out);
        }
        {
            std::vector<mpz_class> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor_with_sk.encrypt_many(pt, ct);

            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct, pt_check);
            std::vector<mpz_class> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = mpz_class(pt_check[i]);
            }
            ASSERT_EQ(in, out);
        }
        {
            std::vector<mpz_class> in = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            std::vector<petace::solo::ahepaillier::Plaintext> pt(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                pt[i] = petace::solo::ahepaillier::Plaintext(in[i]);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct;
            encryptor.encrypt_many(pt, ct);
            std::size_t n_square_byte_count = ((pk->key_length() + 7) / 8) * 2;
            std::vector<petace::solo::Byte> ct_bytes(ct.size() * n_square_byte_count);
            for (std::size_t i = 0; i < ct.size(); ++i) {
                ct[i].serialize_to_bytes(ct_bytes.data() + i * n_square_byte_count, n_square_byte_count);
            }
            std::vector<petace::solo::ahepaillier::Ciphertext> ct_deserialized(ct.size());
            for (std::size_t i = 0; i < ct.size(); ++i) {
                ct_deserialized[i].deserialize_from_bytes(
                        pk, ct_bytes.data() + i * n_square_byte_count, n_square_byte_count);
            }
            std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
            decryptor.decrypt_many(ct_deserialized, pt_check);
            std::vector<mpz_class> out(pt_check.size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = mpz_class(pt_check[i]);
            }
            ASSERT_EQ(in, out);
        }
#endif
        { ASSERT_THROW(petace::solo::ahepaillier::Encryptor(nullptr), std::invalid_argument); }
        { ASSERT_THROW(petace::solo::ahepaillier::Encryptor(nullptr, nullptr), std::invalid_argument); }
        { ASSERT_THROW(petace::solo::ahepaillier::Decryptor(nullptr), std::invalid_argument); }
    }
}

TEST(AHEPaillierTest, Evaluator) {
    std::shared_ptr<petace::solo::ahepaillier::SecretKey> sk = nullptr;
    std::shared_ptr<petace::solo::ahepaillier::PublicKey> pk = nullptr;
    petace::solo::ahepaillier::KeyGenerator generator(1024);
    generator.get_key_pair(sk, pk, true);
    petace::solo::ahepaillier::Encryptor encryptor(pk, sk);
    petace::solo::ahepaillier::Decryptor decryptor(sk);
    petace::solo::ahepaillier::Encoder encoder;
    petace::solo::ahepaillier::Evaluator evaluator(pk);
    petace::solo::ahepaillier::Evaluator evaluator_with_sk(pk, sk);
    {
        std::vector<std::uint64_t> in_0 = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<std::uint64_t> in_1 = {8, 7, 6, 5, 4, 3, 2, 1};
        std::vector<std::uint64_t> in_sum = {9, 9, 9, 9, 9, 9, 9, 9};
        std::vector<std::uint64_t> in_check;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_0;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_1;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_0;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_1;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_out;

        encoder.encode(in_0, pt_0);
        encoder.encode(in_1, pt_1);
        encryptor.encrypt_many(pt_0, ct_0);
        encryptor.encrypt_many(pt_1, ct_1);

        evaluator.add_many(ct_0, ct_1, ct_out);
        decryptor.decrypt_many(ct_out, pt_check);
        encoder.decode(pt_check, in_check);
        ASSERT_EQ(in_check, in_sum);
    }
    {
        std::vector<std::uint64_t> in_0 = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<std::uint64_t> in_1 = {8, 7, 6, 5, 4, 3, 2, 1};
        std::vector<std::uint64_t> in_sum = {9, 9, 9, 9, 9, 9, 9, 9};
        std::vector<std::uint64_t> in_check;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_0;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_1;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_0;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_1;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_out;

        encoder.encode(in_0, pt_0);
        encoder.encode(in_1, pt_1);
        encryptor.encrypt_many(pt_0, ct_0);

        evaluator.add_many(ct_0, pt_1, ct_out);
        decryptor.decrypt_many(ct_out, pt_check);
        encoder.decode(pt_check, in_check);
        ASSERT_EQ(in_check, in_sum);
    }
    {
        std::vector<std::uint64_t> in_0 = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<std::uint64_t> in_1 = {8, 7, 6, 5, 4, 3, 2, 1};
        std::vector<std::uint64_t> in_mul = {8, 14, 18, 20, 20, 18, 14, 8};
        std::vector<std::uint64_t> in_check;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_0;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_1;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_0;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_1;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_out;

        encoder.encode(in_0, pt_0);
        encoder.encode(in_1, pt_1);
        encryptor.encrypt_many(pt_0, ct_0);

        evaluator.mul_many(ct_0, pt_1, ct_out);
        decryptor.decrypt_many(ct_out, pt_check);
        encoder.decode(pt_check, in_check);
        ASSERT_EQ(in_check, in_mul);
    }
    {
        std::vector<std::uint64_t> in_0 = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<std::uint64_t> in_1 = {8, 7, 6, 5, 4, 3, 2, 1};
        std::vector<std::uint64_t> in_mul = {8, 14, 18, 20, 20, 18, 14, 8};
        std::vector<std::uint64_t> in_check;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_0;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_1;
        std::vector<petace::solo::ahepaillier::Plaintext> pt_check;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_0;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_1;
        std::vector<petace::solo::ahepaillier::Ciphertext> ct_out;

        encoder.encode(in_0, pt_0);
        encoder.encode(in_1, pt_1);
        encryptor.encrypt_many(pt_0, ct_0);

        evaluator_with_sk.mul_many(ct_0, pt_1, ct_out);
        decryptor.decrypt_many(ct_out, pt_check);
        encoder.decode(pt_check, in_check);
        ASSERT_EQ(in_check, in_mul);
    }
}
#ifdef SOLO_USE_IPCL
TEST(AHEPaillierTest, Utils) {
    const std::vector<int> bits_vec = {2, 31, 32, 482, 511, 512, 994, 1023, 1024, 2018, 2047, 2048};
    for (std::size_t i = 0; i < bits_vec.size(); ++i) {
        auto bn = BigNumber::One();
        petace::solo::ahepaillier::utils::bn_lshift(bn, bits_vec[i]);
    }
}
#endif
