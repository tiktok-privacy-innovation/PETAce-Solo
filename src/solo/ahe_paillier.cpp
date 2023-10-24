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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

#include "ipcl/ipcl.hpp"

namespace petace {
namespace solo {
namespace ahepaillier {

static BigNum bn_from_u64(std::uint64_t in) {
    std::vector<std::uint32_t> vec_u32 = {static_cast<std::uint32_t>(in), static_cast<std::uint32_t>(in >> 32)};
    return BigNum(vec_u32.data(), 2);
}

static std::uint64_t u64_from_bn(const BigNum& in) {
    std::size_t length = in.DwordSize();
    if (length == 0) {
        return 0;
    }
    std::vector<std::uint32_t> data;
    in.num2vec(data);
    std::uint64_t value = data[0];
    if (length > 1) {
        value += static_cast<std::uint64_t>(data[1]) << 32;
    }
    return value;
}

void Serialization::bn_from_bytes(const Byte* in, std::size_t in_byte_count, BigNum& out) {
    if (in == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    std::size_t length = (in_byte_count + 3) / 4;
    std::vector<std::uint32_t> vec_u32(length, 0);
    for (std::size_t i = 0; i < length; ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            std::size_t cur_idx = i * 4 + j;
            if (cur_idx < in_byte_count) {
                vec_u32[i] += reinterpret_cast<const uint8_t*>(in)[cur_idx] << (8 * j);
            }
        }
    }
    out = BigNum(vec_u32.data(), static_cast<int>(length));
}

void Serialization::bn_to_bytes(const BigNum& in, Byte* out, std::size_t out_byte_count) {
    if (out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    std::size_t length = (in.BitSize() + 7) / 8;
    std::vector<std::uint8_t> temp(length);
    in.num2char(temp);
    std::size_t byte_count = std::min(length, out_byte_count);
    for (std::size_t idx = 0; idx < byte_count; ++idx) {
        out[idx] = static_cast<Byte>(temp[idx]);
    }
    if (length < out_byte_count) {
        std::fill_n(out + length, out_byte_count - length, Byte('\x00'));
    }
}

Serialization::Serialization(std::size_t key_length, bool enable_djn) {
    if (key_length != 1024 && key_length != 2048) {
        throw std::invalid_argument("AHE key length is invalid.");
    }
    key_length_ = key_length;
    n_byte_count_ = (key_length_ + 7) / 8;
    enable_djn_ = enable_djn;
}

std::size_t Serialization::public_key_byte_count() const noexcept {
    return n_byte_count_ * (1 + 2 * static_cast<std::size_t>(enable_djn_));
}

std::size_t Serialization::secret_key_byte_count() const noexcept {
    return n_byte_count_ * 2;
}

void Serialization::serialize_public_key_to_bytes(
        const std::shared_ptr<PublicKey>& pk, Byte* out, std::size_t out_byte_count) const {
    if (pk == nullptr) {
        throw std::invalid_argument("pk is nullptr");
    }
    if (out == nullptr && out_byte_count != 0) {
        throw std::invalid_argument("out is nullptr");
    }
    if (out_byte_count != public_key_byte_count()) {
        throw std::invalid_argument("out_byte_count is not equal to public_key_byte_count");
    }
    bn_to_bytes(*(pk->getN()), out, n_byte_count_);
    if (enable_djn_) {
        bn_to_bytes(pk->getHS(), out + n_byte_count_, out_byte_count - n_byte_count_);
    }
}

void Serialization::serialize_secret_key_to_bytes(
        const std::shared_ptr<SecretKey>& sk, Byte* out, std::size_t out_byte_count) const {
    if (sk == nullptr) {
        throw std::invalid_argument("sk is nullptr");
    }
    if (out == nullptr && out_byte_count != 0) {
        throw std::invalid_argument("out is nullptr");
    }
    if (out_byte_count != secret_key_byte_count()) {
        throw std::invalid_argument("out_byte_count is not equal to secret_key_byte_count");
    }
    bn_to_bytes(*(sk->getN()), out, n_byte_count_);
    std::size_t pq_byte_count = n_byte_count_ / 2;
    bn_to_bytes(*(sk->getP()), out + n_byte_count_, pq_byte_count);
    bn_to_bytes(*(sk->getQ()), out + n_byte_count_ + pq_byte_count, pq_byte_count);
}

void Serialization::deserialize_public_key_from_bytes(
        const Byte* in, std::size_t in_byte_count, std::shared_ptr<PublicKey>& pk) const {
    if (in == nullptr && in_byte_count != 0) {
        throw std::invalid_argument("in is nullptr");
    }
    if (in_byte_count != public_key_byte_count()) {
        throw std::invalid_argument("in_byte_count is not equal to public_key_byte_count");
    }
    pk = std::make_shared<PublicKey>();
    if (enable_djn_) {
        BigNum n;
        bn_from_bytes(in, n_byte_count_, n);
        BigNum hs;
        bn_from_bytes(in + n_byte_count_, in_byte_count - n_byte_count_, hs);
        pk->create(n, static_cast<int>(n_byte_count_ * 8), hs, static_cast<int>(n_byte_count_ * 4));
    } else {
        BigNum n;
        bn_from_bytes(in, n_byte_count_, n);
        pk->create(n, static_cast<int>(n_byte_count_ * 8), false);
    }
}

void Serialization::deserialize_secret_key_from_bytes(
        const Byte* in, std::size_t in_byte_count, std::shared_ptr<SecretKey>& sk) const {
    if (in == nullptr && in_byte_count != 0) {
        throw std::invalid_argument("in is nullptr");
    }
    if (in_byte_count != secret_key_byte_count()) {
        throw std::invalid_argument("in_byte_count is not equal to secret_key_byte_count");
    }
    BigNum n;
    bn_from_bytes(in, n_byte_count_, n);
    BigNum p;
    BigNum q;
    std::size_t pq_byte_count = n_byte_count_ / 2;
    bn_from_bytes(in + n_byte_count_, pq_byte_count, p);
    bn_from_bytes(in + n_byte_count_ + pq_byte_count, pq_byte_count, q);
    sk = std::make_shared<ipcl::PrivateKey>(n, p, q);
}

Plaintext& Plaintext::operator=(const ipcl::PlainText& other) noexcept {
    ipcl::PlainText::operator=(other);
    return *this;
}

Plaintext::operator std::vector<BigNumber>() const {
    return ipcl::PlainText::operator std::vector<BigNumber>();
}

std::size_t Plaintext::slot_count() const noexcept {
    return ipcl::PlainText::getSize();
}

Ciphertext& Ciphertext::operator=(const ipcl::CipherText& other) noexcept {
    ipcl::CipherText::operator=(other);
    return *this;
}

Ciphertext::operator std::vector<BigNumber>() const {
    return getTexts();
}

std::size_t Ciphertext::slot_count() const noexcept {
    return ipcl::CipherText::getSize();
}

void Encoder::encode(std::uint64_t in, Plaintext& out) const noexcept {
    out = ipcl::PlainText(bn_from_u64(in));
}

std::uint64_t Encoder::decode(const Plaintext& in) const noexcept {
    return u64_from_bn(BigNum(in));
}

void Encoder::encode(const std::vector<std::uint64_t>& in, Plaintext& out) const noexcept {
    std::vector<BigNum> tmp(in.size());
    std::transform(in.begin(), in.end(), tmp.begin(), [&](std::uint64_t val) { return bn_from_u64(val); });
    out = ipcl::PlainText(tmp);
}

void Encoder::decode(const Plaintext& in, std::vector<std::uint64_t>& out) const noexcept {
    std::vector<BigNum> tmp = std::vector<BigNum>(in);
    out.resize(tmp.size());
    std::transform(tmp.begin(), tmp.end(), out.begin(), [&](BigNum bn) { return u64_from_bn(bn); });
}

void KeyGenerator::get_key_pair(
        std::shared_ptr<SecretKey>& sk, std::shared_ptr<PublicKey>& pk, bool enable_djn) const noexcept {
    ipcl::KeyPair key_pair = ipcl::generateKeypair(static_cast<int64_t>(key_length_), enable_djn);
    sk = std::make_shared<SecretKey>(
            *(key_pair.priv_key.getN()), *(key_pair.priv_key.getP()), *(key_pair.priv_key.getQ()));
    pk = std::make_shared<PublicKey>();
    if (enable_djn) {
        pk->create(*(key_pair.pub_key.getN()), key_pair.pub_key.getBits(), key_pair.pub_key.getHS(),
                key_pair.pub_key.getRandBits());
    } else {
        pk->create(*(key_pair.pub_key.getN()), key_pair.pub_key.getBits(), false);
    }
}

Encryptor::Encryptor(const std::shared_ptr<PublicKey>& pk, bool enable_djn) {
    if (pk == nullptr) {
        throw std::invalid_argument("pk is nullptr");
    }
    pk_ = std::make_shared<ipcl::PublicKey>();
    if (enable_djn) {
        pk_->create(*(pk->getN()), pk->getBits(), pk->getHS(), pk->getRandBits());
    } else {
        pk_->create(*(pk->getN()), pk->getBits(), false);
    }
}

void Encryptor::encrypt(const Plaintext& in, Ciphertext& out) const noexcept {
    ipcl::setHybridMode(ipcl::HybridMode::IPP);
    out = pk_->encrypt(in, true);
    ipcl::setHybridOff();
}

Decryptor::Decryptor(const std::shared_ptr<SecretKey>& sk) {
    if (sk == nullptr) {
        throw std::invalid_argument("sk is nullptr");
    }
    sk_ = std::make_shared<SecretKey>(*(sk->getN()), *(sk->getP()), *(sk->getQ()));
}

void Decryptor::decrypt(const Ciphertext& in, Plaintext& out) const noexcept {
    ipcl::setHybridMode(ipcl::HybridMode::IPP);
    out = sk_->decrypt(in);
    ipcl::setHybridOff();
}

void Evaluator::add(const Ciphertext& in_0, const Ciphertext& in_1, Ciphertext& out) const noexcept {
    out = in_0 + in_1;
}

void Evaluator::add(const Ciphertext& in_0, const Plaintext& in_1, Ciphertext& out) const noexcept {
    out = in_0 + in_1;
}

void Evaluator::mul(const Ciphertext& in_0, const Plaintext& in_1, Ciphertext& out) const noexcept {
    out = in_0 * in_1;
}

namespace utils {
void bn_lshift(BigNum& in, const std::size_t bits) {
    std::size_t length = (bits + 1 + 31) / 32;
    std::size_t remainder = bits % 32;
    std::vector<std::uint32_t> temp(length, 0);
    temp[length - 1] = 1 << remainder;
    BigNumber shift_bn(temp.data(), static_cast<int>(length));
    in *= shift_bn;
}

BigNum get_random_bn(std::size_t bits) {
    return ipcl::getRandomBN(bits);
}
}  // namespace utils

}  // namespace ahepaillier
}  // namespace solo
}  // namespace petace
#endif
