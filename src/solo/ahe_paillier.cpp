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

#include <omp.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

#ifdef SOLO_USE_IPCL
#include "ipcl/ipcl.hpp"
#else
#include "solo/sampling.h"
#endif

namespace petace {
namespace solo {
namespace ahepaillier {

constexpr std::size_t kAHEMaxRandomBits = 8192;
constexpr std::size_t kAHEMaxRandomByteCount = 1024;

PublicKey::PublicKey(std::size_t key_length, bool enable_djn)
        : key_length_(key_length), n_byte_count_((key_length_ + 7) / 8), enable_djn_(enable_djn), pk_set_(false) {
    if (key_length_ != 1024 && key_length_ != 2048) {
        throw std::invalid_argument("AHE key length is invalid.");
    }
}

#ifdef SOLO_USE_IPCL
PublicKey::PublicKey(const ipcl::PublicKey& pk) : enable_djn_(pk.isDJN()) {
    key_length_ = pk.getBits();
    n_byte_count_ = (key_length_ + 7) / 8;
    if (key_length_ != 1024 && key_length_ != 2048) {
        throw std::invalid_argument("AHE key length is invalid.");
    }
    pk_ = std::make_shared<ipcl::PublicKey>();
    if (enable_djn_) {
        pk_->create(*(pk.getN()), pk.getBits(), pk.getHS(), pk.getRandBits());
    } else {
        pk_->create(*(pk.getN()), pk.getBits(), false);
    }
    pk_set_ = true;
}
#else
PublicKey::PublicKey(const mpz_class& n)
        : n_(n),
          g_(n + 1),
          n_square_(n * n),
          hs_(0),
          key_length_(mpz_sizeinbase(n.get_mpz_t(), 2)),
          n_byte_count_((key_length_ + 7) / 8),
          enable_djn_(false),
          pk_set_(true) {
    if (key_length_ != 1024 && key_length_ != 2048) {
        throw std::invalid_argument("AHE key length is invalid.");
    }
}

PublicKey::PublicKey(const mpz_class& n, const mpz_class& hs)
        : n_(n),
          g_(n + 1),
          n_square_(n * n),
          hs_(hs),
          key_length_(mpz_sizeinbase(n.get_mpz_t(), 2)),
          n_byte_count_((key_length_ + 7) / 8),
          enable_djn_(true),
          pk_set_(true) {
    if (key_length_ != 1024 && key_length_ != 2048) {
        throw std::invalid_argument("AHE key length is invalid.");
    }
}
#endif

std::size_t PublicKey::public_key_byte_count() const noexcept {
    return n_byte_count_ * (1 + 2 * static_cast<std::size_t>(enable_djn_));
}

void PublicKey::serialize_to_bytes(Byte* out, std::size_t out_byte_count) const {
    if (pk_set_ == false) {
        throw std::invalid_argument("pk is not set");
    }
#ifdef SOLO_USE_IPCL
    if (pk_ == nullptr) {
        throw std::invalid_argument("pk is nullptr");
    }
#endif
    if (out == nullptr && out_byte_count != 0) {
        throw std::invalid_argument("out is nullptr");
    }
    if (out_byte_count != public_key_byte_count()) {
        throw std::invalid_argument("out_byte_count is not equal to public_key_byte_count");
    }
#ifdef SOLO_USE_IPCL
    Serialization::ipcl_bn_to_bytes(*(pk_->getN()), out, n_byte_count_);
    if (enable_djn_) {
        Serialization::ipcl_bn_to_bytes(pk_->getHS(), out + n_byte_count_, out_byte_count - n_byte_count_);
    }
#else
    Serialization::mpz_bn_to_bytes(n_, out, n_byte_count_);
    if (enable_djn_) {
        Serialization::mpz_bn_to_bytes(hs_, out + n_byte_count_, out_byte_count - n_byte_count_);
    }
#endif
}

void PublicKey::deserialize_from_bytes(const Byte* in, std::size_t in_byte_count) {
    if (pk_set_ == true) {
        throw std::invalid_argument("pk is already set");
    }
    if (in == nullptr && in_byte_count != 0) {
        throw std::invalid_argument("in is nullptr");
    }
    if (in_byte_count != public_key_byte_count()) {
        throw std::invalid_argument("in_byte_count is not equal to public_key_byte_count");
    }
#ifdef SOLO_USE_IPCL
    pk_ = std::make_shared<ipcl::PublicKey>();
    if (enable_djn_) {
        BigNumber n;
        Serialization::ipcl_bn_from_bytes(in, n_byte_count_, n);
        BigNumber hs;
        Serialization::ipcl_bn_from_bytes(in + n_byte_count_, in_byte_count - n_byte_count_, hs);
        pk_->create(n, static_cast<int>(n_byte_count_ * 8), hs, static_cast<int>(n_byte_count_ * 4));
    } else {
        BigNumber n;
        Serialization::ipcl_bn_from_bytes(in, n_byte_count_, n);
        pk_->create(n, static_cast<int>(n_byte_count_ * 8), false);
    }
#else
    Serialization::mpz_bn_from_bytes(in, n_byte_count_, n_);
    g_ = n_ + 1;
    n_square_ = n_ * n_;
    if (enable_djn_) {
        Serialization::mpz_bn_from_bytes(in + n_byte_count_, in_byte_count - n_byte_count_, hs_);
    } else {
        hs_ = 0;
    }
#endif
    pk_set_ = true;
}

SecretKey::SecretKey(std::size_t key_length)
        : key_length_(key_length), n_byte_count_((key_length_ + 7) / 8), sk_set_(false) {
    if (key_length_ != 1024 && key_length_ != 2048) {
        throw std::invalid_argument("AHE key length is invalid.");
    }
}

#ifdef SOLO_USE_IPCL
SecretKey::SecretKey(const ipcl::PrivateKey& sk) {
    sk_ = std::make_shared<ipcl::PrivateKey>(*(sk.getN()), *(sk.getP()), *(sk.getQ()));
    key_length_ = sk.getN()->BitSize();
    n_byte_count_ = (key_length_ + 7) / 8;
    if (key_length_ != 1024 && key_length_ != 2048) {
        throw std::invalid_argument("AHE key length is invalid.");
    }
    sk_set_ = true;
}
#else
SecretKey::SecretKey(const mpz_class& n, const mpz_class& p, const mpz_class& q)
        : n_(n), p_(p), q_(q), key_length_(mpz_sizeinbase(n.get_mpz_t(), 2)), n_byte_count_((key_length_ + 7) / 8) {
    if (key_length_ != 1024 && key_length_ != 2048) {
        throw std::invalid_argument("AHE key length is invalid.");
    }
    if (n <= 1 || (n != p * q)) {
        throw std::invalid_argument("invalid sk.");
    }
    initilize_sk();
    sk_set_ = true;
}

void SecretKey::initilize_sk() {
    g_ = n_ + 1;
    n_square_ = n_ * n_;
    lambda_ = (p_ - 1) * (q_ - 1) / 2;
    p_square_ = p_ * p_;
    q_square_ = q_ * q_;
    mpz_invert(p_inv_.get_mpz_t(), p_.get_mpz_t(), q_.get_mpz_t());
    mpz_invert(q_inv_.get_mpz_t(), q_.get_mpz_t(), p_.get_mpz_t());

    mpz_invert(p_square_inv_.get_mpz_t(), p_square_.get_mpz_t(), q_square_.get_mpz_t());
    mpz_invert(q_square_inv_.get_mpz_t(), q_square_.get_mpz_t(), p_square_.get_mpz_t());

    mpz_class p_minus_one = p_ - 1;
    mpz_class q_minus_one = q_ - 1;

    mpz_powm(hp_.get_mpz_t(), g_.get_mpz_t(), p_minus_one.get_mpz_t(), p_square_.get_mpz_t());
    mpz_powm(hq_.get_mpz_t(), g_.get_mpz_t(), q_minus_one.get_mpz_t(), q_square_.get_mpz_t());

    hp_ = (hp_ - 1) / p_;
    hq_ = (hq_ - 1) / q_;

    mpz_invert(hp_.get_mpz_t(), hp_.get_mpz_t(), p_.get_mpz_t());
    mpz_invert(hq_.get_mpz_t(), hq_.get_mpz_t(), q_.get_mpz_t());
}
#endif

std::size_t SecretKey::secret_key_byte_count() const noexcept {
    return n_byte_count_ * 2;
}

void SecretKey::serialize_to_bytes(Byte* out, std::size_t out_byte_count) const {
    if (sk_set_ == false) {
        throw std::invalid_argument("sk is not set");
    }
#ifdef SOLO_USE_IPCL
    if (sk_ == nullptr) {
        throw std::invalid_argument("sk is nullptr");
    }
#endif
    if (out == nullptr && out_byte_count != 0) {
        throw std::invalid_argument("out is nullptr");
    }
    if (out_byte_count != secret_key_byte_count()) {
        throw std::invalid_argument("out_byte_count is not equal to secret_key_byte_count");
    }
#ifdef SOLO_USE_IPCL
    Serialization::ipcl_bn_to_bytes(*(sk_->getN()), out, n_byte_count_);
    std::size_t pq_byte_count = n_byte_count_ / 2;
    Serialization::ipcl_bn_to_bytes(*(sk_->getP()), out + n_byte_count_, pq_byte_count);
    Serialization::ipcl_bn_to_bytes(*(sk_->getQ()), out + n_byte_count_ + pq_byte_count, pq_byte_count);
#else
    Serialization::mpz_bn_to_bytes(n_, out, n_byte_count_);
    std::size_t pq_byte_count = n_byte_count_ / 2;
    Serialization::mpz_bn_to_bytes(p_, out + n_byte_count_, pq_byte_count);
    Serialization::mpz_bn_to_bytes(q_, out + n_byte_count_ + pq_byte_count, pq_byte_count);
#endif
}

void SecretKey::deserialize_from_bytes(const Byte* in, std::size_t in_byte_count) {
    if (sk_set_ == true) {
        throw std::invalid_argument("sk is already set");
    }
    if (in == nullptr && in_byte_count != 0) {
        throw std::invalid_argument("in is nullptr");
    }
    if (in_byte_count != secret_key_byte_count()) {
        throw std::invalid_argument("in_byte_count is not equal to secret_key_byte_count");
    }
#ifdef SOLO_USE_IPCL
    BigNumber n;
    Serialization::ipcl_bn_from_bytes(in, n_byte_count_, n);
    BigNumber p;
    BigNumber q;
    std::size_t pq_byte_count = n_byte_count_ / 2;
    Serialization::ipcl_bn_from_bytes(in + n_byte_count_, pq_byte_count, p);
    Serialization::ipcl_bn_from_bytes(in + n_byte_count_ + pq_byte_count, pq_byte_count, q);
    sk_ = std::make_shared<ipcl::PrivateKey>(n, p, q);
#else
    Serialization::mpz_bn_from_bytes(in, n_byte_count_, n_);
    std::size_t pq_byte_count = n_byte_count_ / 2;
    Serialization::mpz_bn_from_bytes(in + n_byte_count_, pq_byte_count, p_);
    Serialization::mpz_bn_from_bytes(in + n_byte_count_ + pq_byte_count, pq_byte_count, q_);
    initilize_sk();
#endif
    sk_set_ = true;
}

#ifndef SOLO_USE_IPCL
void SecretKey::powm_crt(const mpz_class& base, const mpz_class& exponent, mpz_class& out) const {
    mpz_class y0;
    mpz_class y1;
    mpz_powm(y0.get_mpz_t(), base.get_mpz_t(), exponent.get_mpz_t(), p_square_.get_mpz_t());
    mpz_powm(y1.get_mpz_t(), base.get_mpz_t(), exponent.get_mpz_t(), q_square_.get_mpz_t());

    out = (y0 * q_square_inv_ * q_square_ + y1 * p_square_inv_ * p_square_) % n_square_;
}

void SecretKey::decrypt(const mpz_class& cipher, mpz_class& out) const {
    mpz_class c_p = p_ - 1;
    mpz_powm(c_p.get_mpz_t(), cipher.get_mpz_t(), c_p.get_mpz_t(), p_square_.get_mpz_t());
    mpz_class l_p = (c_p - 1) / p_;
    mpz_class m_p = l_p * hp_ % p_;
    mpz_class c_q = q_ - 1;
    mpz_powm(c_q.get_mpz_t(), cipher.get_mpz_t(), c_q.get_mpz_t(), q_square_.get_mpz_t());
    mpz_class l_q = (c_q - 1) / q_;
    mpz_class m_q = l_q * hq_ % q_;
    out = (m_p * q_inv_ * q_ + m_q * p_inv_ * p_) % n_;
}
#endif

#ifdef SOLO_USE_IPCL
static BigNumber ipcl_bn_from_u64(std::uint64_t in) {
    std::vector<std::uint32_t> vec_u32 = {static_cast<std::uint32_t>(in), static_cast<std::uint32_t>(in >> 32)};
    return BigNumber(vec_u32.data(), 2);
}

static std::uint64_t u64_from_ipcl_bn(const BigNumber& in) {
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

void Serialization::ipcl_bn_from_bytes(const Byte* in, std::size_t in_byte_count, BigNumber& out) {
    if (in == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    if (in != nullptr && in_byte_count > kAHEMaxRandomByteCount) {
        throw std::invalid_argument("in is too large.");
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
    out = BigNumber(vec_u32.data(), static_cast<int>(length));
}

void Serialization::ipcl_bn_to_bytes(const BigNumber& in, Byte* out, std::size_t out_byte_count) {
    if (out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    std::size_t length = (in.BitSize() + 7) / 8;
    if (length == 0) {
        throw std::invalid_argument("the length of in is zero.");
    }
    if (length > kAHEMaxRandomByteCount) {
        throw std::invalid_argument("in is too large.");
    }
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
#else
void Serialization::mpz_bn_from_bytes(const Byte* in, std::size_t in_byte_count, mpz_class& out) {
    if (in == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    if (in != nullptr && in_byte_count > kAHEMaxRandomByteCount) {
        throw std::invalid_argument("in is too large.");
    }
    mpz_import(out.get_mpz_t(), in_byte_count, -1, sizeof(Byte), -1, 0, in);
}

void Serialization::mpz_bn_to_bytes(const mpz_class& in, Byte* out, std::size_t out_byte_count) {
    if (out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    std::size_t length = (mpz_sizeinbase(in.get_mpz_t(), 2) + 7) / 8;
    if (length == 0) {
        throw std::invalid_argument("the length of in is zero.");
    }
    if (length > kAHEMaxRandomByteCount) {
        throw std::invalid_argument("in is too large.");
    }
    mpz_export(out, nullptr, -1, sizeof(Byte), -1, 0, in.get_mpz_t());
    if (length < out_byte_count) {
        std::fill_n(out + length, out_byte_count - length, Byte('\x00'));
    }
}
#endif

void Plaintext::serialize_to_bytes(Byte* out, std::size_t out_byte_count) const {
    if (out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
#ifdef SOLO_USE_IPCL
    std::size_t pt_byte_count = (BigNumber(pt_).BitSize() + 7) / 8;
    if (pt_byte_count > out_byte_count) {
        throw std::invalid_argument("the byte count of pt is bigger than out_byte_count.");
    }
    Serialization::ipcl_bn_to_bytes(BigNumber(pt_), out, out_byte_count);
#else
    std::size_t pt_byte_count = (mpz_sizeinbase(pt_.get_mpz_t(), 2) + 7) / 8;
    if (pt_byte_count > out_byte_count) {
        throw std::invalid_argument("the byte count of pt is bigger than out_byte_count.");
    }
    Serialization::mpz_bn_to_bytes(pt_, out, out_byte_count);
#endif
}

void Plaintext::deserialize_from_bytes(const Byte* in, std::size_t in_byte_count) {
    if (in == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    if (in != nullptr && in_byte_count > kAHEMaxRandomByteCount) {
        throw std::invalid_argument("in is too large.");
    }
#ifdef SOLO_USE_IPCL
    BigNumber bn;
    Serialization::ipcl_bn_from_bytes(in, in_byte_count, bn);
    pt_ = ipcl::PlainText(bn);
#else
    Serialization::mpz_bn_from_bytes(in, in_byte_count, pt_);
#endif
}

Plaintext& Plaintext::operator=(const Plaintext& other) noexcept {
    this->pt_ = other.pt_;
    return *this;
}

#ifdef SOLO_USE_IPCL
Plaintext::operator ipcl::PlainText() const {
    return pt_;
}
#else

Plaintext::operator mpz_class() const {
    return pt_;
}
#endif

void Ciphertext::serialize_to_bytes(Byte* out, std::size_t out_byte_count) const {
    if (out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
#ifdef SOLO_USE_IPCL
    std::size_t ct_byte_count = (ct_.getElement(0).BitSize() + 7) / 8;
    if (ct_byte_count > out_byte_count) {
        throw std::invalid_argument("the byte count of ct is bigger than out_byte_count");
    }
    Serialization::ipcl_bn_to_bytes(ct_.getElement(0), out, out_byte_count);
#else
    std::size_t ct_byte_count = (mpz_sizeinbase(ct_.get_mpz_t(), 2) + 7) / 8;
    if (ct_byte_count > out_byte_count) {
        throw std::invalid_argument("the byte count of ct is bigger than out_byte_count");
    }
    Serialization::mpz_bn_to_bytes(ct_, out, out_byte_count);
#endif
}

void Ciphertext::deserialize_from_bytes(const std::shared_ptr<PublicKey>& pk, Byte* in, std::size_t in_byte_count) {
    if (pk == nullptr) {
        throw std::invalid_argument("pk is nullptr");
    }
    if (in == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    if (in != nullptr && in_byte_count > kAHEMaxRandomByteCount) {
        throw std::invalid_argument("in is too large.");
    }
#ifdef SOLO_USE_IPCL
    BigNumber bn;
    Serialization::ipcl_bn_from_bytes(in, in_byte_count, bn);
    ct_ = ipcl::CipherText(*(pk->pk()), bn);
#else
    Serialization::mpz_bn_from_bytes(in, in_byte_count, ct_);
#endif
}

Ciphertext& Ciphertext::operator=(const Ciphertext& other) noexcept {
    this->ct_ = other.ct_;
    return *this;
}

#ifdef SOLO_USE_IPCL
Ciphertext::operator ipcl::CipherText() const {
    return ct_;
}

#else
Ciphertext::operator mpz_class() const {
    return ct_;
}
#endif

void Encoder::encode(std::uint64_t in, Plaintext& out) const noexcept {
#ifdef SOLO_USE_IPCL
    out = Plaintext(ipcl_bn_from_u64(in));
#else
    mpz_class bn;
    mpz_import(bn.get_mpz_t(), 1, 1, sizeof(in), 0, 0, &in);
    out = Plaintext(bn);
#endif
}

std::uint64_t Encoder::decode(const Plaintext& in) const noexcept {
#ifdef SOLO_USE_IPCL
    return u64_from_ipcl_bn(BigNumber(ipcl::PlainText(in)));
#else
    Plaintext pt;
    std::uint64_t out(0);
    mpz_class mod(1);
    std::size_t num_bits = 8 * sizeof(std::uint64_t);
    mod <<= num_bits;
    mod = mpz_class(in) % mod;
    mpz_export(&out, nullptr, 1, sizeof(std::uint64_t), 0, 0, mod.get_mpz_t());
    return out;
#endif
}

void Encoder::encode(const std::vector<std::uint64_t>& in, std::vector<Plaintext>& out) const noexcept {
    out.resize(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        encode(in[i], out[i]);
    }
}

void Encoder::decode(const std::vector<Plaintext>& in, std::vector<std::uint64_t>& out) const noexcept {
    out.resize(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        out[i] = decode(in[i]);
    }
}

void KeyGenerator::get_key_pair(std::shared_ptr<SecretKey>& sk, std::shared_ptr<PublicKey>& pk, bool enable_djn,
        PRNGScheme prng_scheme) const noexcept {
#ifdef SOLO_USE_IPCL
    ipcl::KeyPair key_pair = ipcl::generateKeypair(static_cast<int64_t>(key_length_), enable_djn);
    sk = std::make_shared<SecretKey>(key_pair.priv_key);
    pk = std::make_shared<PublicKey>(key_pair.pub_key);
    (void)prng_scheme;
#else
    std::size_t p_length = (key_length_ + 1) / 2;

    mpz_class n;
    mpz_class p;
    mpz_class q;

    mpz_class gcd = 0;
    mpz_class p_minus_one;
    mpz_class q_minus_one;

    PRNGFactory prng_factory = PRNGFactory(prng_scheme);
    auto prng = prng_factory.create();

    std::size_t n_len = 0;
    do {
        p = generate_prime(p_length, prng);
        q = generate_prime(p_length, prng);
        if (p != q && (p % 4) == 3 && (q % 4) == 3) {
            p_minus_one = p - 1;
            q_minus_one = q - 1;
            mpz_gcd(gcd.get_mpz_t(), p_minus_one.get_mpz_t(), q_minus_one.get_mpz_t());
            n = p * q;
            n_len = mpz_sizeinbase(n.get_mpz_t(), 2);
        }
    } while (gcd != 2 || n_len != key_length_);

    if (enable_djn) {
        mpz_class hs;
        mpz_class rand;
        mpz_class n_square = n * n;
        do {
            rand = utils::get_random_mpz(key_length_ + 128, prng);
            mpz_gcd(gcd.get_mpz_t(), rand.get_mpz_t(), n.get_mpz_t());
        } while (gcd != 1);
        mpz_class x = rand % n;
        mpz_class x_square = x * x;
        mpz_class h = (-1 * x_square) % n;
        mpz_powm(hs.get_mpz_t(), h.get_mpz_t(), n.get_mpz_t(), n_square.get_mpz_t());
        pk = std::make_shared<PublicKey>(n, hs);
    } else {
        pk = std::make_shared<PublicKey>(n);
    }
    sk = std::make_shared<SecretKey>(n, p, q);
#endif
}

#ifndef SOLO_USE_IPCL
mpz_class KeyGenerator::generate_prime(std::size_t bit_count, std::shared_ptr<PRNG>& prng) {
    mpz_class p = 0;
    do {
        p = utils::get_random_mpz(bit_count, prng);
        p |= mpz_class(1) << bit_count - 1;
    } while (prime_test(p) == 0 || p == 0);
    return p;
}

int KeyGenerator::prime_test(const mpz_class& in) {
    std::size_t length = mpz_sizeinbase(in.get_mpz_t(), 2);
    return mpz_probab_prime_p(in.get_mpz_t(), static_cast<int>(miller_rabin_iteration_num(length)));
}

std::size_t KeyGenerator::miller_rabin_iteration_num(std::size_t prime_length) {
    return prime_length >= 3747   ? 3
           : prime_length >= 1345 ? 4
           : prime_length >= 476  ? 5
           : prime_length >= 400  ? 6
           : prime_length >= 347  ? 7
           : prime_length >= 308  ? 4
           : prime_length >= 55   ? 27
                                  : 34;
}
#endif

Encryptor::Encryptor(const std::shared_ptr<PublicKey>& pk, PRNGScheme prng_scheme) : sk_set_(false) {
    if (pk == nullptr) {
        throw std::invalid_argument("pk is nullptr");
    }
    std::vector<Byte> pk_bytes(pk->public_key_byte_count());
    pk->serialize_to_bytes(pk_bytes.data(), pk_bytes.size());
    pk_ = std::make_shared<PublicKey>(pk->key_length(), pk->use_djn());
    pk_->deserialize_from_bytes(pk_bytes.data(), pk_bytes.size());
#ifdef SOLO_USE_IPCL
    (void)prng_scheme;
#else
    r_bit_count_ = pk->use_djn() ? pk->key_length() : (pk->key_length() >> 1);
    PRNGFactory prng_factory = PRNGFactory(prng_scheme);
    prng_ = prng_factory.create();
#endif
}

Encryptor::Encryptor(const std::shared_ptr<PublicKey>& pk, const std::shared_ptr<SecretKey>& sk, PRNGScheme prng_scheme)
        : sk_set_(true) {
    if (pk == nullptr) {
        throw std::invalid_argument("pk is nullptr");
    }
    if (sk == nullptr) {
        throw std::invalid_argument("sk is nullptr");
    }
    std::vector<Byte> pk_bytes(pk->public_key_byte_count());
    pk->serialize_to_bytes(pk_bytes.data(), pk_bytes.size());
    pk_ = std::make_shared<PublicKey>(pk->key_length(), pk->use_djn());
    pk_->deserialize_from_bytes(pk_bytes.data(), pk_bytes.size());
#ifdef SOLO_USE_IPCL
    (void)prng_scheme;
#else
    r_bit_count_ = pk->use_djn() ? pk->key_length() : (pk->key_length() >> 1);
    PRNGFactory prng_factory = PRNGFactory(prng_scheme);
    prng_ = prng_factory.create();
#endif
    std::vector<Byte> sk_bytes(sk->secret_key_byte_count());
    sk->serialize_to_bytes(sk_bytes.data(), sk_bytes.size());
    sk_ = std::make_shared<SecretKey>(sk->key_length());
    sk_->deserialize_from_bytes(sk_bytes.data(), sk_bytes.size());
}

void Encryptor::encrypt(const Plaintext& in, Ciphertext& out) noexcept {
#ifdef SOLO_USE_IPCL
    ipcl::setHybridMode(ipcl::HybridMode::IPP);
    ipcl::PlainText pt(in);
    out = Ciphertext(pk_->pk()->encrypt(pt, true));
    ipcl::setHybridOff();
#else
    mpz_class r = 0;
    if (pk_->use_djn()) {
        r = utils::get_random_mpz(r_bit_count_, prng_);
        if (sk_set_) {
            sk_->powm_crt(pk_->hs(), r, r);
        } else {
            mpz_powm(r.get_mpz_t(), pk_->hs().get_mpz_t(), r.get_mpz_t(), pk_->n_square().get_mpz_t());
        }
    } else {
        do {
            r = utils::get_random_mpz(r_bit_count_, prng_);
        } while (r == 0 || r > pk_->n());
        if (sk_set_) {
            sk_->powm_crt(r, pk_->n(), r);
        } else {
            mpz_powm(r.get_mpz_t(), r.get_mpz_t(), pk_->n().get_mpz_t(), pk_->n_square().get_mpz_t());
        }
    }
    mpz_class bn_out = (1 + mpz_class(in) * pk_->n()) * r % pk_->n_square();
    out = Ciphertext(bn_out);
#endif
}

void Encryptor::encrypt_many(
        const std::vector<Plaintext>& in, std::vector<Ciphertext>& out, std::size_t num_threads) noexcept {
#ifdef SOLO_USE_IPCL
    ipcl::setHybridMode(ipcl::HybridMode::IPP);
    std::vector<BigNumber> bn_v(in.size());
    std::transform(
            in.begin(), in.end(), bn_v.begin(), [](const Plaintext& pt_i) { return BigNumber(ipcl::PlainText(pt_i)); });
    ipcl::PlainText pt(bn_v);
    bn_v.clear();
    std::vector<BigNumber> bn_ct = pk_->pk()->encrypt(pt, true).getTexts();
    out.resize(in.size());
    std::transform(bn_ct.begin(), bn_ct.end(), out.begin(),
            [this](const BigNumber& bn_i) { return Ciphertext(*(pk_->pk()), bn_i); });
    ipcl::setHybridOff();
    (void)num_threads;
#else
    out.resize(in.size());
    std::vector<mpz_class> r(in.size(), 0);
    for (std::size_t i = 0; i < r.size(); ++i) {
        if (pk_->use_djn()) {
            r[i] = utils::get_random_mpz(r_bit_count_, prng_);
        } else {
            do {
                r[i] = utils::get_random_mpz(r_bit_count_, prng_);
            } while (r[i] == 0 || r[i] > pk_->n());
        }
    }
#pragma omp parallel for num_threads(num_threads)
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (pk_->use_djn()) {
            if (sk_set_) {
                sk_->powm_crt(pk_->hs(), r[i], r[i]);
            } else {
                mpz_powm(r[i].get_mpz_t(), pk_->hs().get_mpz_t(), r[i].get_mpz_t(), pk_->n_square().get_mpz_t());
            }
        } else {
            if (sk_set_) {
                sk_->powm_crt(r[i], pk_->n(), r[i]);
            } else {
                mpz_powm(r[i].get_mpz_t(), r[i].get_mpz_t(), pk_->n().get_mpz_t(), pk_->n_square().get_mpz_t());
            }
        }
        mpz_class bn_out = (1 + mpz_class(in[i]) * pk_->n()) * r[i] % pk_->n_square();
        out[i] = Ciphertext(bn_out);
    }
#endif
}

Decryptor::Decryptor(const std::shared_ptr<SecretKey>& sk) {
    if (sk == nullptr) {
        throw std::invalid_argument("sk is nullptr");
    }

    std::vector<Byte> sk_bytes(sk->secret_key_byte_count());
    sk->serialize_to_bytes(sk_bytes.data(), sk_bytes.size());
    sk_ = std::make_shared<SecretKey>(sk->key_length());
    sk_->deserialize_from_bytes(sk_bytes.data(), sk_bytes.size());
}

void Decryptor::decrypt(const Ciphertext& in, Plaintext& out) const noexcept {
#ifdef SOLO_USE_IPCL
    ipcl::setHybridMode(ipcl::HybridMode::IPP);
    ipcl::CipherText ct(in);
    out = Plaintext(sk_->sk()->decrypt(ct));
    ipcl::setHybridOff();
#else
    mpz_class plain;
    sk_->decrypt(mpz_class(in), plain);
    out = Plaintext(plain);
#endif
}

void Decryptor::decrypt_many(
        const std::vector<Ciphertext>& in, std::vector<Plaintext>& out, std::size_t num_threads) const noexcept {
#ifdef SOLO_USE_IPCL
    ipcl::setHybridMode(ipcl::HybridMode::IPP);
    std::vector<BigNumber> bn_v(in.size());
    std::transform(
            in.begin(), in.end(), bn_v.begin(), [](const Ciphertext& pt_i) { return ipcl::CipherText(pt_i)[0]; });
    ipcl::CipherText ct_0(in[0]);
    ipcl::CipherText ct(*(ct_0.getPubKey()), bn_v);
    bn_v.clear();
    std::vector<BigNumber> bn_pt = sk_->sk()->decrypt(ct).getTexts();
    out.resize(in.size());
    std::transform(bn_pt.begin(), bn_pt.end(), out.begin(), [](const BigNumber& bn_i) { return Plaintext(bn_i); });
    ipcl::setHybridOff();
    (void)num_threads;
#else
    out.resize(in.size());
#pragma omp parallel for num_threads(num_threads)
    for (std::size_t i = 0; i < in.size(); ++i) {
        mpz_class plain;
        sk_->decrypt(mpz_class(in[i]), plain);
        out[i] = Plaintext(plain);
    }
#endif
}

Evaluator::Evaluator(const std::shared_ptr<PublicKey>& pk) : sk_set_(false) {
    if (pk == nullptr) {
        throw std::invalid_argument("pk is nullptr");
    }
    std::vector<Byte> pk_bytes(pk->public_key_byte_count());
    pk->serialize_to_bytes(pk_bytes.data(), pk_bytes.size());
    pk_ = std::make_shared<PublicKey>(pk->key_length(), pk->use_djn());
    pk_->deserialize_from_bytes(pk_bytes.data(), pk_bytes.size());
    encryptor_ = std::make_shared<Encryptor>(pk_);
}

Evaluator::Evaluator(const std::shared_ptr<PublicKey>& pk, const std::shared_ptr<SecretKey>& sk) : sk_set_(true) {
    if (pk == nullptr) {
        throw std::invalid_argument("pk is nullptr");
    }
    if (sk == nullptr) {
        throw std::invalid_argument("sk is nullptr");
    }
    std::vector<Byte> pk_bytes(pk->public_key_byte_count());
    pk->serialize_to_bytes(pk_bytes.data(), pk_bytes.size());
    pk_ = std::make_shared<PublicKey>(pk->key_length(), pk->use_djn());
    pk_->deserialize_from_bytes(pk_bytes.data(), pk_bytes.size());

    std::vector<Byte> sk_bytes(sk->secret_key_byte_count());
    sk->serialize_to_bytes(sk_bytes.data(), sk_bytes.size());
    sk_ = std::make_shared<SecretKey>(sk->key_length());
    sk_->deserialize_from_bytes(sk_bytes.data(), sk_bytes.size());
    encryptor_ = std::make_shared<Encryptor>(pk_);
}

void Evaluator::add(const Ciphertext& in_0, const Ciphertext& in_1, Ciphertext& out) const noexcept {
#ifdef SOLO_USE_IPCL
    out = Ciphertext(ipcl::CipherText(in_0) + ipcl::CipherText(in_1));
#else
    mpz_class bn_out = mpz_class(in_0) * mpz_class(in_1) % pk_->n_square();
    out = Ciphertext(bn_out);
#endif
}

void Evaluator::add_many(const std::vector<Ciphertext>& in_0, const std::vector<Ciphertext>& in_1,
        std::vector<Ciphertext>& out, std::size_t num_threads) const {
    if (in_0.size() != in_1.size()) {
        throw std::invalid_argument("Input size of two vector is not equal.");
    }
#ifdef SOLO_USE_IPCL
    std::vector<BigNumber> bn_v0(in_0.size());
    std::vector<BigNumber> bn_v1(in_1.size());
    std::transform(
            in_0.begin(), in_0.end(), bn_v0.begin(), [](const Ciphertext& pt_i) { return ipcl::CipherText(pt_i)[0]; });
    std::transform(
            in_1.begin(), in_1.end(), bn_v1.begin(), [](const Ciphertext& pt_i) { return ipcl::CipherText(pt_i)[0]; });
    auto ct = ipcl::CipherText(*(ipcl::CipherText(in_0[0]).getPubKey()), bn_v0) +
              ipcl::CipherText(*(ipcl::CipherText(in_1[0]).getPubKey()), bn_v1);
    std::vector<BigNumber> bn_ct = ct.getTexts();
    out.resize(in_0.size());
    std::transform(bn_ct.begin(), bn_ct.end(), out.begin(),
            [&ct](const BigNumber& bn_i) { return Ciphertext(*(ct.getPubKey()), bn_i); });
    (void)num_threads;
#else
    out.resize(in_0.size());
#pragma omp parallel for num_threads(num_threads)
    for (std::size_t i = 0; i < in_0.size(); ++i) {
        add(in_0[i], in_1[i], out[i]);
    }
#endif
}

void Evaluator::add(const Ciphertext& in_0, const Plaintext& in_1, Ciphertext& out) noexcept {
    Ciphertext ct_1;
    encryptor_->encrypt(in_1, ct_1);
    add(in_0, ct_1, out);
}

void Evaluator::add_many(const std::vector<Ciphertext>& in_0, const std::vector<Plaintext>& in_1,
        std::vector<Ciphertext>& out, std::size_t num_threads) {
    if (in_0.size() != in_1.size()) {
        throw std::invalid_argument("Input size of two vector is not equal.");
    }
    std::vector<Ciphertext> ct_1;
    encryptor_->encrypt_many(in_1, ct_1, num_threads);
    out.resize(in_0.size());
    add_many(in_0, ct_1, out, num_threads);
}

void Evaluator::mul(const Ciphertext& in_0, const Plaintext& in_1, Ciphertext& out) const noexcept {
#ifdef SOLO_USE_IPCL
    out = Ciphertext(ipcl::CipherText(in_0) * ipcl::PlainText(in_1));
#else
    mpz_class bn_out;
    if (sk_set_) {
        sk_->powm_crt(mpz_class(in_0), mpz_class(in_1), bn_out);
    } else {
        mpz_powm(bn_out.get_mpz_t(), mpz_class(in_0).get_mpz_t(), mpz_class(in_1).get_mpz_t(),
                pk_->n_square().get_mpz_t());
    }
    out = Ciphertext(bn_out);
#endif
}

void Evaluator::mul_many(const std::vector<Ciphertext>& in_0, const std::vector<Plaintext>& in_1,
        std::vector<Ciphertext>& out, std::size_t num_threads) const {
    if (in_0.size() != in_1.size()) {
        throw std::invalid_argument("Input vector sizes are not equal.");
    }
#ifdef SOLO_USE_IPCL
    std::vector<BigNumber> bn_v0(in_0.size());
    std::vector<BigNumber> bn_v1(in_1.size());
    std::transform(
            in_0.begin(), in_0.end(), bn_v0.begin(), [](const Ciphertext& pt_i) { return ipcl::CipherText(pt_i)[0]; });
    std::transform(in_1.begin(), in_1.end(), bn_v1.begin(),
            [](const Plaintext& pt_i) { return BigNumber(ipcl::PlainText(pt_i)); });
    auto ct = ipcl::CipherText(*(ipcl::CipherText(in_0[0]).getPubKey()), bn_v0) * ipcl::PlainText(bn_v1);
    std::vector<BigNumber> bn_ct = ct.getTexts();
    out.resize(in_0.size());
    std::transform(bn_ct.begin(), bn_ct.end(), out.begin(),
            [&ct](const BigNumber& bn_i) { return Ciphertext(*(ct.getPubKey()), bn_i); });
    (void)num_threads;
#else
    out.resize(in_0.size());
#pragma omp parallel for num_threads(num_threads)
    for (std::size_t i = 0; i < in_0.size(); ++i) {
        mul(in_0[i], in_1[i], out[i]);
    }
#endif
}

namespace utils {
#ifdef SOLO_USE_IPCL
void bn_lshift(BigNumber& in, const std::size_t bits) {
    if (bits > kAHEMaxRandomBits) {
        throw std::invalid_argument("Shift bits is too large.");
    }
    std::size_t length = bits / 32 + 1;
    std::size_t remainder = bits % 32;
    std::vector<std::uint32_t> temp(length, 0);
    temp[length - 1] = 1 << remainder;
    BigNumber shift_bn(temp.data(), static_cast<int>(length));
    in *= shift_bn;
}

BigNumber get_random_bn(std::size_t bits) {
    if (bits > kAHEMaxRandomBits) {
        throw std::invalid_argument("random bits is too large.");
    }
    return ipcl::getRandomBN(static_cast<int>(bits));
}
#else
mpz_class get_random_mpz(std::size_t bits, std::shared_ptr<PRNG>& prng) {
    if (bits > kAHEMaxRandomBits) {
        throw std::invalid_argument("random bits is too large.");
    }
    mpz_class out = 0;
    std::size_t byte_count = (bits + 7) / 8;
    std::vector<Byte> in(byte_count);
    do {
        prng->generate(byte_count, in.data());
        mpz_import(out.get_mpz_t(), in.size(), 1, 1, 0, 0, in.data());
        out >>= byte_count * 8 - bits;
    } while (out == 0 || mpz_sizeinbase(out.get_mpz_t(), 2) != bits);
    return out;
}
#endif
}  // namespace utils

}  // namespace ahepaillier
}  // namespace solo
}  // namespace petace
