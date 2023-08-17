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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/err.h"

#include "solo/hash.h"
#include "solo/prng.h"
#include "solo/util/defines.h"

namespace petace {
namespace solo {

ECOpenSSL::UInt& ECOpenSSL::UInt::operator=(const UInt& copy) {
    if (BN_copy(data_, copy.data_) == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    return *this;
}

ECOpenSSL::Point& ECOpenSSL::Point::operator=(const Point& copy) {
    if (EC_POINT_copy(data_, copy.data_) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    return *this;
}

ECOpenSSL::ECOpenSSL(int curve_id, HashScheme hash_scheme)
        : group_(EC_GROUP_new_by_curve_name(curve_id)),
          p_(BN_new()),
          a_(BN_new()),
          b_(BN_new()),
          order_(BN_new()),
          p_minus_one_over_two_(BN_new()),
          three_(BN_new()),
          hash_factory_(HashFactory::create_factory(hash_scheme)) {
    if (group_ == nullptr || p_ == nullptr || a_ == nullptr || b_ == nullptr || order_ == nullptr ||
            p_minus_one_over_two_ == nullptr || three_ == nullptr || hash_factory_ == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (EC_GROUP_get_curve(group_, p_, a_, b_, NULL) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (EC_GROUP_get_order(group_, order_, NULL) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }

    if (BN_copy(p_minus_one_over_two_, p_) == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (BN_sub_word(p_minus_one_over_two_, 1) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (BN_rshift1(p_minus_one_over_two_, p_minus_one_over_two_) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }

    if (BN_set_word(three_, 3) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
}

ECOpenSSL::~ECOpenSSL() {
    EC_GROUP_free(group_);
    BN_clear_free(p_);
    BN_clear_free(a_);
    BN_clear_free(b_);
    BN_clear_free(order_);
    BN_clear_free(p_minus_one_over_two_);
    BN_clear_free(three_);
}

void ECOpenSSL::add(const Point& in_0, const Point& in_1, Point& out) const {
    if (EC_POINT_add(group_, out.data(), in_0.data(), in_1.data(), NULL) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
}

void ECOpenSSL::invert(const Point& in, Point& out) const {
    out = in;
    if (EC_POINT_invert(group_, out.data(), NULL) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
}

void ECOpenSSL::mul(const Point& point, const UInt& scalar, Point& out) const {
    if (EC_POINT_mul(group_, out.data(), NULL, point.data(), scalar.data(), NULL) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
}

void ECOpenSSL::mul_generator(const UInt& scalar, Point& out) const {
    if (EC_POINT_mul(group_, out.data(), scalar.data(), NULL, NULL, NULL) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
}

void ECOpenSSL::create_secret_key(std::shared_ptr<PRNG> prng, SecretKey& out) const {
    if (prng == nullptr) {
        throw std::invalid_argument("prng is nullptr");
    }
    if (out.data() == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }

    std::size_t byte_count = static_cast<size_t>(BN_num_bytes(order_));
    BIGNUM* cap(BN_new());
    if (cap == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    BN_CTX* ctx(BN_CTX_new());
    if (ctx == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    std::vector<Byte> buffer(byte_count, Byte(0xFF));
    BN_bin2bn(reinterpret_cast<const unsigned char*>(buffer.data()), static_cast<int>(byte_count), cap);
    if (BN_nnmod(out.data(), cap, order_, ctx) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    BN_sub(cap, cap, out.data());
    do {
        do {
            prng->generate(byte_count, buffer.data());
            BN_bin2bn(reinterpret_cast<const unsigned char*>(buffer.data()), static_cast<int>(byte_count), out.data());
        } while (BN_cmp(out.data(), cap) != -1);
        if (BN_nnmod(out.data(), out.data(), order_, ctx) == 0) {
            throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
        }
    } while (BN_num_bits(out.data()) != BN_num_bits(order_));

    BN_clear_free(cap);
    BN_CTX_free(ctx);
}

void ECOpenSSL::create_public_key(const SecretKey& key, Point& out) const {
    if (key.data() == nullptr) {
        throw std::invalid_argument("key is nullptr");
    }
    if (out.data() == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    if (EC_POINT_mul(group_, out.data(), key.data(), NULL, NULL, NULL) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
}

void ECOpenSSL::encrypt(const Point& in, const SecretKey& key, Point& out) const {
    if (in.data() == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    if (key.data() == nullptr) {
        throw std::invalid_argument("key is nullptr");
    }
    if (out.data() == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }

    BN_CTX* ctx(BN_CTX_secure_new());
    if (ctx == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (EC_POINT_mul(group_, out.data(), NULL, in.data(), key.data(), ctx) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    BN_CTX_free(ctx);
}

void ECOpenSSL::decrypt(const Point& in, const SecretKey& key, Point& out) const {
    if (in.data() == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    if (key.data() == nullptr) {
        throw std::invalid_argument("key is nullptr");
    }
    if (out.data() == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }

    BN_CTX* ctx(BN_CTX_secure_new());
    if (ctx == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    BIGNUM* factor(BN_secure_new());
    if (factor == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (BN_mod_inverse(factor, key.data(), order_, ctx) == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (EC_POINT_mul(group_, out.data(), NULL, in.data(), factor, ctx) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    BN_clear_free(factor);
    BN_CTX_free(ctx);
}

void ECOpenSSL::switch_key(const Point& in, const SecretKey& key_old, const SecretKey& key_new, Point& out) const {
    if (in.data() == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    if (key_old.data() == nullptr) {
        throw std::invalid_argument("key_old is nullptr");
    }
    if (key_new.data() == nullptr) {
        throw std::invalid_argument("key_new is nullptr");
    }
    if (out.data() == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }

    BN_CTX* ctx(BN_CTX_secure_new());
    if (ctx == nullptr) {
        throw std::runtime_error("openssl error: BN_CTX_secure_new " + std::to_string(ERR_get_error()));
    }
    BIGNUM* factor(BN_secure_new());
    if (factor == nullptr) {
        throw std::runtime_error("openssl error: BN_secure_new " + std::to_string(ERR_get_error()));
    }
    if (BN_mod_inverse(factor, key_old.data(), order_, ctx) == nullptr) {
        throw std::runtime_error("openssl error: BN_mod_inverse " + std::to_string(ERR_get_error()));
    }
    if (BN_mod_mul(factor, factor, key_new.data(), order_, ctx) == 0) {
        throw std::runtime_error("openssl error: BN_mod_mul " + std::to_string(ERR_get_error()));
    }
    if (EC_POINT_mul(group_, out.data(), NULL, in.data(), factor, ctx) == 0) {
        throw std::runtime_error("openssl error: EC_POINT_mul " + std::to_string(ERR_get_error()));
    }
    BN_clear_free(factor);
    BN_CTX_free(ctx);
}

void ECOpenSSL::hash_to_field(
        std::shared_ptr<Hash> hash, const Byte* in, std::size_t in_byte_count, BIGNUM* out, BN_CTX* ctx) const {
    if (in == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    if (out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    if (ctx == nullptr) {
        throw std::invalid_argument("ctx is nullptr");
    }

    std::size_t hash_byte_count = hash->hash_byte_count();
    std::size_t num_iter = (static_cast<size_t>(BN_num_bytes(p_)) + hash_byte_count - 1) / hash_byte_count + 1;
    std::size_t out_byte_count = hash_byte_count * num_iter;
    if (num_iter > 255) {
        throw std::invalid_argument("in_byte_count is too large");
    }

    std::vector<Byte> in_buf(in_byte_count + 1);
    std::copy_n(in, in_byte_count, in_buf.data() + 1);
    std::vector<Byte> out_buf(out_byte_count);

    for (std::size_t i = 1; i <= num_iter; i++) {
        in_buf[0] = static_cast<Byte>(i);
        hash->compute(in_buf.data(), in_buf.size(), out_buf.data() + hash_byte_count * (i - 1), hash_byte_count);
    }
    if (BN_bin2bn(reinterpret_cast<const unsigned char*>(out_buf.data()), static_cast<int>(out_byte_count), out) ==
            nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (BN_nnmod(out, out, p_, ctx) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
}

void ECOpenSSL::hash_to_curve(const Byte* in, std::size_t in_byte_count, Point& out) const {
    if (in == nullptr) {
        throw std::invalid_argument("in is nullptr");
    }
    if (out.data() == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }

    BN_CTX* ctx(BN_CTX_new());
    if (ctx == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    BIGNUM* elt(BN_new());
    if (elt == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    BIGNUM* y_square(BN_new());
    if (y_square == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    BIGNUM* tmp(BN_new());
    if (tmp == nullptr) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    auto hash = hash_factory_->create();
    std::vector<Byte> in_buf(in_byte_count);
    std::copy_n(in, in_byte_count, in_buf.data());

    bool repeat = true;

    do {
        hash_to_field(hash, in_buf.data(), in_buf.size(), elt, ctx);
        compute_y_square(elt, y_square, ctx);
        if (BN_mod_exp(tmp, y_square, p_minus_one_over_two_, p_, ctx) == 0) {
            throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
        }
        if (BN_is_one(tmp)) {
            if (BN_mod_sqrt(tmp, y_square, p_, ctx) == nullptr) {
                throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
            }
            if (BN_is_bit_set(tmp, 0)) {
                if (BN_sub(tmp, p_, tmp) == 0) {
                    throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
                }
            }
            if (EC_POINT_set_affine_coordinates(group_, out.data(), elt, tmp, ctx) == 0) {
                throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
            }
            switch (EC_POINT_is_on_curve(group_, out.data(), ctx)) {
                case -1:
                    throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
                case 0:
                    break;
                case 1:
                    if (EC_POINT_is_at_infinity(group_, out.data()) == 0) {
                        repeat = false;
                    }
                    break;
            }
        }
        in_buf.resize(static_cast<size_t>(BN_num_bytes(elt)));
        BN_bn2bin(elt, reinterpret_cast<unsigned char*>(in_buf.data()));
    } while (repeat);

    BN_clear_free(elt);
    BN_clear_free(y_square);
    BN_clear_free(tmp);
    BN_CTX_free(ctx);
}

void ECOpenSSL::compute_y_square(const BIGNUM* x, BIGNUM* y_square, BN_CTX* ctx) const {
    if (x == nullptr) {
        throw std::invalid_argument("x is nullptr");
    }
    if (y_square == nullptr) {
        throw std::invalid_argument("y_square is nullptr");
    }
    if (ctx == nullptr) {
        throw std::invalid_argument("ctx is nullptr");
    }

    if (BN_mod_sqr(y_square, x, p_, ctx) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (BN_mod_add(y_square, y_square, a_, p_, ctx) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (BN_mod_mul(y_square, y_square, x, p_, ctx) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    if (BN_mod_add(y_square, y_square, b_, p_, ctx) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
}

bool ECOpenSSL::are_equal(const Point& in_0, const Point& in_1) const {
    switch (EC_POINT_cmp(group_, in_0.data(), in_1.data(), NULL)) {
        case 0:
            return true;
        case 1:
            return false;
        case -1:
            throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
            break;
        default:
            throw std::runtime_error("bad return from EC_POINT_cmp");
    }
    return false;
}

size_t ECOpenSSL::point_to_bytes(const Point& point, std::size_t out_byte_count, Byte* out) const {
    if (point.data() == nullptr) {
        throw std::invalid_argument("point is nullptr");
    }
    if (out == nullptr) {
        return EC_POINT_point2oct(group_, point.data(), POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    }
    std::size_t res = EC_POINT_point2oct(group_, point.data(), POINT_CONVERSION_COMPRESSED,
            reinterpret_cast<unsigned char*>(out), out_byte_count, NULL);
    if (res == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
    return res;
}

void ECOpenSSL::point_from_bytes(const Byte* in, std::size_t in_byte_count, Point& out) const {
    if (in_byte_count == 0) {
        throw std::invalid_argument("in_byte_count is zero");
    }
    if (in == nullptr && in_byte_count != 0) {
        throw std::invalid_argument("in is nullptr");
    }
    if (out.data() == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    if (EC_POINT_oct2point(group_, out.data(), reinterpret_cast<const unsigned char*>(in), in_byte_count, NULL) == 0) {
        throw std::runtime_error("openssl error: " + std::to_string(ERR_get_error()));
    }
}

}  // namespace solo
}  // namespace petace
