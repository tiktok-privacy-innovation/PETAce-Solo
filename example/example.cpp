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

#include <iomanip>
#include <iostream>
#include <sstream>

#include "solo/solo.h"

static void print_header(std::string name) {
    if (!name.empty()) {
        std::size_t name_length = name.length();
        std::size_t header_length = name_length + 2 * 10;
        std::string header_top = "+" + std::string(header_length - 2, '-') + "+";
        std::string header_middle = "|" + std::string(9, ' ') + name + std::string(9, ' ') + "|";
        std::cout << std::endl << header_top << std::endl << header_middle << std::endl << header_top << std::endl;
    }
}

static std::string byte_array_to_hex_string(const petace::solo::Byte* input, std::size_t input_byte_count) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < input_byte_count; i++) {
        ss << std::hex << std::setw(2) << static_cast<int>(input[i]);
    }
    return ss.str();
}

void example_hash() {
    print_header("Example: Hash");

    std::cout << "Use SHA-256 as our hash function" << std::endl;
    auto hash = petace::solo::Hash::create(petace::solo::HashScheme::SHA_256);

    std::string input_text = "Use SHA-256 as our hash function";
    std::cout << "    Input text:    \"" << input_text << "\"" << std::endl;
    std::array<petace::solo::Byte, petace::solo::HashSHA_256::kHashByteCount> output_digest;
    hash->compute(reinterpret_cast<const petace::solo::Byte*>(input_text.c_str()), input_text.length(),
            output_digest.data(), output_digest.size());
    std::cout << "    Output digest: \"" << byte_array_to_hex_string(output_digest.data(), output_digest.size()) << "\""
              << std::endl;
}

void example_prng() {
    print_header("Example: PRNG");

    std::vector<petace::solo::Byte> seed(32);
    petace::solo::PRNG::get_random_byte_array(seed.size(), seed.data());
    std::cout << "Generate a random 256-bit seed: \"" << byte_array_to_hex_string(seed.data(), seed.size()) << "\""
              << std::endl;

    std::cout << std::endl;
    std::cout << "Use BLAKE2Xb to create our PRNG" << std::endl;
    petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::BLAKE2Xb, seed.size());
    auto prng = prng_factory.create(seed);

    petace::solo::Byte output[32];
    prng->generate(32, output);
    std::cout << "    Generate 32 random bytes: \"" << byte_array_to_hex_string(output, 32) << "\"" << std::endl;

    prng->generate(16, output);
    std::cout << "    Generate 16 random bytes: \"" << byte_array_to_hex_string(output, 16) << "\"" << std::endl;

    std::cout << std::endl;
    std::cout << "Re-create another PRNG from the same seed..." << std::endl;
    auto prng_other = prng_factory.create(seed);

    prng_other->generate(32, output);
    std::cout << "    Generate 32 random bytes: \"" << byte_array_to_hex_string(output, 32) << "\"" << std::endl;

    prng_other->generate(16, output);
    std::cout << "    Generate 16 random bytes: \"" << byte_array_to_hex_string(output, 16) << "\"" << std::endl;
}

void example_sampling() {
    print_header("Example: Sampling");

    std::vector<petace::solo::Byte> seed(16);
    petace::solo::PRNG::get_random_byte_array(seed.size(), seed.data());
    std::cout << "Generate a random 128-bit seed: \"" << byte_array_to_hex_string(seed.data(), seed.size()) << "\""
              << std::endl;

    std::cout << std::endl;
    std::cout << "Use AES_ECB_CTR to create our PRNG" << std::endl;
    petace::solo::PRNGFactory prng_factory(petace::solo::PRNGScheme::AES_ECB_CTR, seed.size());
    auto prng = prng_factory.create(seed);

    std::cout << "    Generate a random 32-bit unsigned integer: " << sample_uniform_uint32(*prng) << std::endl;
    std::cout << "    Generate a random 64-bit unsigned integer: " << sample_uniform_uint64(*prng) << std::endl;

    std::cout << std::endl;
    std::cout << "Re-create another PRNG from the same seed..." << std::endl;
    auto prng_other = prng_factory.create(seed);

    std::cout << "    Generate a random 32-bit unsigned integer: " << sample_uniform_uint32(*prng_other) << std::endl;
    std::cout << "    Generate a random 64-bit unsigned integer: " << sample_uniform_uint64(*prng_other) << std::endl;
}

void example_ec_openssl() {
    print_header("Example: EC OpenSSL");

    using EC = petace::solo::ECOpenSSL;
    int curve_id = NID_X9_62_prime256v1;
    std::cout << "Use curve NID_X9_62_prime256v1 and BLAKE2b" << std::endl;
    EC ec(curve_id, petace::solo::HashScheme::BLAKE2b);

    std::string input_text = "Use curve NID_X9_62_prime256v1 and BLAKE2b";
    std::cout << "    Input text:    \"" << input_text << "\"" << std::endl;

    EC::Point output_point(ec);
    ec.hash_to_curve(
            reinterpret_cast<const petace::solo::Byte*>(input_text.c_str()), input_text.length(), output_point);
    std::size_t output_byte_count = ec.point_to_bytes(output_point, 0, nullptr);
    std::vector<petace::solo::Byte> output_bytes(output_byte_count);
    ec.point_to_bytes(output_point, output_byte_count, output_bytes.data());
    std::cout << "    Output point: \"" << byte_array_to_hex_string(output_bytes.data(), output_bytes.size()) << "\""
              << std::endl;
}

int main() {
    std::cout << "PETAce-Solo version: " << SOLO_VERSION << std::endl;

    example_hash();
    example_prng();
    example_sampling();
    example_ec_openssl();

    return 0;
}
