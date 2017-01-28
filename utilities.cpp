#include <algorithm>
#include <array>
#include <bitset>
#include <climits>
#include <experimental/string_view>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>
// uncomment to disable assert()
// #define NDEBUG
#include <cassert>

using byte = uint8_t;
static_assert(sizeof(byte) == 1);
static_assert(CHAR_BIT == 8);

///////////////////////////////////////////////////////////////////////////////
// Character encoding
///////////////////////////////////////////////////////////////////////////////

constexpr bool is_upper(byte b) { return 'A' <= b && b <= 'Z'; }
constexpr bool is_lower(byte b) { return 'a' <= b && b <= 'z'; }
constexpr bool is_digit(byte b) { return '0' <= b && b <= '9'; }

namespace base64 {
static constexpr std::experimental::string_view base64_alphabet(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64);

constexpr bool is_valid_base64_char(char c) {
  return is_upper(c) || is_lower(c) || is_digit(c) || c == '+' || c == '/';
}

constexpr unsigned int base64_to_int(char c) {
  assert(is_valid_base64_char(c));

  constexpr auto pos_A = 0;
  constexpr auto pos_a = 26;
  constexpr auto pos_0 = 26 + 26;

  if (is_upper(c)) {
    return pos_A + (c - 'A');
  } else if (is_lower(c)) {
    return pos_a + (c - 'a');
  } else if (is_digit(c)) {
    return pos_0 + (c - '0');
  } else if (c == '+') {
    return 62;
  } else {
    return 63;
  }
}

constexpr char int_to_base64(unsigned int i) {
  assert(0 <= i && i < 64);

  return base64_alphabet[i];
}
}

enum class Encoding { hex, ascii, base64 };

///////////////////////////////////////////////////////////////////////////////
// Byte vector functions
///////////////////////////////////////////////////////////////////////////////

std::vector<byte> string_to_bytes(std::experimental::string_view s,
                                  Encoding mode = Encoding::hex) {
  std::vector<byte> byte_vector;

  switch (mode) {
  case Encoding::hex: {
    assert(s.size() % 2 == 0); // 2 hex digits per 1 byte
    byte_vector.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
      byte_vector.push_back(stoi(std::string(s.substr(i, 2)), nullptr, 16));
    }
    break;
  }
  case Encoding::ascii: {
    byte_vector.reserve(s.size());
    std::copy(s.begin(), s.end(), std::back_inserter(byte_vector));
    break;
  }
  case Encoding::base64: {
    assert(s.size() % 4 == 0); // 4 base64 chars per 3 bytes
    byte_vector.reserve((s.size() / 4) * 3);

    for (auto str_it = s.begin(); str_it != s.end(); str_it += 4) {
      std::array<std::string, 4> binary_array;
      std::transform(str_it, str_it + 4, binary_array.begin(), [](char c) {
        return std::bitset<6>(base64::base64_to_int(c)).to_string();
      });

      std::string binary_string;
      binary_string.reserve(24); // 4 base64 chars, each one 6 bits
      binary_string = std::accumulate(begin(binary_array), end(binary_array),
                                      binary_string);

      for (size_t i = 0; i < binary_string.size(); i += 8) {
        byte_vector.push_back(stoi(binary_string.substr(i, 8), nullptr, 2));
      }
    }

    break;
  }
  }

  return byte_vector;
}

std::string bytes_to_string(std::vector<byte> byte_vector,
                            Encoding mode = Encoding::hex) {
  std::string s;

  switch (mode) {
  case Encoding::hex: {
    std::stringstream ss;
    ss << std::hex;
    for_each(byte_vector.begin(), byte_vector.end(),
             [&ss](byte b) { ss << static_cast<short int>(b); });
    s = ss.str();
    break;
  }
  case Encoding::ascii: {
    s.reserve(byte_vector.size());
    std::copy(byte_vector.begin(), byte_vector.end(), std::back_inserter(s));
    break;
  }
  case Encoding::base64: {
    assert(byte_vector.size() % 3 == 0); // 3 bytes per 4 base64 chars
    s.reserve((byte_vector.size() / 3) * 4);

    for (auto it = byte_vector.begin(); it != byte_vector.end(); it += 3) {
      std::array<std::string, 3> binary_array;
      std::transform(it, it + 3, binary_array.begin(),
                     [](byte b) { return std::bitset<8>(b).to_string(); });

      std::string binary_string;
      binary_string.reserve(24); // 3 bytes, each one 8 bits
      binary_string = std::accumulate(begin(binary_array), end(binary_array),
                                      binary_string);

      for (size_t i = 0; i < binary_string.size(); i += 6) {
        s.push_back(base64::int_to_base64(
            stoi(binary_string.substr(i, 6), nullptr, 2)));
      }
    }
    break;
  }
  }

  return s;
}

///////////////////////////////////////////////////////////////////////////////
// Xor functions
///////////////////////////////////////////////////////////////////////////////

std::vector<byte> fixed_xor(const std::vector<byte> &lhs,
                            const std::vector<byte> &rhs) {
  assert(lhs.size() == rhs.size());

  std::vector<byte> result;
  result.reserve(lhs.size());
  std::transform(lhs.begin(), lhs.end(), rhs.begin(),
                 std::back_inserter(result), std::bit_xor<byte>());
  return result;
}

std::vector<byte> single_byte_xor(const std::vector<byte> &lhs, byte rhs) {

  std::vector<byte> result;
  result.reserve(lhs.size());
  std::transform(lhs.begin(), lhs.end(), std::back_inserter(result),
                 [rhs](byte b) { return b ^ rhs; });
  return result;
}

///////////////////////////////////////////////////////////////////////////////
// Decrypting xor ciphers
///////////////////////////////////////////////////////////////////////////////

struct LetterCount {
  std::array<unsigned int, 26> counts;
  unsigned int num_letters;
};

LetterCount count_letters(const std::vector<byte> &byte_vector) {
  LetterCount letter_count = {}; // default value initilization

  for (auto b : byte_vector) {
    if (is_lower(b)) {
      letter_count.counts[b - 'a'] += 1;
      letter_count.num_letters++;
    } else if (is_upper(b)) {
      letter_count.counts[b - 'A'] += 1;
      letter_count.num_letters++;
    }
  }

  return letter_count;
}

double chi_squared_statistic(const std::vector<byte> &byte_vector) {
  auto letter_count = count_letters(byte_vector);

  static constexpr std::array<double, 26> expected_frequencies{
      {0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
       0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
       0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
       0.00978, 0.02360, 0.00150, 0.01974, 0.00074}}; // wikipedia

  double chi_statistic = 0.0;
  for (auto i = 0; i < 26; i++) {
    auto o_i = letter_count.counts[i]; // observations
    auto e_i = letter_count.num_letters *
               expected_frequencies[i]; // expected absolute frequency
    chi_statistic += ((o_i - e_i) * (o_i - e_i)) / e_i;
  }

  return chi_statistic;
}

struct SingleByteXorDecryption {
  std::vector<byte> plaintext;
  byte key;
};

SingleByteXorDecryption
decrypt_single_byte_xor(const std::vector<byte> &ciphertext) {
  byte best_key = 0;
  auto best_plaintext = single_byte_xor(ciphertext, best_key);
  auto best_chi_statistic = chi_squared_statistic(best_plaintext);

  for (auto i = 1; i < 256; i++) { // 1 byte represent 256 values
    byte new_key = i;
    auto new_plaintext = single_byte_xor(ciphertext, new_key);
    auto new_chi_statistic = chi_squared_statistic(new_plaintext);

    if (new_chi_statistic < best_chi_statistic) {
      best_key = new_key;
      best_plaintext = new_plaintext;
      best_chi_statistic = new_chi_statistic;
    }
  }

  return {best_plaintext, byte(best_key)};
}
