#include <algorithm>
#include <array>
#include <bitset>
#include <experimental/string_view>
#include <iostream>
#include <iterator>
#include <numeric>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>
// uncomment to disable assert()
// #define NDEBUG
#include <cassert>

using byte = uint8_t;

///////////////////////////////////////////////////////////////////////////////
// Character encoding
///////////////////////////////////////////////////////////////////////////////

constexpr bool is_upper(byte b) { return 'A' <= b && b <= 'Z'; }
constexpr bool is_lower(byte b) { return 'a' <= b && b <= 'z'; }
constexpr bool is_digit(byte b) { return '0' <= b && b <= '9'; }

namespace base64 {
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

  constexpr std::experimental::string_view alphabet(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64);

  return alphabet[i];
}
}

enum class Encoding { hex, ascii, base64 };

///////////////////////////////////////////////////////////////////////////////
// Byte vector functions
///////////////////////////////////////////////////////////////////////////////

std::vector<byte> string_to_byte_vector(const std::string &s,
                                        Encoding mode = Encoding::hex) {
  std::vector<byte> byte_vector;

  switch (mode) {
  case Encoding::hex: {
    assert(s.size() % 2 == 0); // 2 hex digits per 1 byte
    byte_vector.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
      byte_vector.push_back(stoi(s.substr(i, 2), nullptr, 16));
    }
    break;
  }
  case Encoding::ascii: {
    byte_vector.reserve(s.size());
    std::copy(s.begin(), s.end(), std::back_inserter(byte_vector));
    break;
  }
  case Encoding::base64: {
    assert(s.size() % 4 == 0); // 4 base64 char per 3 bytes
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

std::string byte_vector_to_string(std::vector<byte> byte_vector,
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

int main() {
  std::string ascii_s = "I'm killing your brain like a poisonous mushroom";
  std::string hex_s =
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706"
      "f69736f6e6f7573206d757368726f6f6d";
  std::string base64_s =
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  auto hex_v = string_to_byte_vector(hex_s);
  auto ascii_v = string_to_byte_vector(ascii_s, Encoding::ascii);
  auto base64_v = string_to_byte_vector(base64_s, Encoding::base64);

  assert(byte_vector_to_string(hex_v) == byte_vector_to_string(ascii_v) &&
         byte_vector_to_string(hex_v) == byte_vector_to_string(base64_v) &&
         byte_vector_to_string(hex_v, Encoding::ascii) == ascii_s &&
         byte_vector_to_string(hex_v, Encoding::base64) == base64_s);
}
