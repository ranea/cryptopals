#include <algorithm>
#include <array>
#include <bitset>
#include <climits>
#include <experimental/string_view>
#include <fstream>
#include <iostream>
#include <limits>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>
// uncomment to disable assert()
// #define NDEBUG
#include "evp-encrypt.cxx"
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
constexpr bool is_printable(byte b) {
  return (' ' <= b && b <= '~') || b == '\n';
}

template <class Container> bool is_container_printable(const Container &c) {
  return std::find_if_not(std::begin(c), std::end(c), is_printable) ==
         std::end(c);
}

namespace base64 {
static constexpr std::experimental::string_view base64_alphabet(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64);

constexpr bool is_valid_base64_char(char c) {
  return is_upper(c) || is_lower(c) || is_digit(c) || c == '+' || c == '/' ||
         c == '=';
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
  } else if (c == '/') {
    return 63;
  } else { // ==
    return 0;
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

std::string bytes_to_string(const std::vector<byte> &byte_vector,
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

    if (s.back() == 'A') { // padding whp
      s.back() = '=';
    }

    break;
  }
  }

  return s;
}

std::ostream &operator<<(std::ostream &stream,
                         const std::vector<byte> &byte_vector) {
  stream << bytes_to_string(byte_vector, Encoding::ascii);
  return stream;
}

std::vector<byte> file_to_bytes(std::experimental::string_view filename,
                                Encoding mode = Encoding::hex) {
  std::string filetext;
  std::ifstream infile(filename.data());
  std::copy_if(std::istreambuf_iterator<char>{infile},
               std::istreambuf_iterator<char>{}, std::back_inserter(filetext),
               [](auto c) { return c != '\n'; });

  return string_to_bytes(filetext, mode);
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

std::vector<byte> repeating_key_xor(const std::vector<byte> &lhs,
                                    const std::vector<byte> &rhs) {
  assert(lhs.size() >= rhs.size());

  std::vector<byte> result = lhs;

  auto rhs_it = rhs.begin();
  for (auto &b : result) {
    b ^= *rhs_it;
    rhs_it = (rhs_it == rhs.end() - 1) ? rhs.begin() : rhs_it + 1;
  }

  return result;
}

///////////////////////////////////////////////////////////////////////////////
// Decrypting xor ciphers
///////////////////////////////////////////////////////////////////////////////

struct LetterFrequencies {
  std::array<unsigned int, 26> freqs;
  unsigned int num_letters;
};

LetterFrequencies count_letters(const std::vector<byte> &byte_vector) {
  LetterFrequencies lf = {}; // default value initilization (freqs = [0, ...])

  for (auto b : byte_vector) {
    if (is_lower(b)) {
      lf.freqs[b - 'a'] += 1;
      lf.num_letters++;
    } else if (is_upper(b)) {
      lf.freqs[b - 'A'] += 1;
      lf.num_letters++;
    }
  }

  return lf;
}

double chi_squared_statistic(const std::vector<byte> &byte_vector) {
  auto lf = count_letters(byte_vector);

  static constexpr std::array<double, 26> english_freqs{
      {0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
       0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
       0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
       0.00978, 0.02360, 0.00150, 0.01974, 0.00074}}; // wikipedia

  double chi_statistic = 0.0;
  for (auto i = 0; i < 26; i++) {
    auto o_i = lf.freqs[i];                       // observation
    auto e_i = lf.num_letters * english_freqs[i]; // expected value
    chi_statistic += ((o_i - e_i) * (o_i - e_i)) / e_i;
  }

  return chi_statistic;
}

template <unsigned short int num_keys = 1, bool only_printable = true,
          bool return_chi_stats = true>
std::array<byte, num_keys>
decrypt_single_byte_xor(const std::vector<byte> &ciphertext,
                        std::array<double, num_keys> &best_chis) {
  using key_score = std::pair<double, byte>; // double first to sort later
  std::array<key_score, 256> scores;

  for (auto i = 0; i < 256; i++) {
    auto plaintext = single_byte_xor(ciphertext, i);
    if (!only_printable || is_container_printable(plaintext)) {
      scores[i] = key_score(chi_squared_statistic(plaintext), i);
    } else { // only printable && !is_container_printable(new_plaintext)
      scores[i] = key_score(std::numeric_limits<double>::max(), i);
    }
  }

  std::partial_sort(scores.begin(), scores.begin() + num_keys, scores.end());

  std::array<byte, num_keys> best_keys;
  std::transform(scores.begin(), scores.begin() + num_keys, best_keys.begin(),
                 [](auto ks) { return ks.second; });

  if (return_chi_stats) {
    std::transform(scores.begin(), scores.begin() + num_keys, best_chis.begin(),
                   [](auto ks) { return ks.first; });
  }

  return best_keys;
}

// Simple version for non-returning chi statistics
template <unsigned short int num_keys = 1, bool only_printable = true>
std::array<byte, num_keys>
decrypt_single_byte_xor(const std::vector<byte> &ciphertext) {
  std::array<double, num_keys> null_array;
  return decrypt_single_byte_xor<num_keys, only_printable, false>(ciphertext,
                                                                  null_array);
}

template <unsigned short int num_lines = 1, bool only_printable = true>
std::array<unsigned int, num_lines>
detect_single_byte_xor(std::experimental::string_view filename) {
  std::ifstream input(filename.data());
  std::string cipherline;

  using line_score = std::pair<double, unsigned int>; // double first to sort
  std::vector<line_score> scores;

  for (unsigned int i = 0; std::getline(input, cipherline); i++) {
    std::array<double, 1> best_chis;
    decrypt_single_byte_xor<1, only_printable, true>(
        string_to_bytes(cipherline), best_chis);

    scores.push_back(line_score(best_chis[0], i));
  }

  std::partial_sort(scores.begin(), scores.begin() + num_lines, scores.end());

  std::array<unsigned int, num_lines> best_lines;
  std::transform(scores.begin(), scores.begin() + num_lines, best_lines.begin(),
                 [](auto ks) { return ks.second; });

  return best_lines;
}

template <class InputIt1, class InputIt2>
unsigned int edit_distance(InputIt1 first1, InputIt1 last1, InputIt2 first2,
                           InputIt2 last2) {
  assert(last1 - first1 == last2 - first2);

  unsigned int distance = 0;
  while (first1 != last1) {
    distance += std::bitset<8>((*first1++) ^ (*first2++)).count();
  }
  return distance;
}

template <class Container1, class Container2>
unsigned int edit_distance(Container1 c1, Container2 c2) {
  return edit_distance(std::begin(c1), std::end(c1), std::begin(c2),
                       std::end(c2));
}

template <unsigned int num_keysize_blocks = 10>
double key_size_score(const std::vector<byte> &v, unsigned int key_size) {
  assert(v.size() / key_size >= num_keysize_blocks);
  auto first1 = v.begin();
  auto last1 = first1 + key_size; // equals to first2
  auto last2 = last1 + key_size;

  double distance = 0.0;
  for (unsigned int i = 0; i < num_keysize_blocks; i++) {
    auto offset = (last1 - first1) * i;
    distance += edit_distance(first1 + offset, last1 + offset, last1 + offset,
                              last2 + offset);
  }
  distance /= (num_keysize_blocks * key_size);
  return distance;
}

template <unsigned int max_key_size = 40, bool only_printable = true,
          unsigned int num_keysize_blocks = 10>
std::vector<byte>
break_repeating_key_xor(std::experimental::string_view filename) {
  auto bytes = file_to_bytes(filename, Encoding::base64);

  unsigned int best_key_size = 2;
  auto best_score = key_size_score(bytes, best_key_size);

  for (unsigned int key_size = 3; key_size <= max_key_size; key_size++) {
    auto new_score = key_size_score(bytes, key_size);

    if (new_score < best_score) {
      best_key_size = key_size;
      best_score = new_score;
    }
  }

  std::vector<byte> key;
  key.reserve(best_key_size);
  for (size_t i = 0; i < best_key_size; i++) {
    std::vector<byte> block;
    block.reserve(bytes.size() / best_key_size);
    for (size_t j = i; j < bytes.size(); j += best_key_size) {
      block.push_back(bytes[j]);
    }
    key.push_back(decrypt_single_byte_xor<1, only_printable>(block)[0]);
  }

  return key;
}

///////////////////////////////////////////////////////////////////////////////
// Openssl functions
///////////////////////////////////////////////////////////////////////////////

openssl_c11::secure_string
bytes_to_secure_string(const std::vector<byte> &bytes) {
  return openssl_c11::secure_string(
      reinterpret_cast<const char *>(bytes.data()), bytes.size());
}
