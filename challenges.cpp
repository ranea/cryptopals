#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "utilities.cpp"

TEST_CASE("Challege1 extended.") {
  std::string ascii_s = "I'm killing your brain like a poisonous mushroom";
  std::string hex_s =
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706"
      "f69736f6e6f7573206d757368726f6f6d";
  std::string base64_s =
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  auto hex_v = string_to_byte_vector(hex_s);
  auto ascii_v = string_to_byte_vector(ascii_s, Encoding::ascii);
  auto base64_v = string_to_byte_vector(base64_s, Encoding::base64);

  REQUIRE(byte_vector_to_string(hex_v) == byte_vector_to_string(ascii_v));
  REQUIRE(byte_vector_to_string(hex_v) == byte_vector_to_string(base64_v));
  REQUIRE(byte_vector_to_string(hex_v) == hex_s);
  REQUIRE(byte_vector_to_string(hex_v, Encoding::ascii) == ascii_s);
  REQUIRE(byte_vector_to_string(hex_v, Encoding::base64) == base64_s);
}

TEST_CASE("Challege2.") {
  auto lhs = string_to_byte_vector("1c0111001f010100061a024b53535009181c");
  auto rhs = string_to_byte_vector("686974207468652062756c6c277320657965");
  auto result = string_to_byte_vector("746865206b696420646f6e277420706c6179");

  REQUIRE(fixed_xor(lhs, rhs) == result);
}
