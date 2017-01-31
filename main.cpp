#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "utilities.cpp"

TEST_CASE("Challenge 1 extended.") {
  std::string ascii_s = "I'm killing your brain like a poisonous mushroom";
  std::string hex_s =
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706"
      "f69736f6e6f7573206d757368726f6f6d";
  std::string base64_s =
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  auto hex_v = string_to_bytes(hex_s);
  auto ascii_v = string_to_bytes(ascii_s, Encoding::ascii);
  auto base64_v = string_to_bytes(base64_s, Encoding::base64);

  REQUIRE(bytes_to_string(hex_v) == bytes_to_string(ascii_v));
  REQUIRE(bytes_to_string(hex_v) == bytes_to_string(base64_v));
  REQUIRE(bytes_to_string(hex_v) == hex_s);
  REQUIRE(bytes_to_string(hex_v, Encoding::ascii) == ascii_s);
  REQUIRE(bytes_to_string(hex_v, Encoding::base64) == base64_s);
}

TEST_CASE("Challenge 2.") {
  auto lhs = string_to_bytes("1c0111001f010100061a024b53535009181c");
  auto rhs = string_to_bytes("686974207468652062756c6c277320657965");
  auto result = string_to_bytes("746865206b696420646f6e277420706c6179");

  REQUIRE(fixed_xor(lhs, rhs) == result);
}

TEST_CASE("Challenge 3.") {
  auto ciphertext = string_to_bytes(
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
  auto plaintext =
      string_to_bytes("Cooking MC's like a pound of bacon", Encoding::ascii);
  byte key = 'X';
  auto decrypted_key = decrypt_single_byte_xor(ciphertext)[0];

  REQUIRE(decrypted_key == key);
  REQUIRE(single_byte_xor(ciphertext, decrypted_key) == plaintext);
}

TEST_CASE("Challenge 4.") {
  std::string plainline = "Now that the party is jumping\n";
  auto best_lines = detect_single_byte_xor<2>("4.txt");
  bool line_found = false;

  std::ifstream input("4.txt");
  std::string cipherline;
  for (unsigned int i = 0; std::getline(input, cipherline); i++) {
    if (std::find(best_lines.begin(), best_lines.end(), i) !=
        best_lines.end()) {
      auto bytes = string_to_bytes(cipherline);
      auto decrypted_key = decrypt_single_byte_xor(bytes)[0];
      auto new_plainline = bytes_to_string(
          single_byte_xor(bytes, decrypted_key), Encoding::ascii);
      if (plainline == new_plainline) {
        line_found = true;
        break;
      }
    }
  }

  REQUIRE(line_found == true);
}

TEST_CASE("Challenge 5.") {
  auto plaintext = string_to_bytes("Burning 'em, if you ain't quick and "
                                   "nimble\nI go crazy when I hear a cymbal",
                                   Encoding::ascii);
  auto key = string_to_bytes("ICE", Encoding::ascii);
  auto ciphertext =
      string_to_bytes("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c"
                      "2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b"
                      "2027630c692b20283165286326302e27282f",
                      Encoding::hex);

  REQUIRE(repeating_key_xor(plaintext, key) == ciphertext);
}

TEST_CASE("Challenge 6.") {
  auto s1 = string_to_bytes("this is a test", Encoding::ascii);
  auto s2 = string_to_bytes("wokka wokka!!!", Encoding::ascii);
  REQUIRE(edit_distance(s1, s2) == 37);

  auto key = break_repeating_key_xor("6.txt");
  REQUIRE(bytes_to_string(key, Encoding::ascii) ==
          "Terminator X: Bring the noise");
}

TEST_CASE("Challenge 7.") {
  auto ciphertext = file_to_bytes("7.txt", Encoding::base64);
  auto key = string_to_bytes("YELLOW SUBMARINE", Encoding::ascii);
  auto ptext =
      bytes_to_string(decrypt_aes_128_ecb(ciphertext, key), Encoding::ascii);
  ptext.resize(ptext.find_first_of('\n') - 1); // first line
  REQUIRE(ptext == "I'm back and I'm ringin' the bell");
}
