// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#C.2B.2B_Programs
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wunused-parameter"
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace openssl_c11 {
///////////////////////////////////////////////////////////////////////////////
// Internal members
///////////////////////////////////////////////////////////////////////////////

template <typename T> struct zallocator {
public:
  typedef T value_type;
  typedef value_type *pointer;
  typedef const value_type *const_pointer;
  typedef value_type &reference;
  typedef const value_type &const_reference;
  typedef std::size_t size_type;
  typedef std::ptrdiff_t difference_type;

  pointer address(reference v) const { return &v; }
  const_pointer address(const_reference v) const { return &v; }

  pointer allocate(size_type n, const void *hint = 0) {
    if (n > std::numeric_limits<size_type>::max() / sizeof(T))
      throw std::bad_alloc();
    return static_cast<pointer>(::operator new(n * sizeof(value_type)));
  }

  void deallocate(pointer p, size_type n) {
    OPENSSL_cleanse(p, n * sizeof(T));
    ::operator delete(p);
  }

  size_type max_size() const {
    return std::numeric_limits<size_type>::max() / sizeof(T);
  }

  template <typename U> struct rebind { typedef zallocator<U> other; };

  void construct(pointer ptr, const T &val) {
    new (static_cast<T *>(ptr)) T(val);
  }

  void destroy(pointer ptr) { static_cast<T *>(ptr)->~T(); }

  template <typename U, typename... Args>
  void construct(U *ptr, Args &&... args) {
    ::new (static_cast<void *>(ptr)) U(std::forward<Args>(args)...);
  }

  template <typename U> void destroy(U *ptr) { ptr->~U(); }
};

typedef unsigned char byte;
typedef std::basic_string<char, std::char_traits<char>, zallocator<char>>
    secure_string;
using EVP_CIPHER_CTX_free_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

template <unsigned int KEY_SIZE = 16, unsigned int BLOCK_SIZE = 16>
void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE]) {
  int rc = RAND_bytes(key, KEY_SIZE);
  if (rc != 1)
    throw std::runtime_error("RAND_bytes key failed");

  rc = RAND_bytes(iv, BLOCK_SIZE);
  if (rc != 1)
    throw std::runtime_error("RAND_bytes for iv failed");
}

template <decltype(EVP_aes_128_ecb) AesCipher = EVP_aes_128_ecb,
          unsigned int KEY_SIZE = 16, unsigned int BLOCK_SIZE = 16>
void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE],
                 const secure_string &ptext, secure_string &ctext) {
  EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
  int rc = EVP_EncryptInit_ex(ctx.get(), AesCipher(), NULL, key, iv);
  if (rc != 1)
    throw std::runtime_error("EVP_EncryptInit_ex failed");

  // Recovered text expands upto BLOCK_SIZE
  ctext.resize(ptext.size() + BLOCK_SIZE);
  int out_len1 = (int)ctext.size();

  rc = EVP_EncryptUpdate(ctx.get(), (byte *)&ctext[0], &out_len1,
                         (const byte *)&ptext[0], (int)ptext.size());
  if (rc != 1)
    throw std::runtime_error("EVP_EncryptUpdate failed");

  int out_len2 = (int)ctext.size() - out_len1;
  rc = EVP_EncryptFinal_ex(ctx.get(), (byte *)&ctext[0] + out_len1, &out_len2);
  if (rc != 1)
    throw std::runtime_error("EVP_EncryptFinal_ex failed");

  // Set cipher text size now that we know it
  ctext.resize(out_len1 + out_len2);
}

template <decltype(EVP_aes_128_ecb) AesCipher = EVP_aes_128_ecb,
          unsigned int KEY_SIZE = 16, unsigned int BLOCK_SIZE = 16>
void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE],
                 const secure_string &ctext, secure_string &rtext) {
  EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
  int rc = EVP_DecryptInit_ex(ctx.get(), AesCipher(), NULL, key, iv);
  if (rc != 1)
    throw std::runtime_error("EVP_DecryptInit_ex failed");

  // Recovered text contracts upto BLOCK_SIZE
  rtext.resize(ctext.size());
  int out_len1 = (int)rtext.size();

  rc = EVP_DecryptUpdate(ctx.get(), (byte *)&rtext[0], &out_len1,
                         (const byte *)&ctext[0], (int)ctext.size());
  if (rc != 1)
    throw std::runtime_error("EVP_DecryptUpdate failed");

  int out_len2 = (int)rtext.size() - out_len1;
  rc = EVP_DecryptFinal_ex(ctx.get(), (byte *)&rtext[0] + out_len1, &out_len2);
  if (rc != 1)
    throw std::runtime_error("EVP_DecryptFinal_ex failed");

  // Set recovered text size now that we know it
  rtext.resize(out_len1 + out_len2);
}

///////////////////////////////////////////////////////////////////////////////
// Public functions
///////////////////////////////////////////////////////////////////////////////
template <decltype(EVP_aes_128_ecb) AesCipher = EVP_aes_128_ecb,
          unsigned int KEY_SIZE = 16, unsigned int BLOCK_SIZE = 16>
secure_string smart_aes_decrypt(const secure_string &ctext,
                                const byte key[KEY_SIZE]) {
  EVP_add_cipher(AesCipher());
  secure_string ptext;
  static constexpr byte iv[BLOCK_SIZE] = {0};
  aes_decrypt<AesCipher, KEY_SIZE, BLOCK_SIZE>(key, iv, ctext, ptext);
  return ptext;
}
}
