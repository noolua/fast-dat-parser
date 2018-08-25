#pragma once
#include <string>
#include "hash.hpp"
#include "ranger.hpp"
#include "serial.hpp"

/*
  reference:
    https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
*/

typedef std::array<uint8_t, 25> address_t;
static const char* b58alphabets = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t mapBase58[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};
template<typename R>
bool base58decode(const char* psz, R &vch)
{
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    int size = strlen(psz) * 733 /1000 + 1; // log(58) / log(256), rounded up.
    std::vector<uint8_t> b256(size);
    // Process the characters.
    // static_assert(sizeof(mapBase58)/sizeof(mapBase58[0]) == 256, "mapBase58.size() should be 256"); // guarantee not out of range
    while (*psz && !isspace(*psz)) {
        // Decode base58 character
        int carry = mapBase58[(uint8_t)*psz];
        if (carry == -1)  // Invalid b58 character
            return false;
        int i = 0;
        for (std::vector<uint8_t>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
      psz++;
    if (*psz != 0)
      return false;
    // Skip leading zeroes in b256.
    std::vector<uint8_t>::iterator it = b256.begin() + (size - length);
    while (it != b256.end() && *it == 0)
      it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
      vch.push_back(*(it++));
    return true;
}

template<typename R>
std::string base58encode(R &r){
  uint8_t *pbegin = r.begin(), *pend = r.end();
  int zeroes = 0;
  int length = 0;
  while (pbegin != pend && *pbegin == 0) {
      pbegin++;
      zeroes++;
  }
  // Allocate enough space in big-endian base58 representation.
  int size = (pend - pbegin) * 138 / 100 + 1; // log(256) / log(58), rounded up.
  std::vector<uint8_t> b58(size);
  // Process the bytes.
  while (pbegin != pend) {
      int carry = *pbegin;
      int i = 0;
      // Apply "b58 = b58 * 256 + ch".
      for (std::vector<uint8_t>::reverse_iterator it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
          carry += 256 * (*it);
          *it = carry % 58;
          carry /= 58;
      }
      assert(carry == 0);
      length = i;
      pbegin++;
  }
  // Skip leading zeroes in base58 result.
  std::vector<uint8_t>::iterator it = b58.begin() + (size - length);
  while (it != b58.end() && *it == 0)
      it++;
  // Translate the result into a string.
  std::string str;
  str.reserve(zeroes + (b58.end() - it));
  str.assign(zeroes, '1');
  while (it != b58.end())
    str += b58alphabets[*(it++)];
  return str;
}

address_t hash2address(uint160_t &hash, uint8_t version){
  address_t address;
  serial::place<uint8_t>(address, version);
  serial::place<uint160_t>(range(address).drop(1), hash);
  // auto r_addr = range(address).take(21);
  auto check_sum = hash256(range(address).take(21));
  range(address).drop(21).put(range(check_sum).take(4));
  return address;
}

template<typename R>
address_t pubkey2address(R &pk){
  auto hash = rmd160(sha256(pk));
  return hash2address(hash, 0);
}
