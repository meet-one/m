#pragma once

#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>

namespace meetone {
CONTRACT m : public eosio::contract {
 public:
  using eosio::contract::contract;

  ACTION newaccount(eosio::name newname, std::string owner_key_str);

  ACTION setglobal(eosio::asset stake_net_by_m, eosio::asset stake_cpu_by_m,
                   eosio::asset stake_net_by_own, eosio::asset stake_cpu_by_own,
                   eosio::asset welfare);
  ACTION deleteglobal();

 private:
  void convert_public_key(const std::string& str, eosio::public_key& key);
  bool StartsWith(const std::string& source, const std::string& prefix) {
    return std::equal(prefix.cbegin(), prefix.cend(), source.cbegin());
  }
  struct key_weight {
    eosio::public_key key;
    uint16_t weight;
  };
  struct permission_level_weight {
    eosio::permission_level permission;
    uint16_t weight;
  };
  struct wait_weight {
    uint32_t wait_sec;
    uint16_t weight;
  };
  struct authority {
    uint32_t threshold;
    std::vector<key_weight> keys;
    std::vector<permission_level_weight> accounts;
    std::vector<wait_weight> waits;
  };
  struct createaccount {
    eosio::name creator;
    eosio::name name;
    authority owner;
    authority active;
  };
  struct transfer_args {
    eosio::name from;
    eosio::name to;
    eosio::asset quantity;
    std::string memo;
  };

  TABLE global {
    eosio::asset stake_net_by_m;
    eosio::asset stake_cpu_by_m;
    eosio::asset stake_net_by_own;
    eosio::asset stake_cpu_by_own;
    eosio::asset welfare;

    EOSLIB_SERIALIZE(global, (stake_net_by_m)(stake_cpu_by_m)(stake_net_by_own)(
                                 stake_cpu_by_own)(welfare))
  };

  typedef eosio::singleton<"global"_n, global> global_table;
};

}  // namespace meetone

// Copied from https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
static const int8_t mapBase58[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,
    8,  -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15, 16, -1, 17, 18,
    19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1,
    -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch) {
  static_assert(
      sizeof(mapBase58) / sizeof(mapBase58[0]) == 256,
      "mapBase58.size() should be 256");  // guarantee not out of range

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
  int size =
      (strlen(psz) * 733 + 999) / 1000;  // log(58) / log(256), rounded up.
  std::vector<unsigned char> b256(size);
  // Process the characters.
  while (*psz && !isspace(*psz)) {
    // Decode base58 character
    int carry = mapBase58[(uint8_t)*psz];
    if (carry == -1) {
      // Invalid b58 character
      return false;
    }
    int i = 0;
    for (auto it = b256.rbegin();
         (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
      carry += 58 * (*it);
      //*it = carry % 256;
      // carry /= 256;
      *it = carry & 255;
      carry >>= 8;
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
  auto it = b256.begin() + (size - length);
  while (it != b256.end() && *it == 0)
    it++;
  // Copy result into output vector.
  vch.reserve(zeroes + (b256.end() - it));
  vch.assign(zeroes, 0x00);
  while (it != b256.end())
    vch.push_back(*(it++));
  return true;
}

bool decode_base58(const std::string& str, std::vector<unsigned char>& vch) {
  return DecodeBase58(str.c_str(), vch);
}
