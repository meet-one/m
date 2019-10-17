#include "../include/m.hpp"

namespace meetone {

const auto kSuffix = std::string(".m");

void m::newaccount(eosio::name newname, std::string owner_key_str) {
  require_auth(get_self());
  std::string newname_str = newname.to_string();
  // Account name suffix should be .m
  std::string account_suffix = newname_str.substr(newname_str.size() - 2);
  eosio::check(account_suffix.compare(kSuffix) == 0,
               "account name must be 9 characters with no dots + .m.");
  // Newaccout for short name
  eosio::check(newname_str.size() == 11,
               "account name must be 9 characters with no dots + .m.");

  bool has_dot = false;
  uint32_t dot_count = 0;
  for (int32_t moving_bits = 4; moving_bits <= 59; moving_bits += 5) {
    if ((newname.value & (0x1full << moving_bits))) {
      has_dot = true;
    }
    if (!(newname.value & (0x1full << moving_bits)) && has_dot) {
      dot_count += 1;
      eosio::check(dot_count < 2,
                   "Account name must be 9 characters with no dots + .m");
    }
  }
  eosio::check(!eosio::is_account(newname), "that name is already taken.");

  // owner key decode
  eosio::public_key pubkey;
  convert_public_key(owner_key_str, pubkey);

  // buy_ram 4kb
  uint32_t buy_ram_bytes = 4 * 1024;

  key_weight pubkey_weight = {
      .key = pubkey,
      .weight = 1,
  };

  authority owner = authority{
      .threshold = 1, .keys = {pubkey_weight}, .accounts = {}, .waits = {}};
  authority active = authority{
      .threshold = 1, .keys = {pubkey_weight}, .accounts = {}, .waits = {}};
  struct createaccount new_account = createaccount{
      .creator = get_self(), .name = newname, .owner = owner, .active = active};

  // newaccount action
  eosio::action(eosio::permission_level{get_self(), "active"_n}, "eosio"_n,
                "newaccount"_n, new_account)
      .send();

  // buy ram action
  eosio::action(eosio::permission_level{get_self(), "active"_n}, "eosio"_n,
                "buyrambytes"_n,
                std::make_tuple(get_self(), newname, buy_ram_bytes))
      .send();

  global_table globals(get_self(), get_self().value);
  auto global = globals.get();

  // delegatebw action by own
  if (global.stake_net_by_own.amount + global.stake_cpu_by_own.amount > 0) {
    eosio::action(eosio::permission_level{get_self(), "active"_n}, "eosio"_n,
                  "delegatebw"_n,
                  std::make_tuple(get_self(), newname, global.stake_net_by_own,
                                  global.stake_cpu_by_own, true))
        .send();
  }

  // delegatebw action by m
  if (global.stake_net_by_m.amount + global.stake_cpu_by_m.amount > 0) {
    eosio::action(eosio::permission_level{get_self(), "active"_n}, "eosio"_n,
                  "delegatebw"_n,
                  std::make_tuple(get_self(), newname, global.stake_net_by_m,
                                  global.stake_cpu_by_m, false))
        .send();
  }

  // transfer
  if (global.welfare.amount > 0) {
    eosio::action(eosio::permission_level{get_self(), "active"_n},
                  "eosio.token"_n, "transfer"_n,
                  transfer_args{get_self(), newname, global.welfare,
                                "new account welfare!"})
        .send();
  }
}

void m::setglobal(eosio::asset stake_net_by_m,
                  eosio::asset stake_cpu_by_m,
                  eosio::asset stake_net_by_own,
                  eosio::asset stake_cpu_by_own,
                  eosio::asset welfare) {
  require_auth(get_self());

#if MAINNET
  constexpr auto kSystemSymbol = eosio::symbol("EOS", 4);
#else
  constexpr auto kSystemSymbol = eosio::symbol("MEETONE", 4);
#endif
  eosio::check(stake_net_by_m.symbol == kSystemSymbol &&
                   stake_cpu_by_m.symbol == kSystemSymbol &&
                   stake_net_by_own.symbol == kSystemSymbol &&
                   stake_cpu_by_own.symbol == kSystemSymbol &&
                   welfare.symbol == kSystemSymbol,
               "symbol mismatch!");
  global_table globals(get_self(), get_self().value);
  globals.set({stake_net_by_m, stake_cpu_by_m, stake_net_by_own,
               stake_cpu_by_own, welfare},
              get_self());
}

void m::deleteglobal() {
  require_auth(get_self());
  global_table globals(get_self(), get_self().value);
  globals.remove();
}

void m::convert_public_key(const std::string& str, eosio::public_key& key) {
  static const size_t kPublicKeySize = 33;
  static const std::string k1_prefix("EOS");

  // UMU: 这里只支持 K1，如果要支持 R1，请修改这个函数
  // K1 格式 53 字符，前缀：EOS，负载 50 字符
  // R1 格式 57 字符，前缀：PUB_R1_，负载 50 字符
  eosio::check(str.size() == 53, "length of public key should be 53");
  eosio::check(StartsWith(str, k1_prefix), "public key should starts with EOS");

  auto base58_payload = str.substr(k1_prefix.size());
  std::vector<unsigned char> vch;
  eosio::check(decode_base58(base58_payload, vch), "decode public key failed");
  eosio::check(vch.size() == 37, "invalid public key length");
  copy_n(vch.begin(), kPublicKeySize, key.data.begin());

  eosio::checksum160 checksum;
  checksum = eosio::ripemd160(key.data.data(), kPublicKeySize);
  eosio::check(std::equal(vch.cend() - 4, vch.cend(),
                          checksum.extract_as_byte_array().data()),
               "wrong checksum for public key");
}

}  // namespace meetone

