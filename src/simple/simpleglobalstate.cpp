// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "eEVM/bigint.h"
#include "eEVM/simple/simpleglobalstate.h"
#include "eEVM/simple/msgpacker.h"
#include <cstdint>

namespace eevm
{

  SimpleGlobalState::SimpleGlobalState(
      const SimpleGlobalState* obj, Block b, bool use_backing_store) :
      currentBlock(std::move(b))
    {
      // std::cerr << "cloning SimpleGlobalState with #accounts = " << obj->accounts.size() << "and new block with backing store? =>" << use_backing_store << std::endl;
      for (auto& a : obj->accounts)
      {
        SimpleStorage st;
        if (use_backing_store && 
            /* optimization: don't use backinstore if not necesary */
            a.second.second.size() > 0 && 
            /* disallow a second backing store for now */
            (!a.second.second.has_backing_store())) {
          // std::cerr << "using backingstore for " << eevm::to_hex_string(a.first) << " in global state" << std::endl;
          st.set_backing_store(&a.second.second);
        } else {
          // trigger copy-constructor
          st = a.second.second;
        }
        accounts[a.first] = std::make_pair(a.second.first, std::move(st));
      }
    }

  void SimpleGlobalState::remove(const Address& addr)
  {
    accounts.erase(addr);
  }

  AccountState SimpleGlobalState::get(const Address& addr)
  {
    const auto acc = accounts.find(addr);
    if (acc != accounts.cend())
      return acc->second;

    return create(addr, 0, {});
  }

  AccountState SimpleGlobalState::create(
    const Address& addr, const uint256_t& balance, const Code& code)
  {
    insert({SimpleAccount(addr, balance, code), {}});

    return get(addr);
  }

  AccountState SimpleGlobalState::create(
    const Address& addr, const uint256_t& balance, const Code& code, const Account::Nonce& nonce)
  {
    insert({SimpleAccount(addr, balance, code, nonce), {}});

    return get(addr);
  }


  bool SimpleGlobalState::exists(const Address& addr)
  {
    return accounts.find(addr) != accounts.end();
  }

  size_t SimpleGlobalState::num_accounts()
  {
    return accounts.size();
  }

  Block& SimpleGlobalState::get_current_block()
  {
    return currentBlock;
  }

  void SimpleGlobalState::set_current_block(Block& block)
  {
    currentBlock = block;
  }

  uint256_t SimpleGlobalState::get_block_hash(uint64_t offset)
  {
    using namespace intx;
    // return 0xe12b377280d0b42a38ca891056e0955a987c1784fc9f079ecf7072f6ad78887d_u256;
    return 0xfefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe_u256 - offset;
  }

  void SimpleGlobalState::insert(const StateEntry& p)
  {
    const auto ib = accounts.insert(std::make_pair(p.first.get_address(), p));

    assert(ib.second);
  }

  bool operator==(const SimpleGlobalState& l, const SimpleGlobalState& r)
  {
    return (l.accounts == r.accounts) && (l.currentBlock == r.currentBlock);
  }

  bool operator!=(const SimpleGlobalState& l, const SimpleGlobalState& r)
  {
    return ! (l == r);
  }

  void to_json(nlohmann::json& j, const SimpleGlobalState& s)
  {
    j["block"] = s.currentBlock;
    auto o = nlohmann::json::array();
    for (const auto& p : s.accounts)
    {
      o.push_back({to_hex_string(p.first), p.second});
    }
    j["accounts"] = o;
  }

  void from_json(const nlohmann::json& j, SimpleGlobalState& a)
  {
    if (j.find("block") != j.end())
    {
      a.currentBlock = j["block"];
    }

    for (const auto& it : j["accounts"].items())
    {
      const auto& v = it.value();
      a.accounts.insert(make_pair(to_uint256(v[0]), v[1]));
    }
  }
} // namespace eevm
