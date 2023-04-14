// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "eEVM/globalstate.h"
#include "eEVM/simple/msgpacker.h"
#include "eEVM/simple/simpleaccount.h"
#include "eEVM/simple/simplestorage.h"

namespace eevm
{
  /**
   * Simple std::map-backed implementation of GlobalState
   */
  class SimpleGlobalState : public GlobalState
  {
  public:
    using StateEntry = std::pair<SimpleAccount, SimpleStorage>;

  private:
    Block currentBlock;

    std::map<Address, StateEntry> accounts;

  public:
    SimpleGlobalState() = default;

    virtual ~SimpleGlobalState() = default;

    SimpleGlobalState(const SimpleGlobalState& obj) :
      currentBlock(obj.currentBlock)
    {
      accounts = obj.accounts;
    }

    explicit SimpleGlobalState(Block b) : currentBlock(std::move(b)) {}

    explicit SimpleGlobalState(const SimpleGlobalState& obj, Block b) :
      currentBlock(std::move(b))
    {
      this->accounts = obj.accounts;
    }

    explicit SimpleGlobalState(
      const SimpleGlobalState* obj, Block b, bool use_backing_store);

    void for_each_account(const std::function<void(AccountState)>& f)
    {
      for (auto& a : accounts)
      {
        f(a.second);
      }
    }

    virtual void remove(const Address& addr) override;

    AccountState get(const Address& addr) override;

    std::map<Address, StateEntry>& getAccounts()
    {
      return this->accounts;
    }

    AccountState create(
      const Address& addr, const uint256_t& balance, const Code& code) override;
    AccountState create(
      const Address& addr,
      const uint256_t& balance,
      const Code& code,
      const Account::Nonce& nonce);

    virtual bool exists(const Address& addr) override;
    size_t num_accounts();

    virtual Block& get_current_block() override;
    virtual uint256_t get_block_hash(uint64_t offset) override;
    void set_current_block(Block& block) override;

    /**
     * For tests which require some initial state, allow manual insertion of
     * pre-constructed accounts
     */
    void insert(const StateEntry& e);

    friend void to_json(nlohmann::json&, const SimpleGlobalState&);
    friend void from_json(const nlohmann::json&, SimpleGlobalState&);
    friend bool operator==(const SimpleGlobalState&, const SimpleGlobalState&);
    friend bool operator!=(
      const SimpleGlobalState& l, const SimpleGlobalState& r);

    friend bool dump_simplestate_msgpack(
      eevm::SimpleGlobalState* gs, const std::string& fname);
  };

  void to_json(nlohmann::json&, const SimpleGlobalState&);
  void from_json(const nlohmann::json&, SimpleGlobalState&);
  bool operator==(const SimpleGlobalState&, const SimpleGlobalState&);
} // namespace eevm
