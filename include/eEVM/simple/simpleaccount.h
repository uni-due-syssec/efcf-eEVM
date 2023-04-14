// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "eEVM/account.h"

#include <nlohmann/json.hpp>

namespace eevm
{
  /**
   * Simple implementation of Account
   */
  class SimpleAccount : public Account
  {
  private:
    Address address = {};
    uint256_t balance = {};
    std::shared_ptr<Code> code = {};
    Nonce nonce = {};
    void* specialized_processor = nullptr;
    bool mocked = false;

  public:
    SimpleAccount() = default;

    ~SimpleAccount() override
    {
      specialized_processor = nullptr;
    }

    SimpleAccount(const SimpleAccount& obj) :
      address(obj.address),
      balance(obj.balance),
      code(obj.code),
      nonce(obj.nonce),
      specialized_processor(obj.specialized_processor),
      mocked(obj.mocked)
    {}

    SimpleAccount(const Address& a, const uint256_t& b, const Code& c) :
      address(a),
      balance(b),
      code(std::make_shared<Code>(c)),
      nonce(0),
      specialized_processor(nullptr)
    {}

    SimpleAccount(
      const Address& a, const uint256_t& b, const Code& c, Nonce n) :
      address(a),
      balance(b),
      code(std::make_shared<Code>(c)),
      nonce(n),
      specialized_processor(nullptr)
    {}

    virtual void set_specialized_processor(
      void* t_specialized_processor) override;

    virtual void* get_specialized_processor() const override;

    virtual Address get_address() const override;
    void set_address(const Address& a);

    virtual uint256_t get_balance() const override;
    virtual void set_balance(const uint256_t& b) override;

    virtual Nonce get_nonce() const override;
    void set_nonce(Nonce n);
    virtual void increment_nonce() override;

    virtual std::shared_ptr<Code> get_code_ref() override;
    virtual Code& get_code() const override;
    virtual void set_code(Code&& c) override;
    virtual bool has_code() override;

    bool operator==(const Account&) const;

    virtual bool is_mocked() override
    {
      return mocked;
    };
    virtual void set_mocked(bool m) override
    {
      mocked = m;
    };

    friend void to_json(nlohmann::json&, const SimpleAccount&);
    friend void from_json(const nlohmann::json&, SimpleAccount&);
  };

  void to_json(nlohmann::json&, const SimpleAccount&);
  void from_json(const nlohmann::json&, SimpleAccount&);
} // namespace eevm
