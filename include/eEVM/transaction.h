// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "address.h"
#include "bigint.h"

#include <nlohmann/json.hpp>
#include <vector>

namespace eevm
{
  namespace log
  {
    using Data = std::vector<uint8_t>;
    using Topic = uint256_t;
  }

  struct LogEntry
  {
    Address address;
    log::Data data;
    std::vector<log::Topic> topics;

    bool operator==(const LogEntry& that) const;

    friend void to_json(nlohmann::json&, const LogEntry&);
    friend void from_json(const nlohmann::json&, LogEntry&);
  };

  void to_json(nlohmann::json&, const LogEntry&);
  void from_json(const nlohmann::json&, LogEntry&);

  struct LogHandler
  {
    virtual ~LogHandler() = default;
    virtual void handle(LogEntry&&) = 0;
  };

  struct NullLogHandler : public LogHandler
  {
    NullLogHandler() = default;
    virtual void handle(LogEntry&&) override {}
  };

  struct VectorLogHandler : public LogHandler
  {
    std::vector<LogEntry> logs;

    virtual ~VectorLogHandler() = default;
    virtual void handle(LogEntry&& e) override
    {
      logs.emplace_back(e);
    }
  };

  /**
   * Ethereum transaction
   */
  struct Transaction
  {
    Address origin;
    uint256_t value;
    uint256_t gas_price;
    uint256_t gas_limit;

    LogHandler& log_handler;
    std::vector<std::pair<Address, Address>> selfdestruct_list;

    Transaction() :
      origin{(intx::uint<256>)0},
      value{(intx::uint<256>)0},
      gas_price{(intx::uint<256>)0},
      gas_limit{(intx::uint<256>)0},
      log_handler{*(new NullLogHandler{})},
      selfdestruct_list{std::vector<std::pair<Address, Address>>{}}
    {}

    Transaction(
      const Address origin,
      LogHandler& lh,
      uint256_t value = 0,
      uint256_t gas_price = 0,
      uint256_t gas_limit = 0) :
      origin(origin),
      value(value),
      gas_price(gas_price),
      gas_limit(gas_limit),
      log_handler(lh)
    {}

    Transaction& operator=(const Transaction& other)
    {
      this->origin = other.origin;
      this->value = other.value;
      this->gas_price = other.gas_price;
      this->gas_limit = other.gas_limit;
      this->log_handler = other.log_handler;
      //this->selfdestruct_list = other.selfdestruct_list;

      return *this;
    }
  };

  using TransactionInput = std::vector<uint8_t>;
} // namespace eevm
