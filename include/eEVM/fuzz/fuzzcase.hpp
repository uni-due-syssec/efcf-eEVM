// Copyright (c) Michael Rodler. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "eEVM/bigint.h"
#include "eEVM/fuzz/EthFuzzDataProvider.hpp"
#include "eEVM/fuzz/addresses.hpp"

namespace eevm::fuzz
{
  struct __attribute__((__packed__)) FuzzBlockHeader
  {
    uint64_t number;
    uint64_t difficulty;
    uint64_t gas_limit;
    uint64_t timestamp;
    uint64_t initial_ether;
    // uint8_t coinbase[32]; // would this be useful for something?
    
    uint256_t getInitialEther() const
    {
      constexpr uint64_t VALUE_SHIFT_SET = (((uint64_t)1) << 63);
      uint256_t val(initial_ether);
      if (initial_ether & VALUE_SHIFT_SET)
      {
        val ^= VALUE_SHIFT_SET;
        val <<= 18;
      }
      return val;
    }
  };

  struct __attribute__((__packed__)) FuzzTransactionHeader
  {
    uint16_t input_length;   // 0, 1
    uint8_t return_count;    // 2
    uint8_t receiver_select; // 3
    uint8_t sender_select;   // 4
    uint8_t block_advance;   // 5
    uint8_t _padding1[2];    // 6, 7
    uint64_t call_value;     // 8-16
  };

  struct __attribute__((__packed__)) FuzzReturnHeader
  {
    uint8_t value;
    uint8_t reenter;
    uint16_t length;
  };

  struct FuzzReturn
  {
    FuzzReturnHeader header;
    std::vector<uint8_t> data;
  };

  typedef std::vector<FuzzReturn> FuzzReturnSequence;

  struct FuzzTransaction
  {
    FuzzTransactionHeader header;
    std::vector<uint8_t> data;
    FuzzReturnSequence returns;
    size_t cur_ret = 0;

    unsigned stats_ret_count = 0;

    uint256_t getCallValue()
    {
      constexpr uint64_t VALUE_SHIFT_SET = (((uint64_t)1) << 63);
      uint256_t val(header.call_value);
      // if the most significant bit is set, then we left shift the value. this
      // allows us to cover a larger subset of possible call values without
      // wasting too much space in the input format.
      // We can specify exact amounts up to ~9 ether and everything above
      // becomes approximative... In terms of what kind of constraints this
      // allows us to solve, here are some examples:
      // * [x] require(msg.value == 1 wei)
      // * [x] require(msg.value == 9 ether)
      // * [x] require(msg.value == (9 ether + 1 wei))
      // * [x] require(msg.value == 10 ether)
      // * [ ] require(msg.value == (10 ether + 1 wei))
      // * [ ] require(msg.value > 2417852 ether)
      //
      if (header.call_value & VALUE_SHIFT_SET)
      {
        val ^= VALUE_SHIFT_SET;
        val <<= 18;
      }
      return val;
    }

    const Address getSender()
    {
      auto idx = header.sender_select % eevm::fuzz::NUM_SENDER;
      return eevm::fuzz::tx_sender[idx];
    }

    bool hasReturns()
    {
      return returns.size() > 0;
    }

    const FuzzReturn* getNextReturn()
    {
      if (cur_ret < returns.size())
      {
        auto r = &(returns[cur_ret]);
        cur_ret++;
        stats_ret_count++;
        return r;
      }
      else
      {
        return nullptr;
      }
    }
  };

  class FuzzCaseParser
  {
  private:
    EthFuzzDataProvider fuzz_data;
    FuzzBlockHeader bh;
    std::vector<FuzzTransaction> txs;

    unsigned stats_tx_count = 0;

  public:
    FuzzCaseParser(const uint8_t* data, size_t size) : fuzz_data(data, size)
    {
      auto block_hdr_maybe = fuzz_data.ConsumeType<FuzzBlockHeader>();
      if (block_hdr_maybe.has_value())
      {
        bh = *block_hdr_maybe;
      }
      else
      {
        bh = {0, 0, 0, 0, 0};
      }
    }

    unsigned getStatsTxCount()
    {
      return stats_tx_count;
    }

    unsigned getStatsReturnCount()
    {
      unsigned ret_count = 0;
      for (auto& tx : txs)
      {
        ret_count += tx.stats_ret_count;
      }
      return ret_count;
    }

    const FuzzBlockHeader* getBlockHeader()
    {
      return &bh;
    }

    FuzzTransaction* getCurrentTx()
    {
      if (txs.size() > 0)
      {
        return &txs.back();
      }
      else
      {
        return nullptr;
      }
    }

    void popTransaction()
    {
      txs.pop_back();
    }

    FuzzTransaction* getNextTx()
    {
      auto tx_hdr_maybe = fuzz_data.ConsumeType<FuzzTransactionHeader>();
      if (tx_hdr_maybe.has_value())
      {
        auto tx_hdr = *tx_hdr_maybe;
        auto tx_input = fuzz_data.ConsumeBytes<uint8_t>(tx_hdr.input_length);
        FuzzReturnSequence returns = {};
        if (tx_hdr.input_length == tx_input.size())
        {
          for (size_t i = 0; i < tx_hdr.return_count; i++)
          {
            auto ret_hdr_maybe = fuzz_data.ConsumeType<FuzzReturnHeader>();
            if (ret_hdr_maybe.has_value())
            {
              auto ret_hdr = *ret_hdr_maybe;
              auto ret_data = fuzz_data.ConsumeBytes<uint8_t>(ret_hdr.length);
              bool reached_end = false;
              if (ret_data.size() != ret_hdr.length)
              {
                reached_end = true;
                ret_hdr.length = ret_data.size();
              }
              // according to evm spec, can only ever be 0/1
              ret_hdr.value = ret_hdr.value & 1;
              returns.push_back({ret_hdr, ret_data});
              if (reached_end)
              {
                break;
              }
            }
            else
            {
              break;
            }
          }
          tx_hdr.return_count = returns.size();
        }
        else
        {
          tx_hdr.input_length = tx_input.size();
        }
        tx_hdr.return_count = returns.size();

        txs.push_back({tx_hdr, tx_input, returns});

        stats_tx_count++;

        return &txs.back();
      }
      else
      {
        return nullptr;
      }
    }
  };
}
