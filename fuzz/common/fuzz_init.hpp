// Copyright (c) Michael Rodler. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "eEVM/evm2cpp/contracts.h"
#include "eEVM/fuzz/addresses.hpp"
#include "eEVM/fuzz/fuzzcase.hpp"
#include "eEVM/opcode.h"
#include "eEVM/processor.h"
#include "eEVM/simple/simpleglobalstate.h"
#include "fuzz_config.hpp"

#include <fmt/format_header_only.h>
#include <fstream>
#include <iostream>
#include <type_traits>
#include <vector>

#define _TOKENPASTE(x, y) x##y
#define _TOKENPASTE2(x, y) _TOKENPASTE(x, y)

#define CONTRACT _TOKENPASTE2(eevm::EVM2CPP_, TARGET_CONTRACT)

namespace eevm
{
  namespace fuzz
  {
    inline char* evm_coverage_file = nullptr;

    inline std::string dump_state_to = "";
    // inline std::string save_trace = "";
    inline std::string dump_comparison_log = "";
    inline std::ofstream dump_comparison_log_fs;

    inline bool custom_global_state_loaded = false;

    inline std::shared_ptr<eevm::SimpleGlobalState> global_state;
    inline eevm::NullLogHandler ignore_logs;
    inline eevm::VectorLogHandler keep_logs;
    void check_properties(eevm::AccountState&, eevm::Processor&);
    void check_revert_output(std::vector<uint8_t>&);
    void check_logs(eevm::VectorLogHandler&);

    inline std::vector<std::pair<std::vector<uint8_t>, std::string>>
      invariant_properties;
    inline const std::vector<uint8_t> PROPERTY_EXPECTED_RETURN = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    inline std::vector<std::pair<uint256_t, string>> EVENT_TOPICS_TO_REPORT = {
      {0x4e487b71539e0164c9d29506cc725e49342bcac15e0927282bf30fedfe1c7268_u256,
       "Panic(uint256)"},
      {0xb42604cb105a16c8f6db8a41e6b00c0c1b4826465e8bc504b3eb3e88b3e6a4a0_u256,
       "AssertionFailed(string)"},
      {0xf92d4a94d1d5014696dcfc65a0a061af97608eebd7fea0519ff4fdbca71bae9f_u256,
       "AssertionFailed()"},
      {0xf7889b86ffab17fff0fcdf4cd268e14d338480cb7058f6fdfed3975f6524a6cf_u256,
       "AssertionFailed(uint256)"},
    };

    constexpr eevm::Address choose_tx_from[] = {
      tx_sender[0],
      tx_sender[1],
      tx_sender[2],
      tx_sender[3],
      tx_sender[4],
      tx_sender[5],
      contract_creator,
    };


    inline std::vector<eevm::Address> tx_receivers;

#define fuzzer_signal_crash(msg, details) \
  { \
    std::cerr << "[BUG] " << msg << " | " << details << std::endl; \
    if (!eevm::fuzz::do_not_abort_fuzzer) [[likely]] \
      std::abort(); \
  }

#define DBG(X) \
  if (eevm::fuzz::debug_print) [[unlikely]] \
  { \
    X; \
  }

    // Run input as an EVM transaction, check the result and return the output
    inline std::vector<uint8_t> run_and_check_result(
      const eevm::Address& from,
      const eevm::Address& to,
      const eevm::Code& input)
    {
      eevm::Transaction tx(from, ignore_logs);
      eevm::Processor p(global_state);
      const auto exec_result = p.run(
        std::make_shared<Transaction>(tx),
        from,
        global_state->get(to),
        input,
        0u,
        nullptr);

      if (exec_result.er != eevm::ExitReason::returned)
      {
        // Print the trace if nothing was returned
        if (exec_result.er == eevm::ExitReason::threw)
        {
          // Rethrow to highlight any exceptions raised in execution
          auto msg = fmt::format(
            "Execution threw an error: {} (last EVM PC was {})",
            exec_result.exmsg,
            exec_result.last_pc);
          std::cerr << msg << std::endl;
          throw std::runtime_error(msg);
        }

        auto msg = fmt::format(
          "Deployment did not return properly: (reason {}, last EVM PC {}) {}",
          exec_result.er,
          exec_result.last_pc,
          exec_result.exmsg);
        std::cerr << msg << std::endl;
        throw std::runtime_error(msg);
      }

      return exec_result.output;
    }

    inline bool string_ends_with(
      std::string const& str, std::string const& suffix)
    {
      if (str.length() < suffix.length())
      {
        return false;
      }
      return str.rfind(suffix) == str.size() - suffix.size();
    }

    // Function to load the invariant properties from file to
    // invariant_properties vector
    inline void load_invariant_properties(std::string propertyPath)
    {
      std::ifstream invariant_property_file;
      invariant_property_file.open(propertyPath);
      if (!invariant_property_file)
      {
        auto msg = fmt::format(
          "The following property file cannot be opened : {}", propertyPath);
        std::cerr << msg << std::endl;
        throw std::runtime_error(msg);
      }
      else
      {
        std::string line;
        while (std::getline(invariant_property_file, line))
        {
          // skip if the string starts with "//" or "#"
          if (line.rfind("//", 0) != 0 && line.rfind("#", 0) != 0)
          {
            int pos = line.find(":");
            std::string byte = line.substr(0, pos);
            std::string funcname = line.substr(pos + 1, line.length());
            std::pair<vector<uint8_t>, std::string> tmp_pair(
              eevm::to_bytes(byte), funcname);
            invariant_properties.push_back(tmp_pair);
            if (debug_print)
            {
              std::cout << " BYTE AND NAME " << byte << " -" << funcname
                        << std::endl;
            }
          }
        }
      }
    }

    inline void load_additional_log_topics(std::string path)
    {
      std::ifstream ifile;
      ifile.open(path);
      if (!ifile)
      {
        auto msg = fmt::format("Could not load log topic from file: {}", path);
        std::cerr << "[ERROR]" << msg << std::endl;
        throw std::runtime_error(msg);
      }

      std::string line;
      while (std::getline(ifile, line))
      {
        // skip if the string starts with "//" or "#"
        if (line.rfind("//", 0) != 0 && line.rfind("#", 0) != 0)
        {
          int pos = line.find(":");
          std::string hash = line.substr(0, pos);
          std::string name = line.substr(pos + 1, line.length());
          hash = "0x" + hash;
          uint256_t hashi = eevm::to_uint256(hash);
          EVENT_TOPICS_TO_REPORT.push_back(std::make_pair(hashi, name));
        }
      }
    }

    void dump_state(eevm::SimpleGlobalState* gs, const std::string& postfix);

    void dump_state_json(
      eevm::SimpleGlobalState* gs, const std::string& postfix);

    bool initialize_fuzz();

    bool save_coverage(const eevm::Trace& trace, const Address contract);
    bool dump_comparion_ops_to_file(
      const eevm::Trace& trace, std::ofstream& fs);

#define FUZZ_ASSERT(cond, msg) \
  { \
    if (!(cond)) \
    { \
      std::cerr << __FILE__ << ":" << __LINE__ \
                << " assertion failed during fuzzing: " << std::string(msg) \
                << std::endl; \
      abort(); \
    } \
  }

    template <typename T>
    inline void _print_left_right(T left, T right)
    {
      std::cerr << "left: " << left << std::endl
                << "right: " << right << std::endl;
    }

    template <>
    inline void _print_left_right(const uint256_t left, const uint256_t right)
    {
      std::cerr << "left: " << eevm::to_hex_string(left) << std::endl
                << "right: " << eevm::to_hex_string(right) << std::endl;
    }

    template <>
    inline void _print_left_right(
      const std::vector<uint8_t> left, decltype(left) right)
    {
      std::cerr << "left: " << eevm::to_hex_string(left) << std::endl
                << "right: " << eevm::to_hex_string(right) << std::endl;
    }

#define FUZZ_ASSERT_EQ(_left, _right, msg) \
  { \
    const auto left = _left; \
    const auto right = _right; \
    if (!(left == right)) \
    { \
      std::cerr << __FILE__ << ":" << __LINE__ \
                << " assertion failed during fuzzing: " << std::string(msg) \
                << std::endl; \
      eevm::fuzz::_print_left_right(left, right); \
      abort(); \
    } \
  }
  }
}
