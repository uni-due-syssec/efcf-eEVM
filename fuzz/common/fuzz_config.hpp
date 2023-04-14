#pragma once

#include "eEVM/bigint.h"
#include "eEVM/block.h"

namespace eevm
{
  namespace fuzz
  {
    const uint64_t TX_GAS_LIMIT = 0x1500000;
    const uint64_t TX_GAS_PRICE = 100;

    using namespace intx;
    constexpr uint256_t INITIAL_FUNDS = 1_u256 << 192;

    inline bool debug_print = false;
    inline bool state_initialized = false;
    inline bool allow_tx_from_creator = false;
    inline bool allow_indirect_ether_transfers = true;
    inline bool ignore_initial_ether = false;
    inline bool ignore_leaking_ether = true;
    inline bool disable_builtin_detector = false;
    inline bool do_not_abort_fuzzer = false;
    inline bool mock_calls_to_precompiles = true;
    inline bool mock_calls_to_nonexistent_accounts = false;
    inline bool report_dos_selfdestruct = false;
    inline bool report_on_event = false;
    inline bool report_on_event_in_target_only = true;
    inline bool report_on_sol_panic = false;

    inline bool use_json_state_format = false;

    inline eevm::Block start_block = {
      100000, // number
      8050151966801941, // difficulty (taken arbitrarily from block 13000000)
      30000000, // gas_limit
      1420066800, // timestamp 2015-01-01 00:00:00
      0x421337 // coinbase ¯\_(ツ)_/¯
    };
  }
}
