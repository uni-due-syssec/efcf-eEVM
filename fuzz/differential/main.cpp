// Copyright (c) Microsoft Corporation. All rights reserved.
// Copyright (c) Michael Rodler. All rights reserved.
// Licensed under the MIT License.

#include "eEVM/evm2cpp/contracts.h"
#include "eEVM/evm2cpp/contracts/crowdsale.h"
#include "eEVM/evm2cpp/contracts/simpledao.h"
#include "eEVM/opcode.h"
#include "eEVM/processor.h"
#include "eEVM/simple/simpleglobalstate.h"
#include "fuzz_init.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <fmt/format_header_only.h>
#include <fstream>
#include <iostream>

using namespace eevm::fuzz;

/*************************************************************************/

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  static bool state_initialized = initialize_fuzz();
  if (!state_initialized)
  {
    std::cerr << "Wat? State was not properly initialized!" << std::endl;
    return 1;
  }

  DBG(std::cout << "running fuzzcase" << std::endl);

  FuzzedDataProvider fuzzed_data(data, size);

  auto sender = fuzzed_data.PickValueInArray(choose_tx_from);

  // choose call value
  uint256_t call_value = fuzzed_data.ConsumeIntegral<uint64_t>();
  call_value <<= 32;

  // tx input bytes
  const std::vector<uint8_t> input_bytes =
    fuzzed_data.ConsumeRemainingBytes<uint8_t>();

  eevm::Transaction tx(sender, ignore_logs);

  DBG(std::cout << "Running bytecode interpreter" << std::endl);
  auto gs_interp(global_state);
  eevm::AccountState contract = gs_interp.get(tx_receiver);
  eevm::Processor p_interp(gs_interp);
  const eevm::ExecResult e_interp = p_interp.run(
    tx, /* transaction*/
    sender, /* caller */
    contract, /* AccounState of contract */
    input_bytes, /* input as bytes */
    call_value /* call value */);

  DBG(std::cout << "Running specialized code" << std::endl);
  auto gs_special(global_state);
  eevm::AccountState contract_special = gs_special.get(tx_receiver);
  eevm::Processor p_special(gs_special);
  const eevm::ExecResult e_special = p_special.runSpecialized<CONTRACT>(
    tx, /* transaction*/
    sender, /* caller */
    contract_special, /* AccounState of contract */
    input_bytes, /* input as bytes */
    call_value /* call value */);

  if (debug_print)
  {
    std::cout << "EVM execution done" << std::endl
              << std::endl
              << "sender: " << eevm::to_hex_string(sender) << std::endl
              << "call_value: " << eevm::to_hex_string(call_value) << std::endl
              << "input: " << eevm::to_hex_string(input_bytes) << std::endl
              << std::endl
              << "states are equal? " << (gs_special == gs_interp) << std::endl
              << "Interpreter " << e_interp << std::endl
              << "Specialized " << e_special << std::endl;
  }

  // we check if something is wrong/unexpected
  if (
    e_interp.er != e_special.er || e_interp.ex != e_special.ex ||
    e_interp.output != e_special.output) // || gs_special != gs_interp)
  {
    eevm::Trace itr;
    eevm::Trace str;
    {
      auto gsnew(global_state);
      auto contract = gsnew.get(tx_receiver);
      eevm::Processor p(gsnew);
      auto r = p.run(tx, sender, contract, input_bytes, call_value, &itr);
      FUZZ_ASSERT_EQ(
        r.er,
        e_interp.er,
        "different execution result on second run of interpreter");
      FUZZ_ASSERT_EQ(
        r.ex,
        e_interp.ex,
        "different exception type on second run of interpreter");
      FUZZ_ASSERT_EQ(
        r.output,
        e_interp.output,
        "different output on second run of interpreter");
    }

    {
      auto gsnew(global_state);
      eevm::Processor p(gsnew);
      auto contract = gsnew.get(tx_receiver);
      auto r = p.runSpecialized<CONTRACT>(
        tx, sender, contract, input_bytes, call_value, &str);

      FUZZ_ASSERT_EQ(
        r.er,
        e_special.er,
        "different execution result on second run of specialized");
      FUZZ_ASSERT_EQ(
        r.ex,
        e_special.ex,
        "different exception type on second run of specialized");
      FUZZ_ASSERT_EQ(
        r.output,
        e_special.output,
        "different output on second run of specialized");
    }

    auto itr_i = itr.events.begin();
    auto itr_i_end = itr.events.end();
    auto itr_s = str.events.begin();
    auto itr_s_end = str.events.end();
    bool last_printed = false;

    while (itr_s != itr_s_end && itr_i != itr_i_end)
    {
      auto event_i = &*itr_i;
      auto event_s = &*itr_s;

      while (event_i->pc != event_s->pc && itr_i != itr_i_end)
      {
        itr_i++;
        event_i = &*itr_i;
      }

      if (event_i->pc == event_s->pc)
      {
        std::cout << fmt::format(
                       "=====================\nIntepreter:\n{}\n---------------"
                       "-\nSpecialized\n{}\n",
                       *event_i,
                       *event_s)
                  << std::endl;
        itr_i++;
        itr_s++;
      }
      else
      {
        std::cout << "Execution diverted at interpreter " << event_i->pc
                  << " specialized " << event_s->pc << std::endl;

        std::cout << "========== Last Trace Entries =========" << std::endl
                  << "Intepreter:" << std::endl;
        itr.print_last_n(std::cout, 5);
        std::cout << "---------------------------------------" << std::endl
                  << "Specialized:" << std::endl;
        str.print_last_n(std::cout, 3);
        last_printed = true;
        break;
      }
    }

    if (!last_printed)
    {
      std::cout << "========== Last Trace Entries =========" << std::endl
                << "Intepreter:" << std::endl;
      itr.print_last_n(std::cout, 5);
    }

    // finally signal the fuzzer
    FUZZ_ASSERT_EQ(e_interp.er, e_special.er, "different execution result");
    FUZZ_ASSERT_EQ(e_interp.ex, e_special.ex, "different exception type");
    FUZZ_ASSERT_EQ(e_interp.output, e_special.output, "different output");
    // something else?
    abort();
  }

  return 0;
}
