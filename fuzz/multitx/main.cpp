// Copyright (c) Michael Rodler. All rights reserved.
// Licensed under the MIT License.

#include "eEVM/evm2cpp/contracts.h"
#include "eEVM/fuzz/EthFuzzDataProvider.hpp"
#include "eEVM/fuzz/fuzzcase.hpp"
#include "eEVM/opcode.h"
#include "eEVM/processor-impl.h"
#include "eEVM/processor.h"
#include "eEVM/util.h"
#include "fuzz_init.hpp"

#include <cctype>
#include <chrono>
#include <eEVM/debug.h>
#include <filesystem>
#include <fmt/format_header_only.h>
#include <fstream>
#include <iostream>
#include <thread>

using namespace eevm::fuzz;

void check_balances(
  std::shared_ptr<eevm::SimpleGlobalState> gs,
  bool enforce_abort,
  uint256_t contract_initial)
{
  if (eevm::fuzz::disable_builtin_detector) [[unlikely]]
  {
    return;
  }

  if (debug_print) [[unlikely]]
  {
    {
      auto state = gs->get(tx_receiver);
      auto balance = state.acc.get_balance();
      std::cout << "contract: " << eevm::to_hex_string(tx_receiver) << std::endl
                << "balance = " << eevm::to_hex_string(balance) << std::endl
                << "more than initial balance? "
                << ((balance > contract_initial) ? "yes" : "no") << std::endl;
    }
    {
      auto state = gs->get(contract_creator);
      auto balance = state.acc.get_balance();
      std::cout << "contract creator: " << eevm::to_hex_string(contract_creator)
                << std::endl
                << "balance = " << eevm::to_hex_string(balance) << std::endl
                << "more than initial balance? "
                << ((balance > INITIAL_FUNDS) ? "yes" : "no") << std::endl;
    }
  }

  bool do_abort = false;

  uint256_t expected_max = 0;
  uint256_t total_balance = 0;
  for (const auto sender : tx_sender)
  {
    DBG(
      std::cout << "checking balance of " << eevm::to_hex_string(sender)
                << std::endl);
    auto state = gs->get(sender);
    auto balance = state.acc.get_balance();
    DBG(std::cout << "= " << eevm::to_hex_string(balance) << std::endl);
    if (balance > INITIAL_FUNDS)
    {
      std::cerr << "account " << eevm::to_hex_string(sender) << " has balance "
                << eevm::to_hex_string(state.acc.get_balance()) << "( > "
                << eevm::to_hex_string(INITIAL_FUNDS) << ")" << std::endl;
      dump_state(gs.get(), "bug");

      // fuzzer signal
      if (enforce_abort && (!allow_indirect_ether_transfers))
      {
        do_abort = true;
      }
    }

    expected_max += INITIAL_FUNDS;
    total_balance += balance;
  }

  if (total_balance > expected_max)
  {
    std::cerr << "combined balance of fuzzer accounts is " << total_balance
              << " but expected a maximum of " << expected_max << std::endl;
    dump_state(gs.get(), "bug");

    // fuzzer signal
    if (enforce_abort)
    {
      do_abort = true;
    }
  }

  if (do_abort)
  {
    fuzzer_signal_crash(
      "balance gain",
      fmt::format(
        "{} wei (compare total {} > {} wei expected)",
        total_balance - expected_max,
        total_balance,
        expected_max));
  }
}
/*************************************************************************/

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  static bool state_initialized = initialize_fuzz();
  if (!state_initialized)
  {
    std::cerr << "Wat? State was not properly initialized!" << std::endl;
    abort();
  }

  keep_logs.logs.clear();

  const auto MOD_SENDER_SELECT =
    (NUM_SENDER + (eevm::fuzz::allow_tx_from_creator ? 1 : 0));

  eevm::fuzz::FuzzCaseParser fuzzed_data(data, size);

  DBG(std::cout << "running fuzzcase" << std::endl);

  DBG(std::cout << "Block Header" << std::endl);
  const FuzzBlockHeader* block_header = fuzzed_data.getBlockHeader();

  // create a copy of current block (the start block)
  eevm::Block evm_block = global_state->get_current_block();
  evm_block.difficulty = block_header->difficulty;
  evm_block.gas_limit = block_header->gas_limit;
  // we perform saturating adds for block number and timestamp
  // realistically they can never reach those values, but we support it
  uint64_t x = evm_block.number + block_header->number;
  if (x < evm_block.number)
  {
    evm_block.number = UINT64_MAX;
  }
  else
  {
    evm_block.number = x;
  }
  x = evm_block.timestamp + block_header->timestamp;
  if (x < evm_block.timestamp)
  {
    evm_block.timestamp = UINT64_MAX;
  }
  else
  {
    evm_block.timestamp = x;
  }

  // evm_block.coinbase = eevm::from_big_endian(block_header->coinbase, 32);
  uint256_t initial_ether_balance = block_header->getInitialEther();

  // Create copy global state and new processor
  uint256_t contract_initial_balance = 0;

  // TODO: use the backing store mechanism to enable faster copy-construction
  std::shared_ptr<eevm::SimpleGlobalState> gs =
    std::make_shared<eevm::SimpleGlobalState>(
      global_state.get(), std::move(evm_block), true);

  if (!ignore_initial_ether)
  {
    eevm::AccountState contract_state = gs->get(tx_receiver);
    auto pre_balance = contract_state.acc.get_balance();
    contract_state.acc.set_balance(pre_balance + initial_ether_balance);
    if (debug_print) [[unlikely]]
    {
      std::cout << "setting initial balance from " << pre_balance << " to "
                << contract_state.acc.get_balance() << std::endl;
    }
    contract_initial_balance = contract_state.acc.get_balance();
  }

  eevm::Processor p{gs};

  size_t bound_tx_receivers = tx_receivers.size();

  // p.setFuzzCaseParser(&fuzzed_data);

  eevm::Trace tr;

  size_t tx_idx = 0;
  bool no_further_tx_processing = false;

  for (auto txdata = fuzzed_data.getNextTx();
       txdata != nullptr && (!no_further_tx_processing);
       tx_idx++, txdata = fuzzed_data.getNextTx())
  {
    size_t tx_to_idx = 0;
    eevm::Address tx_to = tx_receiver;
    if (bound_tx_receivers > 1)
    {
      tx_to_idx = txdata->header.receiver_select % bound_tx_receivers;
      tx_to = tx_receivers[tx_to_idx];
    }

    std::shared_ptr<eevm::SimpleGlobalState> snap_gs =
      make_shared<eevm::SimpleGlobalState>(*gs);

    eevm::AccountState contract = gs->get(tx_to);

    DBG(
      std::cout << std::endl
                << "-- TRANSACTION " << static_cast<unsigned>(tx_idx)
                << " --\n");

    FuzzTransactionHeader* tx_header = &txdata->header;

    // advance the block number and timestamp.
    eevm::Block b = gs->get_current_block();
    auto ba = tx_header->block_advance;
    auto new_bn = b.number + ba;
    // we do saturating adds here s.t., we uphold the blockchain invariants
    b.number = new_bn > b.number ? new_bn : b.number;
    // realistically we have about 30 seconds until the next block; However, we
    // want to cover more cases during fuzzing; so we allow the fuzzer to
    // advance the timestamp both by several minutes and also by several weeks
    // (128 weeks)
    auto new_ts =
      b.timestamp + ((ba < 128) ? (ba * 60) : ((ba - 127) * 604800));
    b.timestamp = new_ts > b.timestamp ? new_ts : b.timestamp;

    gs->set_current_block(b);

    // randomly choose a sender for the transaction
    const eevm::Address sender =
      choose_tx_from[(tx_header->sender_select % MOD_SENDER_SELECT)];

    eevm::LogHandler* log_handler = &ignore_logs;
    if (debug_print || report_on_event) [[unlikely]]
    {
      log_handler = &keep_logs;
    }

    uint256_t call_value = txdata->getCallValue();

    auto sender_account = gs->get(sender);
    if (call_value > 0)
    {
      auto sender_balance = sender_account.acc.get_balance();

      // max out funds of sender if needed
      call_value = (call_value > sender_balance ? sender_balance : call_value);

      // transfer the funds
      if (!sender_account.acc.pay_to_noexcept(contract.acc, call_value))
      {
        DBG(
          std::cout << "Error: Insufficient funds to pay " +
            eevm::to_hex_string(call_value) + " to " +
            eevm::to_hex_string(contract.acc.get_address()) + " (from " +
            eevm::to_hex_string(sender_account.acc.get_address()) +
            ", current balance " +
            eevm::to_hex_string(sender_account.acc.get_balance()) +
            ")" << std::endl);
        break;
      }
    }

    auto origin = sender;
    if (sender_account.acc.get_code_ref()->size() > 0)
    {
      // origin = tx_sender[NUM_SENDER - 1];
      origin = default_tx_origin;
    }

    auto tx = std::make_shared<eevm::Transaction>(
      origin, *log_handler, call_value, TX_GAS_PRICE, TX_GAS_LIMIT);

    // tx input bytes
    std::vector<uint8_t>* input_bytes = &txdata->data;
    DBG(
      std::cout << "found input with length: " << input_bytes->size()
                << std::endl);

    eevm::Trace* trptr = nullptr;
    if (debug_print) [[unlikely]]
    {
      std::vector<uint8_t> fourbyte;
      std::copy(
        input_bytes->begin(),
        input_bytes->begin() + (input_bytes->size() < 4 ? 0 : 4),
        std::back_inserter(fourbyte));
      std::cout << "Running Transaction " << tx_idx << std::endl
                << "input bytes: " << eevm::to_hex_string(*input_bytes)
                << std::endl
                << "4byte sig: " << eevm::to_hex_string(fourbyte) << std::endl
                << "call value: " << eevm::to_hex_string(call_value)
                << std::endl
                << "from: " << eevm::to_hex_string(sender) << std::endl
                << "to: " << eevm::to_hex_string(tx_to) << std::endl
                << "block num: " << gs->get_current_block().number << std::endl
                << "block ts: " << gs->get_current_block().timestamp
                << std::endl;

      // enable tracing only when debug_print is also active
    }

    if (debug_print || evm_coverage_file) [[unlikely]]
    {
      trptr = &tr;
    }

    eevm::ExecResult e;
    try
    {
#ifdef FUZZ_WITH_INTERPRETER
      // run code from target contract
      e = p.run(
        tx, /* transaction*/
        sender, /* caller */
        contract, /* AccounState of contract */
        *input_bytes, /* input as bytes */
        call_value, /* call value */
        trptr);
#else

      if (tx_to_idx == 0)
      {
        // run code from target contract
        e = p.runSpecialized<CONTRACT>(
          tx, /* transaction*/
          sender, /* caller */
          contract, /* AccounState of contract */
          *input_bytes, /* input as bytes */
          call_value, /* call value */
          trptr,
          &fuzzed_data);
      }
      else
      {
        e = p.runSpecializedDyn(
          tx, /* transaction*/
          sender, /* caller */
          contract, /* AccounState of contract */
          *input_bytes, /* input as bytes */
          call_value, /* call value */
          trptr,
          &fuzzed_data);
      }

#endif
    }
    catch (eevm::Exception& ex)
    {
      e.exmsg = ex.what();
      e.ex = ex.type;
      e.er = eevm::ExitReason::threw;
    }

    if (debug_print) [[unlikely]]
    {
      std::cout << "== EVM TX Done ==" << std::endl
                << fmt::format("return code: {}", (size_t)e.er) << std::endl
                << "Exception: " << e.exmsg << std::endl
                << "last PC: " << e.last_pc << std::endl
                << "LOGs: " << keep_logs.logs.size() << std::endl;
      for (auto log : keep_logs.logs)
      {
        std::cout << "LOG: address = " << eevm::to_hex_string(log.address)
                  << std::endl
                  << "     data    = " << eevm::to_hex_string(log.data)
                  << std::endl
                  << "     topics  = ";
        for (auto topic : log.topics)
        {
          std::cout << eevm::to_hex_string(topic) << ", ";
        }
        std::cout << std::endl;
      }
      std::cout << std::endl;
      tr.print_last_n(std::cout, 7);
      std::cout << std::endl;
    }

    if (evm_coverage_file) [[unlikely]]
    {
      save_coverage(tr, tx_receiver);
    }

    if (report_on_sol_panic && e.ex == eevm::Exception::Type::reverted)
    {
      check_revert_output(e.output);
    }

    if (!(e.er == eevm::ExitReason::returned ||
          e.er == eevm::ExitReason::halted))
    {
      if (
        e.er == eevm::ExitReason::threw &&
        e.ex == eevm::Exception::Type::notImplemented)
      {
        std::cerr << "Fuzzer triggered unimplemented behavior! " << std::endl
                  << e.exmsg << std::endl;
        std::chrono::seconds dur(30);
        std::this_thread::sleep_for(dur);
        return 0;
      }

      if (debug_print && e.ex == eevm::Exception::Type::reverted) [[unlikely]]
      {
        std::cout << "revert() output = ";
        if (e.output.size() > 0)
        {
          std::cout << eevm::to_hex_string(e.output) << std::endl;
          std::cout << "\tascii: '";
          for (auto c : e.output)
          {
            if (isprint(c))
            {
              std::cout << c;
            }
            else
            {
              std::cout << fmt::format("\\x{:02x}", c);
            }
          }
          std::cout << "'" << std::endl;
        }
        else
        {
          std::cout << " <None>" << std::endl;
        }
      }

      // we need to restore the state after an exception.
      if (snap_gs)
      {
        gs.swap(snap_gs);
        // snap_gs.reset();
        snap_gs = nullptr;
      }

      // we break after the first revert() - we would need to reset the state
      // of the contract to before the call, which we don't do. So we just
      // don't execute further transactions. This should guide the fuzzer to
      // supplying valid transactions only.
      break;
    }

    // Create string from response data, and print it
    if (e.output.size() > 0 && e.output.data() != nullptr)
    {
      // const std::string response(reinterpret_cast<const
      // char*>(e.output.data()));
      DBG(
        std::cout << "output: " << eevm::to_hex_string(e.output) << std::endl);
    }
    else
    {
      DBG(std::cout << "no response" << std::endl);
    }

    for (const auto& destructed : tx->selfdestruct_list)
    {
      if (destructed.first == tx_receiver)
      {
        // we stop processing transactions here. Future transactions would
        // simply fail.
        no_further_tx_processing = true;
        if (eevm::fuzz::disable_builtin_detector) [[unlikely]]
        {
          break;
        }

#ifdef ENABLE_DETECTOR
        for (const auto attacker_sender : tx_sender)
        {
          if (destructed.second == attacker_sender)
          {
            dump_state(gs.get(), "bug");

            DBG(
              std::cout << std::endl
                        << "[STATS] top-level transaction count: "
                        << static_cast<unsigned>(tx_idx) << std::endl
                        << "[STATS] all transaction count: "
                        << fuzzed_data.getStatsTxCount() << std::endl
                        << "[STATS] all mocked returns: "
                        << fuzzed_data.getStatsReturnCount() << std::endl);

            // signal to fuzzer
            fuzzer_signal_crash(
              "controlled selfdestruct",
              fmt::format(
                "selfdestruct to attacker {}",
                eevm::to_hex_string(attacker_sender)));
          }
        }

        if (eevm::fuzz::report_dos_selfdestruct)
        {
          // signal to fuzzer
          fuzzer_signal_crash(
            "selfdestruct DoS",
            fmt::format(
              "selfdestruct to address {}",
              eevm::to_hex_string(destructed.second)))
        }

#endif

        break;
      }
    }
    if (debug_print) [[unlikely]]
    {
#ifdef ENABLE_DETECTOR
      check_balances(gs, false, contract_initial_balance);
#endif
    }

    eevm::fuzz::check_properties(contract, p);

    if (report_on_event)
    {
      eevm::fuzz::check_logs(keep_logs);
    }
  }

  if (report_on_event)
  {
    eevm::fuzz::check_logs(keep_logs);
  }

  DBG(
    std::cout << std::endl
              << "[STATS] top-level transaction count: "
              << static_cast<unsigned>(tx_idx) << std::endl
              << "[STATS] all transaction count: "
              << fuzzed_data.getStatsTxCount() << std::endl
              << "[STATS] all mocked returns: "
              << fuzzed_data.getStatsReturnCount() << std::endl);

  // don't check if we haven't executed anything...
  if (tx_idx > 0) [[likely]]
  {
    DBG(
      std::cout << std::endl
                << "[DONE] all transactions executed" << std::endl);

#ifdef ENABLE_DETECTOR
    check_balances(gs, true, contract_initial_balance);
#endif
  }

  // if (dump_comparison_log_fs.is_open() > 0) [[unlikely]]
  //{
  //   dump_comparion_ops_to_file(tr, dump_comparison_log_fs);
  // }

  dump_state(gs.get(), "end");

  return 0;
}
