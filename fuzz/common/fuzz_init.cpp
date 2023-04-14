// Copyright (c) Michael Rodler. All rights reserved.
// Licensed under the MIT License.

#include "fuzz_init.hpp"

#include "eEVM/SpecializedProcessorFactory.h"
#include "eEVM/evm2cpp/contracts.h"
#include "eEVM/fuzz/addresses.hpp"
#include "eEVM/fuzz/fuzzcase.hpp"
#include "eEVM/fuzz/tracing.hpp"
#include "eEVM/opcode.h"
#include "eEVM/processor-impl.h"
#include "eEVM/processor.h"
#include "eEVM/simple/msgpacker.h"
#include "eEVM/simple/simpleglobalstate.h"
#include "fuzz_config.hpp"

#include <cstdint>
#include <ctime>
#include <fmt/format_header_only.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

// overwrite new/delete and so on
#include <mimalloc-new-delete.h>

using namespace eevm::fuzz;

void eevm::fuzz::check_properties(
  eevm::AccountState& prop_contract, eevm::Processor& prop_p)
{
  // const eevm::Address dummy_prop  = nullptr;
  // Transaction used for property checking
  eevm::Transaction tx_inv(
    choose_tx_from[0], ignore_logs, 0, TX_GAS_PRICE, TX_GAS_LIMIT);

  // Looping through the invariant property list and running the specified
  // transactions
  for (auto invariantPropertyPair : eevm::fuzz::invariant_properties)
  {
    const eevm::ExecResult e_inv = prop_p.runSpecialized<CONTRACT>(
      std::make_shared<eevm::Transaction>(tx_inv), /* dummy transaction*/
      choose_tx_from[0], /* dummy caller */
      prop_contract, /* AccounState of contract */
      invariantPropertyPair.first, /* bytes to call the invariant property */
      0, /* dummy call value */
      nullptr, /*no value */
      nullptr); /*no value */

    if (debug_print)
    {
      std::cout << "Invariant Property run "
                << eevm::to_hex_string(invariantPropertyPair.first) << " - "
                << invariantPropertyPair.second << std::endl
                << "output in String format "
                << eevm::to_hex_string(e_inv.output) << std::endl
                << fmt::format("return code: {}", (size_t)e_inv.er) << std::endl
                << "Exception: " << e_inv.exmsg << std::endl
                << "last PC: " << e_inv.last_pc << std::endl
                << "LOGs: " << keep_logs.logs.size() << std::endl;
    }
    // check the return value of the invariant property
    if (e_inv.output != PROPERTY_EXPECTED_RETURN)
    {
      fuzzer_signal_crash("Property Violation", invariantPropertyPair.second);
    }
  }
}

void eevm::fuzz::check_logs(eevm::VectorLogHandler& evm_logs)
{
  if (EVENT_TOPICS_TO_REPORT.empty())
  {
    std::cerr << "[WARNING] assertion fuzzing enabled, but got no log topics "
                 "to search for!!!"
              << std::endl;
    return;
  }

  // first some debug printing
  if (debug_print)
  {
    std::cout << "*** Checking Logs / Events *** " << std::endl;
    for (auto& log : evm_logs.logs)
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
  }

  // then the actual checking
  for (auto& log : evm_logs.logs)
  {
    if (report_on_event_in_target_only && log.address != tx_receiver)
    {
      // ignore logs from third party contracts...
      continue;
    }

    for (auto& search_topic : EVENT_TOPICS_TO_REPORT)
    {
      if (!log.topics.empty())
      {
        // the first log topic is a hash over the event signature.
        auto topic = log.topics.front();
        if (search_topic.first == topic)
        {
          std::cerr << "LOG: address = " << eevm::to_hex_string(log.address)
                    << std::endl
                    << "     name    = " << search_topic.second << std::endl
                    << "     data    = " << eevm::to_hex_string(log.data)
                    << std::endl
                    << "     topics  = ";
          for (auto topic : log.topics)
          {
            std::cerr << eevm::to_hex_string(topic) << ", ";
          }
          std::cerr << std::endl;

          string msg = fmt::format(
            "Assertion/Event: {} (with topic/hash {})",
            search_topic.second,
            eevm::to_hex_string(topic));
          fuzzer_signal_crash("Violated Assertion/Event", msg);
        }
      }
    }
  }
}

void eevm::fuzz::check_revert_output(std::vector<uint8_t>& data)
{
  if (data.size() == 0)
  {
    return;
  }
  // Solidity: Panic(uint256)
  if (data.size() == (4 + 32))
  {
    // 0x4e487b71
    const uint8_t sig[4] = {0x4e, 0x48, 0x7b, 0x71};
    if (std::memcmp(sig, data.data(), 4) == 0)
    {
      uint256_t code = eevm::from_big_endian(data.data() + 4, 32);
      uint64_t codei = static_cast<uint64_t>(code);
      std::string msg = "<unknown code>";
      switch (codei)
      {
        case 0x0:
          msg = "generic panic";
          break;
        case 0x1:
          msg = "assertion failed";
          break;
        case 0x11:
          msg = "arithmetic over/underflow";
          break;
        case 0x12:
          msg = "divide or modulo by zero";
          break;
        case 0x22:
          msg = "incorrectly encoded storage byte array";
          break;
        case 0x31:
          msg = "pop on empty array";
          break;
        case 0x32:
          msg = "out-of-bounds array access";
          break;
        case 0x41:
          msg = "allocate too much memory";
          break;
        case 0x51:
          msg = "call to zero-initialized function type";
          break;
        default:
          break;
      }

      fuzzer_signal_crash(
        "Solidity Panic", fmt::format("Solidity Panic({}): {}", codei, msg));
    }
  }
}

bool get_boolean_env_var(const char* env_var_name, const bool default_value)
{
  const char* ptr = getenv(env_var_name);
  if (ptr != nullptr)
  {
    switch (*ptr)
    {
      case '1':
      case 'y':
      case 'Y':
      case 'T':
      case 't':
        return true;
      default:
        return false;
    }
  }
  else
  {
    return default_value;
  }
}

eevm::Code read_whole_file(std::ifstream& file)
{
  // Stop eating new lines in binary mode!!!
  file.unsetf(std::ios::skipws);

  std::streampos begin, end;
  file.seekg(0, std::ios::beg);
  begin = file.tellg();
  file.seekg(0, std::ios::end);
  end = file.tellg();
  auto filesize = end - begin;
  file.seekg(0, std::ios::beg);

  eevm::Code data;
  data.reserve(filesize);
  std::copy(
    std::istream_iterator<unsigned char>(file),
    std::istream_iterator<unsigned char>(),
    std::back_inserter(data));
  return data;
}

/* apparently using the LLVMFuzzerInitialize function is discouraged (at least
 * by libfuzzer)
 * -> https://www.llvm.org/docs/LibFuzzer.html#startup-initialization
 */
// extern "C" int LLVMFuzzerInitialize(int*, char***)
/* instead we use the static initializer call trick */
bool eevm::fuzz::initialize_fuzz()
{
#define init_assert(cond, msg) \
  { \
    if (!(cond)) \
    { \
      std::cerr << __FILE__ << ":" << __LINE__ \
                << " assertion failed during init: " << std::string(msg) \
                << std::endl; \
      return false; \
    } \
  }

  // early return incase global state is already initialized
  if (state_initialized)
    return true;
  // init_assert(state_initialized == false, "state already initialized?");

  // this is disabled during fuzzing, but it makes sense when debugging a single
  // input with the binary used for fuzzing.

  // create target contract object (with mock objects) to be able to retrieve
  // contract information non-statically
  auto target_contract{CONTRACT{}};

  debug_print = get_boolean_env_var("EVM_DEBUG_PRINT", false) ||
    get_boolean_env_var("EVM_DEBUG", false) ||
    get_boolean_env_var("DEBUG_PRINT", false);
  allow_tx_from_creator = get_boolean_env_var("EVM_ALLOW_CREATOR_TX", false);
  ignore_initial_ether = get_boolean_env_var("EVM_NO_INITIAL_ETHER", false);
  ignore_leaking_ether = get_boolean_env_var("EVM_IGNORE_LEAKING", true);
  mock_calls_to_nonexistent_accounts =
    get_boolean_env_var("EVM_MOCK_EXTERNAL_CALLS", false);
  mock_calls_to_precompiles = get_boolean_env_var("EVM_MOCK_PRECOMPILES", true);

  report_on_event = get_boolean_env_var("EVM_REPORT_EVENTS", false);
  report_on_event_in_target_only =
    get_boolean_env_var("EVM_REPORT_EVENTS_ONLY_TARGET", true);
  report_on_sol_panic = get_boolean_env_var("EVM_REPORT_SOL_PANIC", false);

  if (get_boolean_env_var("EVM_MOCK_ALL_CALLS", false))
  {
    mock_calls_to_nonexistent_accounts = true;
    mock_calls_to_precompiles = true;
  }

  report_dos_selfdestruct =
    get_boolean_env_var("EVM_REPORT_DOS_SELFDESTRUCT", false);

  allow_indirect_ether_transfers =
    get_boolean_env_var("EVM_ALLOW_INDIRECT_ETHER_TRANSFERS", true);

  do_not_abort_fuzzer = get_boolean_env_var("EVM_NO_ABORT", false);
  disable_builtin_detector = get_boolean_env_var("EVM_DISABLE_DETECTOR", false);

  evm_coverage_file = getenv("EVM_COVERAGE_FILE");
  // if (evm_coverage_file != nullptr)
  //{
  //  debug_print = true;
  //}
  //
  
  use_json_state_format = get_boolean_env_var("EVM_USE_JSON_STATE_FORMAT", false);

  uint256_t constructor_callvalue = 0u;
  char* cs_constructor_callvalue = getenv("EVM_CONSTRUCTOR_CALL_VALUE");
  if (
    cs_constructor_callvalue != nullptr && cs_constructor_callvalue[0] != '\0')
  {
    std::string _cvstring(cs_constructor_callvalue);
    constructor_callvalue = eevm::to_uint256(_cvstring);
  }

  char* evm_property_file = getenv("EVM_PROPERTY_PATH");

  char* evm_log_topics = getenv("EVM_LOG_TOPICS_PATH");
  if (evm_log_topics && evm_log_topics[0] != '\0')
  {
    std::string s(evm_log_topics);
    load_additional_log_topics(s);
  }

  const char* dump_state_cstr = getenv("EVM_DUMP_STATE");
  if (dump_state_cstr != nullptr && *dump_state_cstr != '\0')
  {
    std::string s(dump_state_cstr);
    dump_state_to = s;
  }

  const char* evm_cmplog_cstr = getenv("EVM_CMP_LOG");
  if (evm_cmplog_cstr != nullptr && *evm_cmplog_cstr != '\0')
  {
    std::string s(evm_cmplog_cstr);
    dump_comparison_log = s;

    if (dump_comparison_log.size() == 0)
    {
      return false;
    }

    dump_comparison_log_fs.open(
      dump_comparison_log, std::ios::out | std::ios::binary);
  }

  const char* load_state_cstr = getenv("EVM_LOAD_STATE");
  if (load_state_cstr == nullptr)
  {
    // undocumented env flag to avoid weird behavior, when the human brain is
    // switching things around.
    load_state_cstr = getenv("EVM_STATE_LOAD");
  }

  // load global state from json if environment variable is set
  if (load_state_cstr != nullptr && *load_state_cstr != '\0')
  {
    std::string state_path(load_state_cstr);
    timespec start;
    timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    if (use_json_state_format || string_ends_with(state_path, ".json"))
    {
      std::ifstream i(load_state_cstr);
      init_assert(i.good(), "failed to open state json from provided file");

      nlohmann::json gs_json;
      i >> gs_json;

      global_state = std::make_shared<eevm::SimpleGlobalState>(
        gs_json.get<eevm::SimpleGlobalState>());
    }
    else
    {
      global_state = std::make_shared<eevm::SimpleGlobalState>();
      bool res = eevm::load_simplestate_msgpack(state_path, global_state.get());
      init_assert(res, "failed to load msgpack-formatted state");
    }
    custom_global_state_loaded = true;

    clock_gettime(CLOCK_MONOTONIC, &end);
    double duration = 0.0;
    duration += (end.tv_sec - start.tv_sec);
    duration += (end.tv_nsec - start.tv_nsec) * (1e-9);

    if (debug_print)
    {
      std::string s(load_state_cstr);
      std::cout << "loaded initial global state from file: " << s << " took "
                << duration << " seconds" << std::endl;
    }
  }
  else
  {
#define START_BLOCK_FROM_ENV(FIELD, STRING) \
  { \
    const char* s = getenv("EVM_START_BLOCK_" STRING); \
    if (s != nullptr && *s != '\0') \
    { \
      uint64_t i = std::strtoul(s, nullptr, 0); \
      start_block.FIELD = i; \
    } \
  }

    START_BLOCK_FROM_ENV(number, "NUMBER");
    START_BLOCK_FROM_ENV(timestamp, "TIMESTAMP");

    global_state = std::make_shared<eevm::SimpleGlobalState>(start_block);
  }

  const char* target_addr_cstr = getenv("EVM_TARGET_ADDRESS");
  if (target_addr_cstr != nullptr && *target_addr_cstr != '\0')
  {
    std::string address_string(target_addr_cstr);
    uint256_t address = eevm::to_uint256(address_string);
    tx_receiver = address;
  }

  const char* target_multiaddr_cstr = getenv("EVM_TARGET_MULTIPLE_ADDRESSES");
  if (target_multiaddr_cstr != nullptr && *target_multiaddr_cstr != '\0')
  {
    std::string addresses_string(target_multiaddr_cstr);
    const char sep = ',';
    std::stringstream ss(addresses_string);
    std::string address_string;
    while (std::getline(ss, address_string, sep))
    {
      uint256_t address = eevm::to_uint256(address_string);
      // avoid duplicate addresses
      if (
        std::find(tx_receivers.begin(), tx_receivers.end(), address) ==
        tx_receivers.end())
      {
        tx_receivers.push_back(address);
      }
    }
  }

  if (tx_receivers.size() == 0)
  {
    tx_receivers.push_back(tx_receiver);
  }

  if (global_state->exists(default_tx_origin))
  {
    global_state->remove(default_tx_origin);
  }
  auto attacker_origin = global_state->create(default_tx_origin, 0, {});
  attacker_origin.acc.set_mocked(false);

  if (global_state->exists(contract_creator))
  {
    global_state->remove(contract_creator);
  }
  auto cc_as = global_state->create(contract_creator, INITIAL_FUNDS, {});
  // if we allow the fuzzer to create transactions from the creator, then we
  // also allow the fuzzer to mock the return values when calling the creator
  cc_as.acc.set_mocked(allow_tx_from_creator);

  if (global_state->exists(contract_collaborator))
  {
    global_state->remove(contract_collaborator);
  }
  auto cf_as = global_state->create(
    contract_collaborator, INITIAL_FUNDS, {eevm::Opcode::STOP});
  cf_as.acc.set_mocked(false);

  // tx receiver (i.e. the contract)
  init_assert(tx_receiver != contract_creator, "repeating address");
  // contract/receiver is created later

  // tx sender (i.e. attacker or user)
  for (auto i = 0; i < NUM_SENDER; i++)
  {
    init_assert(tx_sender[i] != contract_creator, "repeating address");
    init_assert(tx_sender[i] != tx_receiver, "repeating address");

    eevm::Code code = {};
    // currently 2 of the 6 possible tx senders will have no associated code.
    // The act as EOA or contract constructor. As such they will issue
    // transactions, including reentrant calls. However, they will not directly
    // issue callbacks.
    if (i <= (NUM_SENDER / 2))
    {
      code.push_back(eevm::Opcode::STOP);
    }

    if (global_state->exists(tx_sender[i]))
    {
      global_state->remove(tx_sender[i]);
    }
    auto sender_as = global_state->create(tx_sender[i], INITIAL_FUNDS, code);
    if (code.empty())
    {
      // the attacker account is set explicitly to "not mocked", which means
      // that it cannot return any data and will simply accept any transferred
      // value. This simulates EOAs and contracts under construction.
      sender_as.acc.set_mocked(false);
    }
    else
    {
      // those attacker accounts that are not EOAs
      sender_as.acc.set_mocked(true);
      init_assert(
        global_state->get(tx_sender[i]).acc.is_mocked() == true,
        "tx_sender not marked as mocked");
    }
  }

  // Create code
  const eevm::Code code = target_contract.bytecode();
  const eevm::Code contract_constructor =
    target_contract.constructor_bytecode();

  if (debug_print)
  {
    std::cout << "= Constructing global state =" << std::endl
              << "target contract address: " << eevm::to_hex_string(tx_receiver)
              << std::endl
              << "with " << (int)NUM_SENDER
              << " attacker accounts with initial funds: "
              << eevm::to_hex_string(INITIAL_FUNDS) << std::endl;
  }

  // check if target contract already is in the global state
  bool target_contract_in_global_state = false;
  eevm::Code state_code = {};
  if (
    global_state->exists(tx_receiver) &&
    (global_state->get(tx_receiver).acc.get_code() == code))
  {
    target_contract_in_global_state = true;
  }
  else
  {
    // search for the first match
    for (const auto& acc : global_state->getAccounts())
    {
      if (acc.second.first.get_code() == code)
      {
        target_contract_in_global_state = true;
        tx_receiver = acc.second.first.get_address();
        break;
      }
    }
  }

  for (const auto& txrecv : tx_receivers)
  {
    if (!global_state->exists(txrecv))
    {
      if (tx_receivers.size() > 1)
      {
        std::cout << "WARNING: tx_receiver " << eevm::to_hex_string(txrecv)
                  << " does not exist in global state!" << std::endl;
      }
    }
    else
    {
      if (global_state->get(txrecv).acc.get_code_ref()->size() == 0)
      {
        std::cerr
          << "WARNING: tx_receiver " << eevm::to_hex_string(txrecv)
          << " account exists but code is empty! (i.e., not a smart contract?)"
          << std::endl;
      }
    }
  }

  if (
    global_state->exists(tx_receiver) &&
    (global_state->get(tx_receiver).acc.get_code_ref()->size() > 0) &&
    (global_state->get(tx_receiver).acc.get_code() != code))
  {
    auto txr_state_code = global_state->get(tx_receiver).acc.get_code_ref();
    std::cerr << "WARNING: tx_receiver " << eevm::to_hex_string(tx_receiver)
              << " exists with code of len " << txr_state_code->size()
              << " but pre-compiled code is of length " << code.size()
              << std::endl;
  }

  // skip constructor if target contract already is in the global state
  if (target_contract_in_global_state)
  {
    if (debug_print)
    {
      std::cout
        << "target contract exists in global state => skipping constructor"
        << std::endl;
    }
  }
  else
  {
    // deploy the target contract on the global state otherwise
    const char* create_tx_input = getenv("EVM_CREATE_TX_INPUT");
    const char* create_tx_args = getenv("EVM_CREATE_TX_ARGS");

    if (
      contract_constructor.size() > 0 ||
      (create_tx_input != nullptr && *create_tx_input != '\0'))
    {
      // if a constructor bytecode is defined, we first create the contract at
      // address with the constructor bytecode, run it and then set the output
      // as the new code. But before we validate that the produced runtime
      // bytecode is actually the same as the bytecode, which was specialized by
      // evm2cpp.

      eevm::Code constructor_and_args;
      if (create_tx_input != nullptr && *create_tx_input != '\0')
      {
        // if we have EVM_CREATE_TX_INPUT we override the built-in constructor
        // and the args.
        if (debug_print)
        {
          std::cout << "reading constructor_and_args from EVM_CREATE_TX_INPUT="
                    << create_tx_input << std::endl;
        }
        std::ifstream input_file(
          create_tx_input, std::ios::in | std::ios::binary);
        init_assert(
          input_file.is_open() && (!input_file.fail()),
          "failed to open EVM_CREATE_TX_INPUT file");
        constructor_and_args = read_whole_file(input_file);
        init_assert(
          constructor_and_args.size() > 0,
          "EVM_CREATE_TX_INPUT should be non-empty");
      }
      else
      {
        // if we have EVM_CREATE_TX_ARGS we keep the built-in constructor and
        // override only the args.

        constructor_and_args = contract_constructor;

        if (create_tx_args != nullptr && *create_tx_args != '\0')
        {
          if (debug_print)
          {
            std::cout << "reading constructor_and_args from EVM_CREATE_TX_ARGS="
                      << create_tx_args << std::endl;
          }
          std::ifstream input_file(
            create_tx_args, std::ios::in | std::ios::binary);
          init_assert(
            input_file.is_open() && (!input_file.fail()),
            "failed to open EVM_CREATE_TX_ARGS file");
          eevm::Code args = read_whole_file(input_file);
          if (debug_print)
          {
            std::cout << "appending args with length " << args.size()
                      << std::endl;
          }
          constructor_and_args.insert(
            constructor_and_args.end(), args.begin(), args.end());
        }
        else
        {
          // else we append also the default args
          auto a = target_contract.constructor_args();
          constructor_and_args.insert(
            constructor_and_args.end(), a.begin(), a.end());
        }
      }

      // Run a transaction to initialise this account
      if (debug_print)
      {
        std::cout << "Running constructor transaction with total input length "
                  << constructor_and_args.size()
                  << " (built-in constructor code is "
                  << target_contract.constructor_bytecode().size() << " + "
                  << target_contract.constructor_args().size() << ")"
                  << std::endl;
      }

      if (global_state->exists(tx_receiver))
      {
        std::cout
          << "WARNING: tx_receiver already exists in global state - removing"
          << std::endl;
        global_state->remove(tx_receiver);
      }
      auto contract =
        global_state->create(tx_receiver, 0, constructor_and_args);
      auto num_account = global_state->num_accounts();

      init_assert(
        global_state->exists(tx_receiver), "tx_receiver does not exist");
      init_assert(
        contract.acc.get_code().size() > 0, "tx_receiver does not have code");
      init_assert(
        global_state->get(tx_receiver).acc.get_code().size() > 0,
        "global_state/tx_receiver does not have code");

      eevm::Processor p(global_state);
      const auto exec_result = p.run(
        std::make_shared<Transaction>(contract_creator, ignore_logs),
        contract_creator,
        contract,
        {},
        constructor_callvalue,
        nullptr);

      // the constructor must always return the code - so we never expect a halt
      // with the STOP opcode here, only a return.
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

      auto result = exec_result.output;

      if (debug_print)
      {
        std::cout << "constructor finished" << std::endl
                  << "returned code of length " << result.size()
                  << " (compare to built-in code size " << code.size() << ")"
                  << std::endl;
        auto ri = result.begin();
        auto ci = code.begin();
        for (size_t i = 0; ci != code.end() && ri != result.end();
             ci++, ri++, i++)
        {
          if (*ri != *ci)
          {
            std::cout << "[ " << static_cast<int>(*ri)
                      << " != " << static_cast<int>(*ci)
                      << " ] built-in code differs from result at byte index "

                      << i << std::endl;
            break;
          }
        }
      }

      auto num_account_post = global_state->num_accounts();

      if (num_account != num_account_post && debug_print)
      {
        std::cerr << "WARNING: constructor created "
                  << (int)(num_account_post - num_account)
                  << " new accounts in global state!" << std::endl
                  << "make sure that this contract is translated to C++!"
                  << std::endl;
        dump_state(global_state.get(), "constructed");
      }

      contract.acc.set_code(std::move(result));
    }
    else
    {
      global_state->create(tx_receiver, 0, code);
    }
  }

  state_code = global_state->get(tx_receiver).acc.get_code();
  init_assert(
    (state_code.size() == code.size() && state_code == code),
    "constructor produced different code than transpiled by evm2cpp");

  // construct SpecializedProcessors
  for (int i = 0; i < eevm::SpecializedProcessorFactory::getListSize(); ++i)
    eevm::SpecializedProcessorFactory::getSpecializedProcessors().emplace_back(
      eevm::SpecializedProcessorFactory::createInstance(i));

  // assign SpecializedProcessors to contract accounts in the global state
  for (auto& acc : global_state->getAccounts())
  {
    // only consider non-sender accounts
    if (acc.second.first.get_code().size() > 1)
    {
      auto sp_found{false};

      for (const auto& sp :
           eevm::SpecializedProcessorFactory::getSpecializedProcessors())
      {
        if (sp->bytecode() == acc.second.first.get_code())
        {
          acc.second.first.set_specialized_processor(sp);
          sp_found = true;
          break;
        }
      }
      if (!sp_found)
      {
        std::string msg = fmt::format(
          "smart contract at {} without compiled cpp code - check evm2cpp!",
          eevm::to_hex_string(acc.second.first.get_address()));
        throw std::runtime_error(msg);
      }
    }
  }

  if (debug_print)
  {
    auto block = global_state->get_current_block();
    std::cout << "== GLOBAL STATE ";
    std::cout << "Block " << block.number << " timestamp " << block.timestamp
              << " ==" << std::endl;
    global_state->for_each_account([](AccountState entry) {
      auto addr = entry.acc.get_address();

      if (addr == tx_receiver)
      {
        std::cout << "  TARGET   ";
      }
      else if (
        std::find(tx_receivers.begin(), tx_receivers.end(), addr) !=
        tx_receivers.end())
      {
        std::cout << "  TARGET2  ";
      }
      else if (addr == contract_creator)
      {
        std::cout << "  CREATOR  ";
      }
      else if (addr == contract_collaborator)
      {
        std::cout << "  FRIEND   ";
      }
      else
      {
        bool found = false;
        for (auto x : tx_sender)
        {
          if (addr == x)
          {
            found = true;
            std::cout << "  ATTACKER ";
            break;
          }
        }
        if (!found)
        {
          std::cout << "           ";
        }
      }
      std::cout << "address: " << eevm::to_hex_string(addr)
                << " balance: " << eevm::to_hex_string(entry.acc.get_balance())
                << " code length: " << entry.acc.get_code_ref()->size()
                << " specialized: "
                << (entry.acc.get_specialized_processor() != nullptr)
                << " is_mocked: " << entry.acc.is_mocked() << std::endl;
    });
    std::cout << std::endl;
    if (tx_receivers.size() > 1)
    {
      std::cout << "TX receivers = ";
      for (size_t i = 0; i < tx_receivers.size(); ++i)
      {
        std::cout << "[" << i << "] = " << eevm::to_hex_string(tx_receivers[i])
                  << "; ";
      }
      std::cout << std::endl;
    }
  }

  init_assert(
    global_state->get(tx_sender[0]).acc.is_mocked() == true,
    "tx_sender not marked as mocked");
  init_assert(
    global_state->get(contract_collaborator).acc.is_mocked() == false,
    "contract_collaborator marked as mocked");

  dump_state(global_state.get(), "init");

  // check if the a file is provided for property checking and if so load the
  // file and check all defined properties
  if (evm_property_file != nullptr && *evm_property_file != '\0')
  {
    if (debug_print)
      std::cout << "Invariants are loaded from " << evm_property_file
                << std::endl;
    // load the properties into vector
    load_invariant_properties(evm_property_file);
    // init proccessor and get account state to be able to pass them to the
    // check property function which relies on these to be able to run the
    // invariant transacitons
    eevm::Processor p(global_state);
    eevm::AccountState contract = global_state->get(tx_receiver);
    check_properties(contract, p);
  }

  if (debug_print && report_on_event)
  {
    std::cout << "Looking for the following Events while fuzzing:" << std::endl;

    for (auto& event : EVENT_TOPICS_TO_REPORT)
    {
      std::cout << "    " << event.second << " with hash/topic[0] "
                << eevm::to_hex_string(event.first) << std::endl;
    }
  }

  state_initialized = true;
  return true;

#undef init_assert
}

bool eevm::fuzz::save_coverage(const eevm::Trace& trace, const Address contract)
{
  // TODO: Is there a good standard format to record coverage for evm/solidity? 

  if (evm_coverage_file == nullptr)
  {
    return false;
  }

  std::fstream fs(
    evm_coverage_file,
    std::fstream::out | std::fstream::ate | std::fstream::app);

  if (!fs.is_open())
  {
    return false;
  }

  for (auto events = trace.events.begin(); events != trace.events.end();
       events++)
  {
    auto event = &*events;
    if (event->address == contract)
    {
      fs << "0x" << std::hex << event->pc << std::endl;
    }
  }

  fs.close();
  return true;
}

bool eevm::fuzz::dump_comparion_ops_to_file(
  const eevm::Trace& trace, std::ofstream& fs)
{
  if (!fs.is_open())
  {
    return false;
  }

  for (auto events = trace.events.begin(); events != trace.events.end();
       events++)
  {
    auto event = &*events;

    switch (event->op)
    {
      case eevm::Opcode::EQ:
      case eevm::Opcode::GT:
      case eevm::Opcode::SGT:
      case eevm::Opcode::LT:
      case eevm::Opcode::SLT: {
        uint8_t arg0_buf[32] = {
          0,
        };
        uint8_t arg1_buf[32] = {
          0,
        };
        eevm::to_big_endian(event->s->peek(0), arg0_buf);
        eevm::to_big_endian(event->s->peek(1), arg1_buf);
        fs.write((const char*)&event->pc, sizeof(event->pc));
        fs << static_cast<uint8_t>(event->op);
        fs.write((char*)&arg0_buf[0], 32).write((char*)&arg1_buf[0], 32);
        break;
      }

      case eevm::Opcode::RETURN: {
        // fs.write((const char*)&event->pc, sizeof(event->pc));
        // fs << static_cast<uint8_t>(event->op);
        break;
      }

      default:;
        // do nothing
    }
  }

  fs.close();

  return true;
}

void eevm::fuzz::dump_compare(
  const uint64_t pc,
  const eevm::Opcode opcode,
  const uint256_t& a,
  const uint256_t& b)
{
  if (!dump_comparison_log_fs.is_open())
  {
    return;
  }
  switch (opcode)
  {
    case eevm::Opcode::EQ:
    case eevm::Opcode::GT:
    case eevm::Opcode::SGT:
    case eevm::Opcode::LT:
    case eevm::Opcode::SLT: {
      uint8_t arg0_buf[32] = {
        0,
      };
      uint8_t arg1_buf[32] = {
        0,
      };
      eevm::to_big_endian(a, arg0_buf);
      eevm::to_big_endian(b, arg1_buf);
      dump_comparison_log_fs.write((const char*)&pc, sizeof(pc));
      dump_comparison_log_fs << static_cast<uint8_t>(opcode);
      dump_comparison_log_fs.write((char*)&arg0_buf[0], 32)
        .write((char*)&arg1_buf[0], 32);
      break;
    }
    default:;
      // do nothing
  }
}

void eevm::fuzz::dump_return(
  const uint64_t pc, const eevm::Opcode opcode, const eevm::Context* ctxt)
{
  if (!dump_comparison_log_fs.is_open())
  {
    return;
  }
  switch (opcode)
  {
    case eevm::Opcode::RETURN: {
      // write 8 byte pc
      dump_comparison_log_fs.write((const char*)&pc, sizeof(pc));
      // write 1 byte opcode
      dump_comparison_log_fs << static_cast<uint8_t>(opcode);

      if (ctxt->input.size() >= 4)
      {
        dump_comparison_log_fs.write((const char*)ctxt->input.data(), 4);
      }
      else
      {
        uint32_t sig = 0;
        dump_comparison_log_fs.write((const char*)&sig, sizeof(sig));
      }

      uint16_t length = ctxt->return_data.size();
      dump_comparison_log_fs.write((const char*)&length, sizeof(length));
      dump_comparison_log_fs.write(
        (const char*)ctxt->return_data.data(), length);
      break;
    }
      // TODO: handle revert too? -> likely useless
    case eevm::Opcode::REVERT:
    default:;
      // do nothing
  }
}

void eevm::fuzz::dump_state_json(
  eevm::SimpleGlobalState* gs, const std::string& postfix)
{
  if (dump_state_to.size() != 0)
  {
    nlohmann::json gs_json = *gs;

    std::string fname = fmt::format("{}.{}.json", dump_state_to, postfix);
    std::ofstream state_file(fname);
    if (state_file.is_open() && (!state_file.fail()))
    {
      state_file << gs_json << std::endl;
      state_file.close();
    }
    else
    {
      std::cerr << "failed to open EVM_DUMP_STATE file " << fname << std::endl;
    }
  }
}

void eevm::fuzz::dump_state(
  eevm::SimpleGlobalState* gs, const std::string& postfix)
{
  if (eevm::fuzz::use_json_state_format)
  {
    return dump_state_json(gs, postfix);
  }
  else
  {
    if (dump_state_to.size() != 0)
    {
      std::string fname = fmt::format("{}.{}.msgpack", dump_state_to, postfix);
      eevm::dump_simplestate_msgpack(gs, fname);
    }
  }
}
