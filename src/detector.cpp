#include "eEVM/disassembler.h"
#include "eEVM/processor-impl.h"

#ifdef ENABLE_FUZZING
#  include "fuzz_init.hpp"

#  include <fmt/format_header_only.h>

#  define ENV_DETECTOR_DISABLED (eevm::fuzz::disable_builtin_detector)
#else
#  define ENV_DETECTOR_DISABLED (false)
#endif

using namespace eevm;

uint64_t eevm::ProcessorImplementation::check_on_call(
  Address addr, uint256_t value, Opcode op)
{
#ifdef ENABLE_DETECTOR
  // normally if an accounts does not exist yet, then it is created in
  // ethereum. However, while fuzzing this is not something that is useful,
  // as the fuzzer might trigger create of many new contracts. Instead we
  // will first check, whether this looks like a buggy condition.
  //
  // if it is not we will still signal an error to the fuzzer. hopefully
  // this guides the fuzzer to re-using existing addresses.
  if (!gs->exists(addr))
  {
    if ((!ENV_DETECTOR_DISABLED) && addr > 0)
    {
      if (value > 0)
      {
        std::cerr
          << "Contract leaks ether to potentially controllable address: "
          << to_hex_string(addr) << std::endl;
#  ifdef ENABLE_FUZZING
        if (!eevm::fuzz::ignore_leaking_ether)
        {
          auto sgs = reinterpret_cast<SimpleGlobalState*>(gs.get());
          eevm::fuzz::dump_state(sgs, "bug");
          fuzzer_signal_crash(
            "leaking ether",
            fmt::format(
              "call with value {} to address {}",
              to_hex_string(value),
              to_hex_string(addr)));
        }
#  else
        abort();
#  endif
      }
      else
      {
        return 1;
      }
    }

    // std::cerr << "warning: calling unknown address " << to_hex_string(addr)
    //          << std::endl;

#  ifdef ENABLE_FUZZING
    if (eevm::fuzz::mock_calls_to_nonexistent_accounts)
    {
      // set the contract to be mocked
      gs->get(addr).acc.set_mocked(true);
      return 1;
    }
#  else
    // otherwise we signal an error to the executing smart contract
    return 0;
#  endif
  }
#endif

  if (
    (op == DELEGATECALL || op == CALLCODE) && (!ENV_DETECTOR_DISABLED) &&
    addr > 0)
  {
#ifdef ENABLE_FUZZING
    for (const auto attacker_sender : eevm::fuzz::tx_sender)
    {
      if (addr == attacker_sender)
      {
        // signal to fuzzer
        auto sgs = reinterpret_cast<SimpleGlobalState*>(gs.get());
        eevm::fuzz::dump_state(sgs, "bug");
        fuzzer_signal_crash(
          "controlled delegatecall",
          fmt::format(
            "{} to attacker address {}",
            Disassembler::getOp(op).mnemonic,
            to_hex_string(addr)));
      }
    }
#endif

    if (!gs->exists(addr))
    {
#ifdef ENABLE_FUZZING
      auto sgs = reinterpret_cast<SimpleGlobalState*>(gs.get());
      eevm::fuzz::dump_state(sgs, "bug");
      fuzzer_signal_crash(
        "controlled delegatecall",
        fmt::format(
          "{} to unknown address {}",
          Disassembler::getOp(op).mnemonic,
          to_hex_string(addr)));
#else
      abort();
#endif
    }
  }

  return 1;
}
