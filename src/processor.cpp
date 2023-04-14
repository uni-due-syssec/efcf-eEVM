// Copyright (c) Microsoft Corporation. All rights reserved.
// Copyright (c) Michael Rodler. All rights reserved.
// Licensed under the MIT License.

#include "eEVM/processor.h"

#include "eEVM/bigint.h"
#include "eEVM/exception.h"
#include "eEVM/opcode.h"
#include "eEVM/processor-impl.h"
#include "eEVM/stack.h"
#include "eEVM/util.h"

#include <algorithm>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <type_traits>
#include <utility>

#define PRECOMPILES_LAST_ADDR 18

#ifdef ENABLE_FUZZING
#  include "eEVM/fuzz/addresses.hpp"
#  include "fuzz_init.hpp"
#endif

using namespace std;

namespace eevm
{
  void ProcessorImplementation::dispatch()
  {
    const auto op = get_op();
    if (tr) [[unlikely]] // TODO: remove if from critical path
      tr->add(
        ctxt->get_pc(), op, get_call_depth(), ctxt->acc.get_address(), ctxt->s);

    switch (op)
    {
      case Opcode::PUSH1:
      case Opcode::PUSH2:
      case Opcode::PUSH3:
      case Opcode::PUSH4:
      case Opcode::PUSH5:
      case Opcode::PUSH6:
      case Opcode::PUSH7:
      case Opcode::PUSH8:
      case Opcode::PUSH9:
      case Opcode::PUSH10:
      case Opcode::PUSH11:
      case Opcode::PUSH12:
      case Opcode::PUSH13:
      case Opcode::PUSH14:
      case Opcode::PUSH15:
      case Opcode::PUSH16:
      case Opcode::PUSH17:
      case Opcode::PUSH18:
      case Opcode::PUSH19:
      case Opcode::PUSH20:
      case Opcode::PUSH21:
      case Opcode::PUSH22:
      case Opcode::PUSH23:
      case Opcode::PUSH24:
      case Opcode::PUSH25:
      case Opcode::PUSH26:
      case Opcode::PUSH27:
      case Opcode::PUSH28:
      case Opcode::PUSH29:
      case Opcode::PUSH30:
      case Opcode::PUSH31:
      case Opcode::PUSH32:
        push();
        break;
      case Opcode::POP:
        pop();
        break;
      case Opcode::SWAP1:
      case Opcode::SWAP2:
      case Opcode::SWAP3:
      case Opcode::SWAP4:
      case Opcode::SWAP5:
      case Opcode::SWAP6:
      case Opcode::SWAP7:
      case Opcode::SWAP8:
      case Opcode::SWAP9:
      case Opcode::SWAP10:
      case Opcode::SWAP11:
      case Opcode::SWAP12:
      case Opcode::SWAP13:
      case Opcode::SWAP14:
      case Opcode::SWAP15:
      case Opcode::SWAP16:
        swap();
        break;
      case Opcode::DUP1:
      case Opcode::DUP2:
      case Opcode::DUP3:
      case Opcode::DUP4:
      case Opcode::DUP5:
      case Opcode::DUP6:
      case Opcode::DUP7:
      case Opcode::DUP8:
      case Opcode::DUP9:
      case Opcode::DUP10:
      case Opcode::DUP11:
      case Opcode::DUP12:
      case Opcode::DUP13:
      case Opcode::DUP14:
      case Opcode::DUP15:
      case Opcode::DUP16:
        dup();
        break;
      case Opcode::LOG0:
      case Opcode::LOG1:
      case Opcode::LOG2:
      case Opcode::LOG3:
      case Opcode::LOG4:
        log();
        break;
      case Opcode::ADD:
        add();
        break;
      case Opcode::MUL:
        mul();
        break;
      case Opcode::SUB:
        sub();
        break;
      case Opcode::DIV:
        div();
        break;
      case Opcode::SDIV:
        sdiv();
        break;
      case Opcode::MOD:
        mod();
        break;
      case Opcode::SMOD:
        smod();
        break;
      case Opcode::ADDMOD:
        addmod();
        break;
      case Opcode::MULMOD:
        mulmod();
        break;
      case Opcode::EXP:
        exp();
        break;
      case Opcode::SIGNEXTEND:
        signextend();
        break;
      case Opcode::LT:
        lt();
        break;
      case Opcode::GT:
        gt();
        break;
      case Opcode::SLT:
        slt();
        break;
      case Opcode::SGT:
        sgt();
        break;
      case Opcode::EQ:
        eq();
        break;
      case Opcode::ISZERO:
        isZero();
        break;
      case Opcode::AND:
        and_();
        break;
      case Opcode::OR:
        or_();
        break;
      case Opcode::XOR:
        xor_();
        break;
      case Opcode::NOT:
        not_();
        break;
      case Opcode::BYTE:
        byte();
        break;
      case Opcode::JUMP:
        jump();
        break;
      case Opcode::JUMPI:
        jumpi();
        break;
      case Opcode::PC:
        pc();
        break;
      case Opcode::MSIZE:
        msize();
        break;
      case Opcode::MLOAD:
        mload();
        break;
      case Opcode::MSTORE:
        mstore();
        break;
      case Opcode::MSTORE8:
        mstore8();
        break;
      case Opcode::CODESIZE:
        codesize();
        break;
      case Opcode::CODECOPY:
        codecopy();
        break;
      case Opcode::EXTCODESIZE:
        extcodesize();
        break;
      case Opcode::EXTCODECOPY:
        extcodecopy();
        break;
      case Opcode::SLOAD:
        sload();
        break;
      case Opcode::SSTORE:
        sstore();
        break;
      case Opcode::ADDRESS:
        address();
        break;
      case Opcode::BALANCE:
        balance();
        break;
      case Opcode::SELFBALANCE:
        selfbalance();
        break;
      case Opcode::ORIGIN:
        origin();
        break;
      case Opcode::CALLER:
        caller();
        break;
      case Opcode::CALLVALUE:
        callvalue();
        break;
      case Opcode::CALLDATALOAD:
        calldataload();
        break;
      case Opcode::CALLDATASIZE:
        calldatasize();
        break;
      case Opcode::CALLDATACOPY:
        calldatacopy();
        break;
      case Opcode::RETURN:
        return_();
        break;
      case Opcode::REVERT:
        revert();
        break;
      case Opcode::SELFDESTRUCT:
        selfdestruct();
        break;
      case Opcode::CREATE:
        create();
        break;
      case Opcode::STATICCALL:
      case Opcode::CALL:
      case Opcode::CALLCODE:
      case Opcode::DELEGATECALL:
        call();
        break;
      case Opcode::JUMPDEST:
        jumpdest();
        break;
      case Opcode::BLOCKHASH:
        blockhash();
        break;
      case Opcode::NUMBER:
        number();
        break;
      case Opcode::GASPRICE:
        gasprice();
        break;
      case Opcode::COINBASE:
        coinbase();
        break;
      case Opcode::TIMESTAMP:
        timestamp();
        break;
      case Opcode::DIFFICULTY:
        difficulty();
        break;
      case Opcode::GASLIMIT:
        gaslimit();
        break;
      case Opcode::CHAINID:
        chainid();
        break;
      case Opcode::GAS:
        gas();
        break;
      case Opcode::SHA3:
        sha3();
        break;
      case Opcode::STOP:
        stop();
        break;
      case Opcode::RETURNDATASIZE:
        returndatasize();
        break;
      case Opcode::RETURNDATACOPY:
        returndatacopy();
        break;
      case Opcode::SHR:
        shr();
        break;
      case Opcode::SHL:
        shl();
        break;
      case Opcode::SAR:
        sar();
        break;
      default:
        stringstream err;
        err << fmt::format(
                 "Unknown/unsupported Opcode: 0x{:02x}", int{get_op()})
            << endl;
        err << fmt::format(
                 " in contract {}",
                 to_checksum_address(ctxt->as.acc.get_address()))
            << endl;
        err << fmt::format(" called by {}", to_checksum_address(ctxt->caller))
            << endl;
        err << fmt::format(
                 " at position {}, call-depth {}",
                 ctxt->get_pc(),
                 get_call_depth())
            << endl;
        throw Exception(Exception::Type::illegalInstruction, err.str());
    };
  }

  Processor::Processor(std::shared_ptr<eevm::SimpleGlobalState> t_gs)
  {
    gs = t_gs;
  }

  ExecResult Processor::runSpecializedDyn(
    std::shared_ptr<Transaction> tx,
    const Address& caller,
    AccountState callee,
    const std::vector<uint8_t>& input,
    const uint256_t& call_value,
    Trace* tr,
    fuzz::FuzzCaseParser* fp)
  {
    SpecializedProcessor* spptr = static_cast<SpecializedProcessor*>(
      callee.acc.get_specialized_processor());
    if (spptr == nullptr)
    {
      ExecResult result;
      result.last_pc = 0;
      result.output = {};
      if (callee.acc.has_code())
      {
        result.ex = Exception::Type::notImplemented;
        result.er = eevm::ExitReason::threw;
      }
      else
      {
        result.er = eevm::ExitReason::halted;
      }
      return result;
    }
    auto p = spptr->duplicate();
    p->prepare(gs, tx, tr);
    p->setFuzzCaseParser(fp);
    return p->run(caller, callee, input, call_value);
  }

  ExecResult Processor::run(
    std::shared_ptr<Transaction> tx,
    const Address& caller,
    AccountState callee,
    const vector<uint8_t>& input,
    const uint256_t& call_value,
    Trace* tr)
  {
    return ProcessorImplementation(gs, tx, tr)
      .run(caller, callee, input, call_value);
  }

  // NOTE: due to a bug the _addr and gaslimit parameters are switched in the
  // do_call method when comparing to the actual EVM opcode parameter ordering
  // on the evm stack... well ¯\_(ツ)_/¯
  uint256_t SpecializedProcessor::do_call(
    const Opcode op,
    const uint256_t _addr,
    const uint256_t gaslimit,
    const uint256_t value,
    const uint256_t offIn,
    const uint256_t sizeIn,
    const uint256_t offOut,
    const uint256_t sizeOut)
  {
    //#define REENTRANCY_DEBUG_PRINTS 1

    if (ctxt->stop_exec_now)
    {
      // avoid doing calls when the flag is set to stop immediately.
      return 0;
    }

    if (get_call_depth() >= Consts::MAX_CALL_DEPTH)
    {
      ctxt->stop_exec_now = true;
      ctxt->error = std::make_unique<Exception>(
        ET::callStackExhausted,
        "Callstack exhausted! (attempt to call with callstack == " +
          to_string(Consts::MAX_CALL_DEPTH) + ")");
      ctxt->return_value = 0;
      ctxt->return_data = {};
      return 0;
    }

    // when a call happens, we reset the previously stored returndata/value. We
    // set them to sane defaults (i.e., failure code and no returndata).
    ctxt->return_value = 0;
    ctxt->return_data.clear();

    const auto addr = to_addr(_addr);

#ifdef REENTRANCY_DEBUG_PRINTS
#  define PRINT_CALLSTACK() \
    { \
      std::cerr << "\t[ call stack: ]" << std::endl; \
      for (size_t i = 0; i < ctxts->size(); i++) \
      { \
        std::cerr << "\t [" << i << "] => " \
                  << eevm::to_hex_string((*ctxts)[i]->acc.get_address()) \
                  << " [specialized " \
                  << ((*ctxts)[i]->acc.get_specialized_processor() != nullptr) \
                  << "; code size " << (*ctxts)[i]->prog.code->size() \
                  << "; static " << (*ctxts)[i]->static_flag << "]" \
                  << std::endl; \
      } \
    }
    std::cerr << "[CALL HANDLER] " << eevm::Disassembler::getOp(op) << " ("
              << "gaslimit: " << eevm::to_hex_string(gaslimit)
              << ", value: " << eevm::to_hex_string(value)
              << ", addr: " << eevm::to_hex_string(addr)
              << ", calldepth: " << ctxts->size() << ")" << std::endl;
    PRINT_CALLSTACK();
#endif

    if (value != 0 && ctxt->static_flag && op != Opcode::CALLCODE)
    {
      ctxt->stop_exec_now = true;
      ctxt->error = std::make_unique<Exception>(
        ET::staticViolation, "Call with callvalue > 0 during STATICCALL.");
      return 0;
    }

    if (addr >= 1 && addr <= PRECOMPILES_LAST_ADDR)
    {
      // identity precompile - no reason not to do it like that, no?
      if (addr == 4) [[unlikely]]
      {
        prepare_mem_access(
          static_cast<uint64_t>(offIn), static_cast<uint64_t>(sizeIn));
        auto input = copy_from_mem(
          static_cast<uint64_t>(offIn), static_cast<uint64_t>(sizeIn));
        ctxt->return_data = input;
        ctxt->return_value = 1;
        // we handle the call return value according to the cur_ret mock values.
        copy_mem_raw(
          static_cast<uint64_t>(offOut),
          0,
          static_cast<uint64_t>(sizeOut),
          ctxt->mem,
          input);
        return 1;
      }

#ifdef ENABLE_FUZZING
      if (!eevm::fuzz::mock_calls_to_precompiles) [[likely]]
      {
        throw Exception(
          ET::notImplemented,
          "Precompiled contracts/native extensions are not implemented.");
      }
#else
      // TODO: implement native extensions
      throw Exception(
        ET::notImplemented,
        "Precompiled contracts/native extensions are not implemented.");
#endif
    }

    auto r = check_on_call(addr, value, op);
    if (r != 1)
    {
      return r;
    }

    // get the accountstate for the given address, creates a new account if it
    // didn't exist before.
    decltype(auto) callee = gs->get(addr);

#ifdef REENTRANCY_DEBUG_PRINTS
    std::cerr << "[CALL HANDLER] "
              << "attemtping transfer of " << value << " wei from address "
              << to_hex_string(ctxt->acc.get_address()) << " to address "
              << to_hex_string(addr)
              << " from current call depth = " << ctxts->size()
              << "; gaslimit = " << to_hex_string(gaslimit)
              << "; into specialized = "
              << (gs->get(_addr).acc.get_specialized_processor() != nullptr)
              << std::endl;

    PRINT_CALLSTACK()

#endif

    // if the callee has no code and is not mocked, we simply succeed!
    if (callee.acc.get_code_ref()->empty() && (!callee.acc.is_mocked()))
    {
#ifdef REENTRANCY_DEBUG_PRINTS
      std::cerr << "[CALL HANDLER] call to EOA - returning 1" << std::endl;
#endif
      // transfer the ether to the callee
      if (ctxt->acc.pay_to_noexcept(callee.acc, value))
      {
        return 1;
      }
      else
      {
        ctxt->stop_exec_now = true;
        ctxt->error = std::make_unique<Exception>(
          Exception::Type::outOfFunds,
          "Insufficient funds to pay " + to_hex_string(value) +
            " during call attempt.");
        return 0;
      }
    }

    // call is mocked if no specialized processor is found for the account or if
    // it is somehow overridden.
    if (callee.acc.is_mocked())
    {
      // in Ethereum there is this particularity that even if there is no code,
      // the whole thing could be run as part of a constructor call. Then there
      // is no code in the blockchain, but the account still executes code.
      // However, callbacks simply treat the contract as an account without
      // code, so there are no reentrant executions. In typical blockchain state
      // configuration this should not happen, but in case it does we print a
      // warning, s.t., this behavior doesn't go unnoticed.
#ifdef REENTRANCY_DEBUG_PRINTS
      if (callee.acc.get_code_ref()->empty())
      {
        std::cerr << "[CALL HANDLER] potentially executing impossible callback."
                  << std::endl;
      }
#endif

      if (fuzzcase_parser == nullptr)
      {
        throw Exception(
          ET::notImplemented,
          "Specialized Executor cannot call mocked contracts (outside of "
          "Fuzzing)!");
      }

      auto cur_tx = fuzzcase_parser->getCurrentTx();

      if (!cur_tx->hasReturns())
      {
        // we do not have another "return data" provided by the fuzzer. So we
        // can't really mock out the call. Instead we pretend the call fails.
#ifdef REENTRANCY_DEBUG_PRINTS
        std::cerr << "[CALL HANDLER] return now - no return mocks" << std::endl;
        PRINT_CALLSTACK();
#endif
        return 0;
      }
      auto cur_ret = cur_tx->getNextReturn();
      if (cur_ret == nullptr)
      {
#ifdef REENTRANCY_DEBUG_PRINTS
        std::cerr
          << "[CALL HANDLER] return now - no remaining data for return mocks"
          << std::endl;
        PRINT_CALLSTACK();
#endif
        return 0;
      }

      if (op != Opcode::DELEGATECALL && op != Opcode::STATICCALL && value != 0)
      {
        // all other calls can transfer value, no?
        // ctxt->acc.pay_to(callee.acc, value);
        const bool r = ctxt->acc.pay_to_noexcept(callee.acc, value);
        if (!r)
        {
          ctxt->stop_exec_now = true;
          ctxt->error = std::make_unique<Exception>(
            Exception::Type::outOfFunds,
            "Insufficient funds to pay " + to_hex_string(value) +
              " during reentrant call attempt.");
          return 0;
        }
      }

      // these are saved
      AccountState& caller_account_state = ctxt->as;
      auto current_addr = ctxt->acc.get_address();
      auto current_code = ctxt->acc.get_code_ref();

#ifdef REENTRANCY_DEBUG_PRINTS
      std::cerr << "[CALL HANDLER] "
                << "call to contract with mock return data available!"
                << std::endl
                << "current call depth = " << ctxts->size() << std::endl;
#endif

      // we return data on CALL and STATICCALL - we do not consider other call
      // instructions, for mocking return values, as DELEGATECALL or CALLCODE
      // can do much more by accessing and modifying the storage state of the
      // caller.
      if (op == Opcode::CALL || op == Opcode::STATICCALL)
      {
#ifdef REENTRANCY_DEBUG_PRINTS
        std::cerr << "[CALL HANDLER] "
                  << "call/staticcall with reenter: "
                  << (static_cast<uint64_t>(cur_ret->header.reenter))
                  << " gaslimit: " << to_hex_string(gaslimit) << std::endl;
#endif
        // TODO: we might want to check whether we have enough gas for
        // actually doing a reentrant call (i.e., solidity's .call() vs.
        // .transfer()) and probably we need to check whether we can actually
        // perform multiple re-entrant calls?
        //
        // OK. So the whole gas stipend thingy is quite complex. However, the
        // footnote here:
        // https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/
        // sheds some light on how it is done:
        //
        // Solidity’s transfer() needs to ensure that there is always exactly
        // 2300 gas passed to the callee.
        //
        // 2300 is the "gas stipend";
        // if 0 wei are transferred
        //    Solidity adds the gas stipend to the explicit gas parameter
        // if more than 0 wei are transferred
        //    The EVM implicitly adds the gas stipend to the amount of gas
        //
        // In order to avoid false alarms we need to handle this accordingly
        // here. Since eEVM does not implement gas tracking, we only use very
        // basic check on the gas to detect the use of solidity's transfer().
        //
        // In reality we would need to do more sophisticated gas tracking and
        // computation. We would need to check whether the provided gas is high
        // enough to perform all the necessary EVM steps for the reentrant call.
        // However, this seems to be a bit of a hassle and not doing it could
        // actually reveal some interesting cases.

        bool gas_allows_reentrancy = true;
        if (value == 0)
        {
          gas_allows_reentrancy = (gaslimit > CALL_GAS_STIPEND);
        }
        else
        {
          // gas_allows_reentrancy = ((gaslimit + CALL_GAS_STIPEND) >
          // CALL_GAS_STIPEND);
          gas_allows_reentrancy = gaslimit > 0;
        }

        // TODO: I think that it does not make sense to perform
        // reentrant calls while the STATIC flag of the EVM is set. We cannot do
        // any modifications anyway. In theory we can reenter, but we cannot
        // cause inconsistent state or anything, because there are no state
        // updates. For now, let's still allow this.
        if (
          /*op == Opcode::CALL && !ctxt->static_flag && */
          cur_ret->header.reenter > 0 && cur_ret->header.value > 0 &&
          gas_allows_reentrancy && addr > PRECOMPILES_LAST_ADDR && addr > 0)
        {
          // first we push the a new context for the normal call
          {
            // empty handlers? not sure whether we need them.
            auto rh = [](const vector<uint8_t>& output) {};
            auto hh = []() {};
            auto he = [](const Exception&) {};

#ifdef REENTRANCY_DEBUG_PRINTS
            std::cerr << "[CALL HANDLER] "
                      << "pushing mock context at call depth = "
                      << ctxts->size() << " address = "
                      << eevm::to_hex_string(callee.acc.get_address())
                      << std::endl;
#endif
            push_context(
              current_addr,
              callee,
              {}, /* the input is ignored anyway, so we pass empty */
              callee.acc.get_code_ref(),
              value,
              rh,
              hh,
              he,
              (ctxt->static_flag || op == Opcode::STATICCALL));
            // ctxt member now points to a new context!!!
          }

          // so now we have pushed the context of the external call. However,
          // we will not really perform the call. Instead we will ask the
          // fuzzer (1) whether we should reenter the contract under test and
          // (2) mock out the return value of the call.

          size_t reenter_counter = cur_ret->header.reenter;
          fuzz::FuzzTransaction* next_tx = nullptr;
          if (reenter_counter > 0)
          {
            next_tx = fuzzcase_parser->getNextTx();
          }

          while (reenter_counter != 0 && next_tx != nullptr)
          {
#ifdef REENTRANCY_DEBUG_PRINTS
            std::cerr << "[CALL HANDLER] "
                      << "trying reentering! call depth = " << ctxts->size()
                      << " current address "
                      << to_hex_string(ctxt->acc.get_address()) << std::endl;
            PRINT_CALLSTACK();
#endif

            size_t receivers_bound = eevm::fuzz::tx_receivers.size();
            size_t tx_to_idx = 0;
            eevm::Address tx_to = eevm::fuzz::tx_receiver;
            if (receivers_bound > 1)
            {
              tx_to_idx = (next_tx->header.receiver_select % receivers_bound);
              tx_to = eevm::fuzz::tx_receivers[tx_to_idx];
            }
            auto to_account_state = gs->get(tx_to);

            SpecializedProcessor* spp = static_cast<SpecializedProcessor*>(
              to_account_state.acc.get_specialized_processor());

            if (spp == nullptr)
            {
              std::cerr
                << "[WARNING] attempting to call contract without specialized "
                   "constructor; likely a configuration error!"
                << std::endl;

              ctxt->stop_exec_now = true;
              ctxt->error = std::make_unique<Exception>(
                ET::notImplemented,
                "Attempt to call contract without specialized executor");
              break;
            }

            auto t_sp = spp->duplicate();

            bool exception_occured = false;
            auto rh = [](const vector<uint8_t>& output) {};
            auto hh = []() {};
            auto he = [&exception_occured](const Exception&) {
              exception_occured = true;
            };

            eevm::Code re_input = next_tx->data;
            auto re_call_value = next_tx->getCallValue();
            auto re_sender = next_tx->getSender();
            auto re_sender_acc = gs->get(re_sender);
            if (!re_sender_acc.acc.pay_to_noexcept(
                  caller_account_state.acc, re_call_value))
            {
              // not enough funds to perform the reentrant call.
              ctxt->stop_exec_now = true;
              ctxt->error = std::make_unique<Exception>(
                Exception::Type::outOfFunds,
                "Insufficient funds to pay " + to_hex_string(re_call_value) +
                  " during reentrant call attempt.");
              break;
            }

#ifdef REENTRANCY_DEBUG_PRINTS
            std::cerr << "[CALL HANDLER] "
                      << "pushing target contract context call depth = "
                      << ctxts->size() << " address = "
                      << eevm::to_hex_string(to_account_state.acc.get_address())
                      << std::endl;
#endif
            push_context(
              re_sender,
              to_account_state,
              move(re_input),
              to_account_state.acc.get_code_ref(),
              re_call_value,
              rh,
              hh,
              he,
              (ctxt->static_flag || op == Opcode::STATICCALL));
            // ctxt member now points to a new context!!!

            std::shared_ptr<eevm::SimpleGlobalState> snap_gs =
              make_shared<eevm::SimpleGlobalState>(*gs);

#ifdef REENTRANCY_DEBUG_PRINTS
            std::cerr << "[CALL HANDLER] "
                      << "executing specialized executor at call depth = "
                      << ctxts->size() << " current address "
                      << to_hex_string(ctxt->acc.get_address())
                      << " current caller " << to_hex_string(ctxt->caller)
                      << std::endl;
            PRINT_CALLSTACK();
#endif

            t_sp->prepareNested(gs, tx, tr, ctxts);
            t_sp->setFuzzCaseParser(fuzzcase_parser);

            try
            {
              // run the code
              t_sp->dispatch();

              // t_sp->unprepare();

#ifdef REENTRANCY_DEBUG_PRINTS
              std::cerr << "[CALL HANDLER] dispatch done retval: "
                        << ctxt->return_value << std::endl;
              PRINT_CALLSTACK();
#endif
            }
            catch (eevm::Exception& ex)
            {
              // t_sp->unprepare();
#ifdef REENTRANCY_DEBUG_PRINTS
              std::cerr << "[CALL HANDLER] "
                        << "exception during re-entrant call: \"" << ex.what()
                        << "\" at call depth " << ctxts->size()
                        << " with last pc " << ctxt->get_pc() << std::endl;
              PRINT_CALLSTACK()
#endif
              pop_context();
              pop_context();

              if (snap_gs)
              {
                gs.swap(snap_gs);
                /*snap_gs.reset();*/
                snap_gs = nullptr;
              }

              throw;
            }

            if (ctxt && ctxt->stop_exec_now && ctxt->error)
            {
              auto err = std::move(ctxt->error);

#ifdef REENTRANCY_DEBUG_PRINTS
              std::cerr << "[CALL HANDLER] recoverable error detected "
                        << err->what() << " - popping 2 context" << std::endl;
              PRINT_CALLSTACK();
#endif
              pop_context();
              pop_context();

#ifdef REENTRANCY_DEBUG_PRINTS
              std::cerr << "[CALL HANDLER] remaining call stack:" << std::endl;
              PRINT_CALLSTACK();
#endif
              // restore state from snapshot
              if (snap_gs)
              {
                gs.swap(snap_gs);
                /*snap_gs.reset();*/
                snap_gs = nullptr;
              }

              if (ctxt)
              {
                ctxt->error = std::move(err);
                ctxt->stop_exec_now = true;
              }
              ctxt->return_value = 0;
              return 0;
            }

            if (exception_occured)
            {
              // TODO: I don't think this should ever happen. The specialized
              // contracts should always set ctxt->error on exceptions (or at
              // least throw the exception).
#ifdef REENTRANCY_DEBUG_PRINTS
              std::cerr << "[CALL HANDLER] noticed unknown exception during "
                           "execution; restoring snapshot: "
                           "call depth = "
                        << ctxts->size() << " address = "
                        << eevm::to_hex_string(ctxt->acc.get_address())
                        << std::endl;
#endif
              // restore state from snapshot
              if (snap_gs)
              {
                gs.swap(snap_gs);
                /*snap_gs.reset();*/
                snap_gs = nullptr;
              }
            }

#ifdef REENTRANCY_DEBUG_PRINTS
            std::cerr << "[CALL HANDLER] popping target contract context at "
                         "call depth = "
                      << ctxts->size() << " address = "
                      << eevm::to_hex_string(ctxt->acc.get_address())
                      << std::endl;
            PRINT_CALLSTACK();
#endif

            pop_context();

            // we need to remove all reentrant transactions, s.t., the next call
            // to getCurrentTx() again returns the very same TX.
            fuzzcase_parser->popTransaction();

            // next iteration
            --reenter_counter;
            // only get the next TX if we are also going to execute it.
            // if reenter_counter == 0 then the next loop iteration will not
            // happen and we do not need the next transaction
            if (reenter_counter != 0)
            {
              next_tx = fuzzcase_parser->getNextTx();
            }
            else
            {
              next_tx = nullptr;
              break;
            }
          }

#ifdef REENTRANCY_DEBUG_PRINTS
          std::cerr
            << "[CALL HANDLER] popping mock-callee context call depth = "
            << ctxts->size()
            << " address = " << eevm::to_hex_string(ctxt->acc.get_address())
            << std::endl;

          PRINT_CALLSTACK();
#endif
          // pop the fake caller context.
          pop_context();
        }
        else
        {
#ifdef REENTRANCY_DEBUG_PRINTS
          std::cerr << "[CALL HANDLER] **not** reentering at call depth = "
                    << ctxts->size() << std::endl;
#endif
        }

        if (ctxt == nullptr)
        {
          throw std::runtime_error("No context available after return!");
        }

        // Normally this should always be true, and it seems to be. But because
        // I do not really trust this code a lot, I put this check here to
        // verify this condition.
        if (ctxt->acc.get_address() != current_addr)
        {
          std::cerr << "[INTERNAL ERROR] Invalid address after call/return "
                       "mock! current context address: "
                    << eevm::to_hex_string(ctxt->acc.get_address())
                    << " (expected " << eevm::to_hex_string(current_addr) << ")"
                    << std::endl;
#ifdef REENTRANCY_DEBUG_PRINTS
          PRINT_CALLSTACK();
#endif
          throw std::runtime_error("Invalid address after call/return mock!");
        }

        ctxt->return_data = cur_ret->data;
        ctxt->return_value = cur_ret->header.value;
        // we handle the call return value according to the cur_ret mock values.
        copy_mem_raw(
          static_cast<uint64_t>(offOut),
          0, /* src offset, i.e., source is cur_ret->data */
          static_cast<uint64_t>(sizeOut),
          ctxt->mem,
          cur_ret->data);

#ifdef REENTRANCY_DEBUG_PRINTS
        std::cerr << "[CALL HANDLER] returned from call with value = "
                  << static_cast<uint64_t>(cur_ret->header.value)
                  << " at call depth = " << ctxts->size() << std::endl;
        PRINT_CALLSTACK();
#endif

        return cur_ret->header.value;
      }

      ctxt->return_value = 0;
      ctxt->return_data.clear();
      return 0;
    }
    else if (callee.acc.get_specialized_processor() != nullptr)
    {
      // throws exception in case of not enough funds
      if (op != Opcode::DELEGATECALL && op != Opcode::STATICCALL && value != 0)
      {
        // all other calls can transfer value, no?
        if (!ctxt->acc.pay_to_noexcept(callee.acc, value))
        {
          ctxt->stop_exec_now = true;
          ctxt->error = std::make_unique<Exception>(
            Exception::Type::outOfFunds,
            "Insufficient funds to pay " + to_hex_string(value) +
              " during reentrant call attempt.");
          ctxt->return_value = 0;
          ctxt->return_data.clear();
          return 0;
        }
      }

      // a specialized processor was found, so the call is executed
      prepare_mem_access(
        static_cast<uint64_t>(offIn), static_cast<uint64_t>(sizeIn));
      auto input = copy_from_mem(
        static_cast<uint64_t>(offIn), static_cast<uint64_t>(sizeIn));

      auto parentContext = ctxt;
      eevm::ExecResult result;

      auto rh =
        [offOut, sizeOut, parentContext](const vector<uint8_t>& output) {
          parentContext->return_value = 1;
          parentContext->return_data = output;
          copy_mem_raw(
            static_cast<uint64_t>(offOut),
            0,
            static_cast<uint64_t>(sizeOut),
            parentContext->mem,
            output);
        };
      auto hh = [parentContext]() { parentContext->return_value = 1; };
      auto eh = [parentContext](const Exception&) {
        parentContext->return_value = 0;
      };

      switch (op)
      {
        case Opcode::STATICCALL:
          push_context(
            ctxt->acc.get_address(),
            callee,
            move(input),
            callee.acc.get_code_ref(),
            0,
            rh,
            hh,
            eh,
            true /* set static flag */);
          break;
        case Opcode::CALL:
          push_context(
            ctxt->acc.get_address(),
            callee,
            move(input),
            callee.acc.get_code_ref(),
            value,
            rh,
            hh,
            eh,
            ctxt->static_flag);
          break;

        case Opcode::CALLCODE:
          push_context(
            ctxt->acc.get_address(),
            ctxt->as,
            move(input),
            callee.acc.get_code_ref(),
            value,
            rh,
            hh,
            eh,
            ctxt->static_flag);
          break;

        case Opcode::DELEGATECALL:
          push_context(
            ctxt->caller,
            ctxt->as,
            move(input),
            callee.acc.get_code_ref(),
            ctxt->call_value,
            rh,
            hh,
            eh,
            ctxt->static_flag);
          break;

        default:
          throw UnexpectedState("Unknown call opcode.");
      }

#ifdef REENTRANCY_DEBUG_PRINTS
      std::cerr << "[CALL HANDLER] "
                << "performing call with native handler (at call depth: "
                << ctxts->size() << " opcode: " << eevm::Disassembler::getOp(op)
                << ")" << std::endl;
      PRINT_CALLSTACK();
#endif

      std::shared_ptr<eevm::SimpleGlobalState> snap_gs =
        make_shared<eevm::SimpleGlobalState>(*gs);

      // run with specialized processor
      auto spp = static_cast<SpecializedProcessor*>(
        callee.acc.get_specialized_processor());
      auto t_sp = spp->duplicate();
      t_sp->prepareNested(gs, tx, tr, ctxts);
      t_sp->setFuzzCaseParser(fuzzcase_parser);
      try
      {
        // run the target contract
        t_sp->dispatch();

        // t_sp->unprepare();
      }
      catch (eevm::Exception& e)
      {
        t_sp->unprepare();
        pop_context();

        // restore state from snapshot
        if (snap_gs)
        {
          gs.swap(snap_gs);
          /*snap_gs.reset();*/
          snap_gs = nullptr;
        }

        // refers to parent context already
        ctxt->return_value = 0;
        // ctxt->return_data.clear();
        throw;
        return 0;
      }

      if (ctxt->stop_exec_now && ctxt->error)
      {
        auto err = std::move(ctxt->error);
        pop_context();
        if (ctxt)
        {
          ctxt->error = std::move(err);
          ctxt->stop_exec_now = true;
        }

        // restore state from snapshot
        if (snap_gs)
        {
          gs.swap(snap_gs);
          /*snap_gs.reset();*/
          snap_gs = nullptr;
        }
        ctxt->return_value = 0;
        // ctxt->return_data.clear();
        return 0;
      }

      pop_context();

#ifdef REENTRANCY_DEBUG_PRINTS
      std::cerr << "[CALL HANDLER] "
                << "returned from execution with native handler "
                << "back at current call depth = " << ctxts->size()
                << " return value = " << ctxt->return_value << std::endl;
      PRINT_CALLSTACK();
#endif

      ctxt->return_value = 1;
      // ctxt->return_data.clear();
      return 1;
    }

#ifdef REENTRANCY_DEBUG_PRINTS
    std::cerr << "[CALL HANDLER] not mocked, no specialized executor, not an "
                 "EOA - return 0"
              << std::endl;
#endif

    ctxt->return_value = 0;
    return 0;
  }

} // namespace eevm
