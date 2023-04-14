// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "account.h"
#include "address.h"
#include "bigint.h"
#include "eEVM/bigint.h"
#include "eEVM/exception.h"
#include "eEVM/fuzz/fuzzcase.hpp"
#include "eEVM/opcode.h"
#include "eEVM/processor.h"
#include "eEVM/simple/simpleglobalstate.h"
#include "eEVM/stack.h"
#include "eEVM/util.h"
#include "globalstate.h"
#include "intx/include/intx/intx.hpp"
#include "simple/simpleglobalstate.h"
#include "trace.h"
#include "transaction.h"

#include <cstdint>
#include <functional>
#include <set>
#include <type_traits>
#include <utility>
#include <vector>

namespace eevm
{

  enum class ExitReason : uint8_t
  {
    returned = 0,
    halted,
    threw
  };

  std::ostream& operator<<(std::ostream& out, const ExitReason value);

  struct ExecResult
  {
    ExitReason er = {};
    Exception::Type ex = {};
    std::string exmsg = {};
    std::vector<uint8_t> output = {};
    uint64_t last_pc = 0;
  };

  std::ostream& operator<<(std::ostream& out, const ExecResult& value);

  /**
   * Ethereum bytecode processor.
   */
  class Processor
  {
  private:
    std::shared_ptr<eevm::SimpleGlobalState> gs;

  public:
    Processor(std::shared_ptr<eevm::SimpleGlobalState> t_gs);
    /**
     * @brief The main entry point for the EVM.
     *
     * Runs the callee's code in the caller's context. VM exceptions (ie,
     * eevm::Exception) will be caught and returned in the result.
     *
     * @param tx the transaction
     * @param caller the caller's address
     * @param callee the callee's account state
     * @param input the raw byte input
     * @param call_value the call value
     * @param tr [optional] a pointer to a trace object. If given, a trace of
     * the execution will be collected.
     * @return ExecResult the execution result
     */
    ExecResult run(
      std::shared_ptr<Transaction> tx,
      const Address& caller,
      AccountState callee,
      const std::vector<uint8_t>& input,
      const uint256_t& call_value,
      Trace* tr = nullptr);

    template <typename SP>
    ExecResult runSpecialized(
      std::shared_ptr<Transaction> tx,
      const Address& caller,
      AccountState callee,
      const std::vector<uint8_t>& input,
      const uint256_t& call_value,
      Trace* tr = nullptr,
      fuzz::FuzzCaseParser* fp = nullptr)
    {
      auto p = SP(gs, tx, tr);
      p.setFuzzCaseParser(fp);
      return p.run(caller, callee, input, call_value);
    }

    ExecResult runSpecializedDyn(
      std::shared_ptr<Transaction> tx,
      const Address& caller,
      AccountState callee,
      const std::vector<uint8_t>& input,
      const uint256_t& call_value,
      Trace* tr = nullptr,
      fuzz::FuzzCaseParser* fp = nullptr);
  };

  struct Consts
  {
    static constexpr auto MAX_CALL_DEPTH = 1024u;
    static constexpr auto WORD_SIZE = 32u;
    static constexpr auto MAX_MEM_SIZE = 1ull << 25; // 32 MB
  };

  /**
   * bytecode program
   */
  class Program
  {
  public:
    const std::shared_ptr<Code> code;
    std::set<uint64_t> jump_dests;

    Program(Code&& c) : code(std::make_shared<Code>(c)) {}
    // Program(std::shared_ptr<Code>& c) : code(c) {}
    Program(std::shared_ptr<Code>&& c) : code(c) {}

    void compute_jump_dests()
    {
      for (uint64_t i = 0; i < code->size(); i++)
      {
        const auto op = (*code)[i];
        if (op >= PUSH1 && op <= PUSH32)
        {
          const uint8_t immediate_bytes = op - static_cast<uint8_t>(PUSH1) + 1;
          i += immediate_bytes;
        }
        else if (op == JUMPDEST)
          jump_dests.insert(i);
      }
    }
  };

  /**
   * execution context of a call
   */
  class Context
  {
  protected:
    bool pc_changed = true;
    uint64_t pc = 0;

  public:
    using PcType = decltype(pc);
    using ReturnHandler = std::function<void(std::vector<uint8_t>)>;
    using HaltHandler = std::function<void()>;
    using ExceptionHandler = std::function<void(const Exception&)>;

    std::vector<uint8_t> mem;
    Stack s;

    // latest return value and data
    std::vector<uint8_t> return_data;
    uint256_t return_value;

    AccountState as;
    Account& acc;
    Storage& st;
    const Address caller;
    const std::vector<uint8_t> input;
    const uint256_t call_value;
    Program prog;
    ReturnHandler rh;
    HaltHandler hh;
    ExceptionHandler eh;

    bool static_flag = false;

    bool stop_exec_now = false;
    std::unique_ptr<Exception> error;

    Context(
      const Address& caller,
      AccountState as,
      std::vector<uint8_t>&& input,
      const uint256_t& call_value,
      Program&& prog,
      ReturnHandler&& rh,
      HaltHandler&& hh,
      ExceptionHandler&& eh,
      bool is_static = false) :
      as(as),
      acc(as.acc),
      st(as.st),
      caller(caller),
      input(input),
      call_value(call_value),
      prog(prog),
      rh(rh),
      hh(hh),
      eh(eh),
      static_flag(is_static),
      stop_exec_now(false),
      error()
    {}

    /// increment the pc if it wasn't changed before
    void step()
    {
      if (stop_exec_now)
      {
        if (error && error.get() != nullptr)
        {
          throw *error;
        }
      }
      if (pc_changed)
        pc_changed = false;
      else
        pc++;
    }

    PcType get_pc() const
    {
      return pc;
    }

    void set_pc(const PcType pc_)
    {
      pc = pc_;
      pc_changed = true;
    }

    bool pc_valid() const
    {
      return pc < prog.code->size();
    }

    auto get_used_mem() const
    {
      return (mem.size() + Consts::WORD_SIZE - 1) / Consts::WORD_SIZE;
    }
  };

} // namespace eevm
