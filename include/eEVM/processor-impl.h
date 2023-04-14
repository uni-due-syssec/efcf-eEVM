#pragma once

#include "eEVM/bigint.h"
#include "eEVM/exception.h"
#include "eEVM/opcode.h"
#include "eEVM/processor.h"
#include "eEVM/stack.h"
#include "eEVM/util.h"
#include "intx/include/intx/intx.hpp"
#include "simple/simpleglobalstate.h"

#include <cstdint>

#ifdef ENABLE_FUZZING
#  include "eEVM/fuzz/fuzzcase.hpp"
#  include "eEVM/fuzz/tracing.hpp"
#  include "fuzz_config.hpp"
#endif

#include <algorithm>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <type_traits>
#include <utility>

using namespace std;

namespace eevm
{
  inline int get_sign(const uint256_t& v)
  {
    return (v >> 255) ? -1 : 1;
  }

  /**
   * implementation of the VM
   */
  class ProcessorImplementation
  {
  public:
    /// the interface to the global state
    std::shared_ptr<eevm::SimpleGlobalState> gs;
    /// the transaction object
    std::shared_ptr<Transaction> tx;
    /// pointer to trace object (for debugging)
    Trace* tr;
    /// the stack of contexts (one per nested call)
    shared_ptr<vector<shared_ptr<Context>>> ctxts;
    /// pointer to the current context
    shared_ptr<Context> ctxt;

    using ET = Exception::Type;

    fuzz::FuzzCaseParser* fuzzcase_parser = nullptr;

  public:
    ProcessorImplementation() = default;

    ProcessorImplementation(
      std::shared_ptr<eevm::SimpleGlobalState> gs,
      std::shared_ptr<Transaction> tx,
      Trace* tr) :
      tr(tr)
    {
      this->gs = gs;
      this->tx = tx;
    }

    void setFuzzCaseParser(fuzz::FuzzCaseParser* p)
    {
      fuzzcase_parser = p;
    }

    ExecResult run(
      const Address& caller,
      AccountState callee,
      vector<uint8_t> input, // Take a copy here, then move it into context
      const uint256_t& call_value)
    {
      if (!ctxts)
      {
        ctxts = std::make_shared<std::vector<std::shared_ptr<Context>>>();
      }
      // create the first context
      ExecResult result;
      auto rh = [&result](vector<uint8_t> output_) {
        result.er = ExitReason::returned;
        result.output = move(output_);
      };
      auto hh = [&result]() { result.er = ExitReason::halted; };
      auto eh = [&result](const Exception& ex_) {
        result.er = ExitReason::threw;
        result.ex = ex_.type;
        result.exmsg = ex_.what();
      };

      push_context(
        caller,
        callee,
        move(input),
        callee.acc.get_code_ref(),
        call_value,
        rh,
        hh,
        eh);

      // run in interpreter
      while (ctxt->get_pc() < ctxt->prog.code->size() && !ctxt->stop_exec_now)
      {
        try
        {
          dispatch();
        }
        catch (Exception& ex)
        {
          result.last_pc = ctxt->get_pc();
          ctxt->eh(ex);
          pop_context();
        }

        if (!ctxt)
          break;
        ctxt->step();
      }

      // halt outer context if it did not do so itself
      if (ctxt)
      {
        result.last_pc = ctxt->get_pc();

        if (ctxt->error)
        {
          auto eh = ctxt->eh;
          auto err = move(ctxt->error);
          pop_context();
          eh(*err);
        }
        else
        {
          // halt outer context if it did not do so itself
          stop();
        }
      }

      // clean-up
      for (const auto& addr : tx->selfdestruct_list)
        gs->remove(addr.first);

      return result;
    }

  protected:
    void push_context(
      const Address& caller,
      AccountState as,
      vector<uint8_t>&& input,
      Program&& prog,
      const uint256_t& call_value,
      Context::ReturnHandler&& rh,
      Context::HaltHandler&& hh,
      Context::ExceptionHandler&& eh,
      bool static_flag = false)
    {
      if (get_call_depth() >= Consts::MAX_CALL_DEPTH)
        throw Exception(
          ET::outOfBounds,
          "Reached max call depth (" + to_string(Consts::MAX_CALL_DEPTH) + ")");

      auto c = make_shared<Context>(
        caller,
        as,
        move(input),
        call_value,
        move(prog),
        move(rh),
        move(hh),
        move(eh),
        static_flag);
      ctxts->emplace_back(move(c));
      ctxt = ctxts->back();
    }

    uint16_t get_call_depth() const
    {
      return static_cast<uint16_t>(ctxts->size());
    }

    Opcode get_op() const
    {
      return static_cast<Opcode>((*ctxt->prog.code)[ctxt->get_pc()]);
    }

    uint256_t pop_addr(Stack& st)
    {
      static const uint256_t MASK_160 = (uint256_t(1) << 160) - 1;
      return st.pop() & MASK_160;
    }

    constexpr uint256_t to_addr(uint256_t x)
    {
      constexpr uint256_t MASK_160 = (uint256_t(1) << 160) - 1;
      return x & MASK_160;
    }

    void pop_context()
    {
      ctxts->pop_back();
      if (!ctxts->empty())
        ctxt = ctxts->back();
      else
        ctxt = nullptr;
    }

    static void copy_mem_raw(
      const uint64_t offDst,
      const uint64_t offSrc,
      const uint64_t size,
      vector<uint8_t>& dst,
      const vector<uint8_t>& src,
      const uint8_t pad = 0)
    {
      if (!size)
        return;

      const auto lastDst = offDst + size;
      if (lastDst < offDst)
        throw Exception(
          ET::outOfBounds,
          "Integer overflow in copy_mem (" + to_string(lastDst) + " < " +
            to_string(offDst) + ")");

      if (lastDst > Consts::MAX_MEM_SIZE)
        throw Exception(
          ET::outOfBounds,
          "Memory limit exceeded (" + to_string(lastDst) + " > " +
            to_string(Consts::MAX_MEM_SIZE) + ")");

      if (lastDst > dst.size())
        dst.resize(lastDst);

      const auto lastSrc = offSrc + size;
      const auto endSrc =
        min(lastSrc, static_cast<decltype(lastSrc)>(src.size()));
      uint64_t remaining;
      if (endSrc > offSrc)
      {
        copy(src.begin() + offSrc, src.begin() + endSrc, dst.begin() + offDst);
        remaining = lastSrc - endSrc;
      }
      else
      {
        remaining = size;
      }

      // if there are more bytes to copy than available, add padding
      fill(dst.begin() + lastDst - remaining, dst.begin() + lastDst, pad);
    }

    void copy_mem(
      vector<uint8_t>& dst, const vector<uint8_t>& src, const uint8_t pad)
    {
      const auto offDst = ctxt->s.pop64();
      const auto offSrc = ctxt->s.pop64();
      const auto size = ctxt->s.pop64();

      copy_mem_raw(offDst, offSrc, size, dst, src, pad);
    }

    void prepare_mem_access(const uint64_t offset, const uint64_t size)
    {
      const auto end = offset + size;
      if (end < offset)
        throw Exception(
          ET::outOfBounds,
          "Integer overflow in memory access (" + to_string(end) + " < " +
            to_string(offset) + ")");

      if (end > Consts::MAX_MEM_SIZE)
        throw Exception(
          ET::outOfBounds,
          "Memory limit exceeded (" + to_string(end) + " > " +
            to_string(Consts::MAX_MEM_SIZE) + ")");

      if (end > ctxt->mem.size())
        ctxt->mem.resize(end);
    }

    vector<uint8_t> copy_from_mem(const uint64_t offset, const uint64_t size)
    {
      prepare_mem_access(offset, size);
      return {ctxt->mem.begin() + offset, ctxt->mem.begin() + offset + size};
    }

    void jump_to(const uint64_t newPc)
    {
      if (ctxt->prog.jump_dests.size() == 0)
      {
        ctxt->prog.compute_jump_dests();
      }
      if (ctxt->prog.jump_dests.find(newPc) == ctxt->prog.jump_dests.end())
        throw Exception(
          ET::illegalInstruction,
          to_string(newPc) + " is not a jump destination");
      ctxt->set_pc(newPc);
    }

    template <
      typename X,
      typename Y,
      typename = enable_if_t<is_unsigned<X>::value && is_unsigned<Y>::value>>
    static auto safeAdd(const X x, const Y y)
    {
      const auto r = x + y;
      if (r < x)
        throw overflow_error("integer overflow");
      return r;
    }

    template <typename T>
    static T shrink(uint256_t i)
    {
      return static_cast<T>(i & numeric_limits<T>::max());
    }

    template <typename T>
    constexpr T convert_down(uint256_t i)
    {
      if (i > numeric_limits<T>::max())
      {
        throw Exception(
          ET::outOfBounds,
          "Value (" + to_hex_string(i) + ") is larger than limit");
      }
      return static_cast<T>(i);
    }

    void dispatch();

    //
    // op codes
    //
    void swap()
    {
      ctxt->s.swap(get_op() - SWAP1 + 1);
    }

    void dup()
    {
      ctxt->s.dup(get_op() - DUP1);
    }

    void add()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      ctxt->s.push(x + y);
    }

    constexpr uint256_t add_v(const uint256_t x, const uint256_t y)
    {
      return x + y;
    }

    void sub()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      ctxt->s.push(x - y);
    }

    constexpr uint256_t sub_v(const uint256_t x, const uint256_t y)
    {
      return x - y;
    }

    void mul()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      ctxt->s.push(x * y);
    }

    inline uint256_t mul_v(const uint256_t x, const uint256_t y)
    {
      return x * y;
    }

    void div()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      if (!y)
      {
        ctxt->s.push(0);
      }
      else
      {
        ctxt->s.push(x / y);
      }
    }

    constexpr uint256_t div_v(const uint256_t x, const uint256_t y)
    {
      if (!y)
      {
        return 0;
      }
      else
      {
        return x / y;
      }
    }

    void sdiv()
    {
      auto x = ctxt->s.pop();
      auto y = ctxt->s.pop();
      const auto min = (numeric_limits<uint256_t>::max() / 2) + 1;

      if (y == 0)
        ctxt->s.push(0);
      // special "overflow case" from the yellow paper
      else if (x == min && y == -1)
        ctxt->s.push(x);
      else
      {
        const auto signX = get_sign(x);
        const auto signY = get_sign(y);
        if (signX == -1)
          x = 0 - x;
        if (signY == -1)
          y = 0 - y;

        auto z = (x / y);
        if (signX != signY)
          z = 0 - z;
        ctxt->s.push(z);
      }
    }

    constexpr uint256_t sdiv_v(const uint256_t _x, const uint256_t _y)
    {
      const auto min = (numeric_limits<uint256_t>::max() / 2) + 1;
      auto x = _x;
      auto y = _y;

      if (y == 0)
      {
        return 0;
      }
      else if (x == min && y == -1)
      {
        return x;
      }
      else
      {
        const auto signX = get_sign(x);
        const auto signY = get_sign(y);
        if (signX == -1)
          x = 0 - x;
        if (signY == -1)
          y = 0 - y;

        auto z = (x / y);
        if (signX != signY)
          z = 0 - z;
        return z;
      }
    }

    void mod()
    {
      const auto x = ctxt->s.pop();
      const auto m = ctxt->s.pop();
      if (!m)
        ctxt->s.push(0);
      else
        ctxt->s.push(x % m);
    }

    constexpr uint256_t mod_v(const uint256_t x, const uint256_t m)
    {
      if (!m)
      {
        return 0;
      }
      else
      {
        return x % m;
      }
    }

    void smod()
    {
      auto x = ctxt->s.pop();
      auto m = ctxt->s.pop();
      if (m == 0)
        ctxt->s.push(0);
      else
      {
        const auto signX = get_sign(x);
        const auto signM = get_sign(m);
        if (signX == -1)
          x = 0 - x;
        if (signM == -1)
          m = 0 - m;

        auto z = (x % m);
        if (signX == -1)
          z = 0 - z;
        ctxt->s.push(z);
      }
    }

    constexpr uint256_t smod_v(const uint256_t _x, const uint256_t _m)
    {
      auto x = _x;
      auto m = _m;
      if (!m)
      {
        return 0;
      }
      else
      {
        const auto signX = get_sign(x);
        const auto signM = get_sign(m);
        if (signX == -1)
          x = 0 - x;
        if (signM == -1)
          m = 0 - m;

        auto z = (x % m);
        if (signX == -1)
          z = 0 - z;
        return x % z;
      }
    }

    void addmod()
    {
      const uint512_t x = ctxt->s.pop();
      const uint512_t y = ctxt->s.pop();
      const auto m = ctxt->s.pop();
      if (!m)
      {
        ctxt->s.push(0);
      }
      else
      {
        const uint512_t n = (x + y) % m;
        ctxt->s.push(n.lo);
      }
    }

    constexpr uint256_t addmod_v(
      const uint256_t x, const uint256_t y, const uint256_t m)
    {
      if (!m)
      {
        return 0;
      }
      else
      {
        const uint512_t n = (x + y) % m;
        return n.lo;
      }
    }

    void mulmod()
    {
      const uint512_t x = ctxt->s.pop();
      const uint512_t y = ctxt->s.pop();
      const auto m = ctxt->s.pop();
      if (!m)
      {
        ctxt->s.push(m);
      }
      else
      {
        const uint512_t n = (x * y) % m;
        ctxt->s.push(n.lo);
      }
    }

    constexpr uint256_t mulmod_v(
      const uint256_t x, const uint256_t y, const uint256_t m)
    {
      if (!m)
      {
        return m;
      }
      else
      {
        const uint512_t n = (x * y) % m;
        return n.lo;
      }
    }

    void exp()
    {
      const auto b = ctxt->s.pop();
      const auto e = ctxt->s.pop64();
      ctxt->s.push(intx::exp(b, uint256_t(e)));
    }

    constexpr uint256_t exp_v(const uint256_t b, const uint256_t e)
    {
      // const auto d = convert_down<uint64_t>(e);
      return intx::exp(b, e);
    }

    void signextend()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      if (x >= 32)
      {
        ctxt->s.push(y);
        return;
      }
      const auto idx = 8 * shrink<uint8_t>(x) + 7;
      const auto sign = static_cast<uint8_t>((y >> idx) & 1);
      constexpr auto zero = uint256_t(0);
      const auto mask = ~zero >> (256 - idx);
      const auto yex = ((sign ? ~zero : zero) << idx) | (y & mask);
      ctxt->s.push(yex);
    }

    constexpr uint256_t signextend_v(const uint256_t x, const uint256_t y)
    {
      if (x >= 32)
      {
        return y;
      }
      const auto idx = 8 * shrink<uint8_t>(x) + 7;
      const auto sign = static_cast<uint8_t>((y >> idx) & 1);
      constexpr auto zero = uint256_t(0);
      const auto mask = ~zero >> (256 - idx);
      const auto yex = ((sign ? ~zero : zero) << idx) | (y & mask);
      return yex;
    }

    void lt()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      ctxt->s.push((x < y) ? 1 : 0);
    }

    constexpr uint256_t lt_v(const uint256_t x, const uint256_t y)
    {
      return ((x < y) ? 1 : 0);
    }

    void gt()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      ctxt->s.push((x > y) ? 1 : 0);
    }

    constexpr uint256_t gt_v(const uint256_t x, const uint256_t y)
    {
      return ((x > y) ? 1 : 0);
    }

    void slt()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      if (x == y)
      {
        ctxt->s.push(0);
        return;
      }

      const auto signX = get_sign(x);
      const auto signY = get_sign(y);
      if (signX != signY)
      {
        if (signX == -1)
          ctxt->s.push(1);
        else
          ctxt->s.push(0);
      }
      else
      {
        ctxt->s.push((x < y) ? 1 : 0);
      }
    }

    constexpr uint256_t slt_v(const uint256_t x, const uint256_t y)
    {
      if (x == y)
      {
        return 0;
      }

      const auto signX = get_sign(x);
      const auto signY = get_sign(y);
      if (signX != signY)
      {
        if (signX == -1)
          return 1;
        else
          return 0;
      }
      else
      {
        return ((x < y) ? 1 : 0);
      }
    }

    void sgt()
    {
      ctxt->s.swap(1);
      slt();
    }

    constexpr uint256_t sgt_v(const uint256_t x, const uint256_t y)
    {
      return slt_v(y, x);
    }

    void eq()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      if (x == y)
        ctxt->s.push(1);
      else
        ctxt->s.push(0);
    }

    constexpr uint256_t eq_v(const uint256_t x, const uint256_t y)
    {
      return ((x == y) ? 1 : 0);
    }

    void isZero()
    {
      const auto x = ctxt->s.pop();
      if (x == 0)
        ctxt->s.push(1);
      else
        ctxt->s.push(0);
    }

    constexpr uint256_t iszero_v(const uint256_t x)
    {
      return ((x == 0) ? 1 : 0);
    }

    void and_()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      ctxt->s.push(x & y);
    }

    constexpr uint256_t and_v(const uint256_t x, const uint256_t y)
    {
      return x & y;
    }

    void or_()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      ctxt->s.push(x | y);
    }

    constexpr uint256_t or_v(const uint256_t x, const uint256_t y)
    {
      return x | y;
    }

    void xor_()
    {
      const auto x = ctxt->s.pop();
      const auto y = ctxt->s.pop();
      ctxt->s.push(x ^ y);
    }

    constexpr uint256_t xor_v(const uint256_t x, const uint256_t y)
    {
      return x ^ y;
    }

    void not_()
    {
      const auto x = ctxt->s.pop();
      ctxt->s.push(~x);
    }

    constexpr uint256_t not_v(const uint256_t x)
    {
      return (~x);
    }

    void byte()
    {
      const auto idx = ctxt->s.pop();
      if (idx >= 32)
      {
        ctxt->s.push(0);
        return;
      }
      const auto shift = 256 - 8 - 8 * shrink<uint8_t>(idx);
      const auto mask = uint256_t(255) << shift;
      const auto val = ctxt->s.pop();
      ctxt->s.push((val & mask) >> shift);
    }

    constexpr uint256_t byte_v(const uint256_t idx, const uint256_t val)
    {
      if (idx >= 32)
      {
        return 0;
      }
      const auto shift = 256 - 8 - 8 * shrink<uint8_t>(idx);
      const auto mask = uint256_t(255) << shift;
      return ((val & mask) >> shift);
    }

    void shl()
    {
      const auto shift = ctxt->s.pop();
      const auto val = ctxt->s.pop();
      ctxt->s.push(shl_v(shift, val));
    }

    inline uint256_t shl_v(const uint256_t _shift, const uint256_t val)
    {
      const auto shift = static_cast<unsigned>(_shift);
      return (shift >= 256 ? 0 : (val << shift));
    }

    void shr()
    {
      const auto shift = ctxt->s.pop();
      const auto val = ctxt->s.pop();
      ctxt->s.push(shr_v(shift, val));
    }

    inline uint256_t shr_v(const uint256_t _shift, const uint256_t val)
    {
      const auto shift = static_cast<unsigned>(_shift);
      return (shift >= 256 ? 0 : (val >> shift));
    }

    void sar()
    {
      const uint256_t amount = static_cast<unsigned>(ctxt->s.pop());
      const uint256_t shiftee = ctxt->s.pop();

      ctxt->s.push(sar_v(shiftee, amount));
    }

    inline uint256_t sar_v(const uint256_t _amount, const uint256_t shiftee)
    {
      using namespace intx;
      constexpr uint256_t hibit = 1_u256 << 255;
      constexpr uint256_t allbits = ~0_u256;

      const auto amount = static_cast<unsigned>(_amount);
      if (amount >= 256)
      {
        if (shiftee & hibit)
        {
          return allbits;
        }
        else
        {
          return 0;
        }
      }
      else
      {
        auto x = shiftee >> amount;
        if (shiftee & hibit)
        {
          x |= allbits << (256 - amount);
        }
        return x;
      }
    }

    void jump()
    {
      const auto newPc = ctxt->s.pop64();
      jump_to(newPc);
    }

    void jumpi()
    {
      const auto newPc = ctxt->s.pop64();
      const auto cond = ctxt->s.pop();
      if (cond)
        jump_to(newPc);
    }

    void jumpdest() {}

    void pc()
    {
      ctxt->s.push(ctxt->get_pc());
    }

    void msize()
    {
      ctxt->s.push(ctxt->get_used_mem() * 32);
    }

    inline uint256_t msize_v()
    {
      return ctxt->get_used_mem() * 32;
    }

    void mload()
    {
      const auto offset = ctxt->s.pop64();
      prepare_mem_access(offset, Consts::WORD_SIZE);
      const auto start = ctxt->mem.data() + offset;
      ctxt->s.push(from_big_endian(start, Consts::WORD_SIZE));
    }

    inline uint256_t mload_v(uint256_t _offset)
    {
      const auto offset = convert_down<uint64_t>(_offset);
      prepare_mem_access(offset, Consts::WORD_SIZE);
      const auto start = ctxt->mem.data() + offset;
      return (from_big_endian(start, Consts::WORD_SIZE));
    }

    void mstore()
    {
      const auto offset = ctxt->s.pop64();
      const auto word = ctxt->s.pop();
      prepare_mem_access(offset, Consts::WORD_SIZE);
      to_big_endian(word, ctxt->mem.data() + offset);
    }

    inline void mstore_v(uint256_t _offset, uint256_t word)
    {
      const auto offset = convert_down<uint64_t>(_offset);
      prepare_mem_access(offset, Consts::WORD_SIZE);
      to_big_endian(word, ctxt->mem.data() + offset);
    }

    void mstore8()
    {
      const auto offset = ctxt->s.pop64();
      const auto b = shrink<uint8_t>(ctxt->s.pop());
      prepare_mem_access(offset, sizeof(b));
      ctxt->mem[offset] = b;
    }

    inline void mstore8_v(uint256_t _offset, uint256_t word)
    {
      const auto offset = convert_down<uint64_t>(_offset);
      const auto b = shrink<uint8_t>(word);
      prepare_mem_access(offset, sizeof(b));
      ctxt->mem[offset] = b;
    }

    void sload()
    {
      const auto k = ctxt->s.pop();
      ctxt->s.push(ctxt->st.load(k));
    }

    inline uint256_t sload_v(uint256_t k)
    {
      return ctxt->st.load(k);
    }

    void sstore()
    {
      if (ctxt->static_flag)
      {
        throw Exception(
          ET::staticViolation, "Call to SSTORE during STATICCALL.");
      }
      const auto k = ctxt->s.pop();
      const auto v = ctxt->s.pop();
      ctxt->st.store(k, v);
    }

    inline void sstore_v(uint256_t k, uint256_t v)
    {
      if (ctxt->static_flag)
      {
        ctxt->error = std::make_unique<Exception>(
          ET::staticViolation, "Call to SSTORE during STATICCALL.");
        ctxt->stop_exec_now = true;
        return;
      }
      ctxt->st.store(k, v);
    }

    void codecopy()
    {
      copy_mem(ctxt->mem, *ctxt->prog.code, Opcode::STOP);
    }

    inline void codecopy_v(
      uint256_t _offDst, uint256_t _offSrc, uint256_t _size)
    {
      const auto offDst = convert_down<uint64_t>(_offDst);
      const auto offSrc = convert_down<uint64_t>(_offSrc);
      const auto size = convert_down<uint64_t>(_size);

      copy_mem_raw(
        offDst, offSrc, size, ctxt->mem, *ctxt->prog.code, Opcode::STOP);
    }

    void extcodesize()
    {
      ctxt->s.push(gs->get(pop_addr(ctxt->s)).acc.get_code().size());
    }

    inline uint256_t extcodesize_v(uint256_t _addr)
    {
      auto addr = to_addr(_addr);
      if (gs->exists(addr))
      {
#ifdef ENABLE_FUZZING
        bool mocked = gs->get(addr).acc.is_mocked();

        // TODO: I do not think this is correct. The problem is that the normal
        // "attacker" contracts have specific code sizes. If mocking of
        // non-existant contracts is enabled, then we cannot identify the access
        // control bugs that utilize extcodesize to determine whether an address
        // is an EOA or contract.
        if (eevm::fuzz::mock_calls_to_nonexistent_accounts && mocked)
        {
          return 512;
        }
#endif
        return gs->get(addr).acc.get_code().size();
      }
      else
      {
#ifdef ENABLE_FUZZING
        if (eevm::fuzz::mock_calls_to_nonexistent_accounts)
        {
          gs->get(addr).acc.set_mocked(true);
          return 512;
        }
#endif
        return 0;
      }
      return 0;
    }

    void extcodecopy()
    {
      copy_mem(
        ctxt->mem, gs->get(pop_addr(ctxt->s)).acc.get_code(), Opcode::STOP);
    }

    inline void extcodecopy_v(
      uint256_t addr, uint256_t _offDst, uint256_t _offSrc, uint256_t _size)
    {
      const auto offDst = convert_down<uint64_t>(_offDst);
      const auto offSrc = convert_down<uint64_t>(_offSrc);
      const auto size = convert_down<uint64_t>(_size);

      copy_mem_raw(
        offDst,
        offSrc,
        size,
        ctxt->mem,
        gs->get(to_addr(addr)).acc.get_code(),
        Opcode::STOP);
    }

    void codesize()
    {
      ctxt->s.push(ctxt->acc.get_code().size());
    }

    inline uint256_t codesize_v()
    {
      return (ctxt->acc.get_code().size());
    }

    void calldataload()
    {
      const auto offset = ctxt->s.pop64();
      ctxt->s.push(__calldataload(offset));
    }

    inline uint256_t calldataload_v(uint256_t offset)
    {
      return __calldataload(convert_down<uint64_t>(offset));
    }

    inline uint256_t __calldataload(uint64_t offset)
    {
      uint256_t v = 0;

      const auto r = offset + Consts::WORD_SIZE;
      // if it overflowed, we can return a 0 word.
      if (r < offset)
      {
        return v;
      }

      const auto sizeInput = ctxt->input.size();

      if (offset < sizeInput)
      {
        for (uint8_t i = 0; i < Consts::WORD_SIZE; i++)
        {
          const auto j = offset + i;
          if (j < sizeInput)
          {
            v = (v << 8) + ctxt->input[j];
          }
          else
          {
            v <<= 8 * (Consts::WORD_SIZE - i);
            break;
          }
        }
      }

      return v;
    }

    void calldatasize()
    {
      ctxt->s.push(ctxt->input.size());
    }

    inline uint256_t calldatasize_v()
    {
      return ctxt->input.size();
    }

    void calldatacopy()
    {
      copy_mem(ctxt->mem, ctxt->input, 0);
    }

    inline void calldatacopy_v(
      uint256_t _offDst, uint256_t _offSrc, uint256_t _size)
    {
      const auto offDst = convert_down<uint64_t>(_offDst);
      const auto offSrc = convert_down<uint64_t>(_offSrc);
      const auto size = convert_down<uint64_t>(_size);

      copy_mem_raw(offDst, offSrc, size, ctxt->mem, ctxt->input, 0);
    }

    void address()
    {
      ctxt->s.push(ctxt->acc.get_address());
    }

    inline uint256_t address_v()
    {
      return ctxt->acc.get_address();
    }

    void balance()
    {
      decltype(auto) acc = gs->get(pop_addr(ctxt->s)).acc;
      ctxt->s.push(acc.get_balance());
    }

    inline uint256_t balance_v(const uint256_t _addr)
    {
      decltype(auto) acc = gs->get(to_addr(_addr)).acc;
      return acc.get_balance();
    }

    void selfbalance()
    {
      ctxt->s.push(selfbalance_v());
    }

    inline uint256_t selfbalance_v()
    {
      return ctxt->acc.get_balance();
    }

    void origin()
    {
      ctxt->s.push(tx->origin);
    }

    inline uint256_t origin_v()
    {
      return tx->origin;
    }

    void caller()
    {
      ctxt->s.push(ctxt->caller);
    }

    inline uint256_t caller_v()
    {
      return ctxt->caller;
    }

    void callvalue()
    {
      ctxt->s.push(ctxt->call_value);
    }

    inline uint256_t callvalue_v()
    {
      return ctxt->call_value;
    }

    void push()
    {
      const uint8_t bytes = get_op() - PUSH1 + 1;
      const auto end = ctxt->get_pc() + bytes;
      if (end < ctxt->get_pc())
        throw Exception(
          ET::outOfBounds,
          "Integer overflow in push (" + to_string(end) + " < " +
            to_string(ctxt->get_pc()) + ")");

      if (end >= ctxt->prog.code->size())
        throw Exception(
          ET::outOfBounds,
          "Push immediate exceeds size of program (" + to_string(end) +
            " >= " + to_string(ctxt->prog.code->size()) + ")");

      // TODO: parse immediate once and not every time
      auto pc = ctxt->get_pc() + 1;
      uint256_t imm = 0;
      for (int i = 0; i < bytes; i++)
        imm = (imm << 8) | (*ctxt->prog.code)[pc++];

      ctxt->s.push(imm);
      ctxt->set_pc(pc);
    }

    void pop()
    {
      ctxt->s.pop();
    }

    void logN(const uint8_t n)
    {
      const auto offset = ctxt->s.pop64();
      const auto size = ctxt->s.pop64();

      vector<uint256_t> topics(n);
      for (int i = 0; i < n; i++)
        topics[i] = ctxt->s.pop();

      tx->log_handler.handle(
        {ctxt->acc.get_address(), copy_from_mem(offset, size), topics});
    }

    void log()
    {
      if (ctxt->static_flag)
      {
        throw Exception(ET::staticViolation, "Call to LOGN during STATICCALL.");
      }
      const uint8_t n = get_op() - LOG0;
      const auto offset = ctxt->s.pop64();
      const auto size = ctxt->s.pop64();

      vector<uint256_t> topics(n);
      for (int i = 0; i < n; i++)
        topics[i] = ctxt->s.pop();

      tx->log_handler.handle(
        {ctxt->acc.get_address(), copy_from_mem(offset, size), topics});
    }

    inline void logN_v(
      uint64_t offset, uint64_t size, const vector<uint256_t>& topics)
    {
      if (ctxt->static_flag)
      {
        ctxt->error = std::make_unique<Exception>(
          ET::staticViolation, "Call to LOGN during STATICCALL.");
        ctxt->stop_exec_now = true;
        return;
      }
      tx->log_handler.handle(
        {ctxt->acc.get_address(), copy_from_mem(offset, size), topics});
    }

    inline void log0_v(const uint256_t offset, const uint256_t size)
    {
      logN_v(convert_down<uint64_t>(offset), convert_down<uint64_t>(size), {});
    }
    inline void log1_v(
      const uint256_t offset, const uint256_t size, const uint256_t l0)
    {
      logN_v(
        convert_down<uint64_t>(offset), convert_down<uint64_t>(size), {l0});
    }
    inline void log2_v(
      const uint256_t offset,
      const uint256_t size,
      const uint256_t l0,
      const uint256_t l1)
    {
      logN_v(
        convert_down<uint64_t>(offset), convert_down<uint64_t>(size), {l0, l1});
    }
    inline void log3_v(
      const uint256_t offset,
      const uint256_t size,
      const uint256_t l0,
      const uint256_t l1,
      const uint256_t l2)
    {
      logN_v(
        convert_down<uint64_t>(offset),
        convert_down<uint64_t>(size),
        {l0, l1, l2});
    }
    inline void log4_v(
      const uint256_t offset,
      const uint256_t size,
      const uint256_t l0,
      const uint256_t l1,
      const uint256_t l2,
      const uint256_t l3)
    {
      logN_v(
        convert_down<uint64_t>(offset),
        convert_down<uint64_t>(size),
        {l0, l1, l2, l3});
    }

    void blockhash()
    {
      // Original implementation seems wrong?
      // const auto i = ctxt->s.pop64();
      // if (i >= 256)
      //   ctxt->s.push(0);
      // else
      //   ctxt->s.push(gs->get_block_hash(i % 256));

      ctxt->s.push(blockhash_v(ctxt->s.pop()));
    }

    inline uint256_t blockhash_v(const uint256_t blocknum)
    {
      const uint256_t cur_bn = gs->get_current_block().number;
      if (blocknum > cur_bn)
      {
        return 0;
      }
      if (cur_bn < 256 || blocknum >= (cur_bn - 256))
      {
        const auto i = convert_down<uint64_t>(blocknum);
        return (gs->get_block_hash(i));
      }
      return 0;
    }

    void number()
    {
      ctxt->s.push(gs->get_current_block().number);
    }

    inline uint256_t number_v()
    {
      return (gs->get_current_block().number);
    }

    void gasprice()
    {
      ctxt->s.push(tx->gas_price);
    }

    inline uint256_t gasprice_v()
    {
      return tx->gas_price;
    }

    void coinbase()
    {
      ctxt->s.push(gs->get_current_block().coinbase);
    }

    inline uint256_t coinbase_v()
    {
      return gs->get_current_block().coinbase;
    }

    void timestamp()
    {
      ctxt->s.push(gs->get_current_block().timestamp);
    }

    inline uint256_t timestamp_v()
    {
      return gs->get_current_block().timestamp;
    }

    void difficulty()
    {
      ctxt->s.push(gs->get_current_block().difficulty);
    }

    inline uint256_t difficulty_v()
    {
      return gs->get_current_block().difficulty;
    }

    void gas()
    {
      // NB: we do not currently track gas. This will always return the tx's
      // initial gas value
      ctxt->s.push(tx->gas_limit);
    }

    inline uint256_t gas_v()
    {
      return tx->gas_limit;
    }

    void gaslimit()
    {
      ctxt->s.push(gs->get_current_block().gas_limit);
    }

    inline uint256_t gaslimit_v()
    {
      return (gs->get_current_block().gas_limit);
    }

    void chainid()
    {
      ctxt->s.push(chainid_v());
    }

    constexpr uint256_t chainid_v()
    {
      // always run on mainnet (see
      // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md)
      return 1;
    }

    void sha3()
    {
      const auto offset = ctxt->s.pop64();
      const auto size = ctxt->s.pop64();
      prepare_mem_access(offset, size);

      uint8_t h[32];
      keccak_256(ctxt->mem.data() + offset, static_cast<unsigned int>(size), h);
      ctxt->s.push(from_big_endian(h, sizeof(h)));
    }

    inline uint256_t sha3_v(uint256_t _offset, uint256_t _size)
    {
      const auto offset = convert_down<uint64_t>(_offset);
      const auto size = convert_down<uint64_t>(_size);
      prepare_mem_access(offset, size);

      uint8_t h[32];
      keccak_256(ctxt->mem.data() + offset, static_cast<unsigned int>(size), h);
      return from_big_endian(h, sizeof(h));
    }

    void return_()
    {
      const auto offset = ctxt->s.pop64();
      const auto size = ctxt->s.pop64();

      // invoke caller's return handler
      ctxt->rh(copy_from_mem(offset, size));
      pop_context();
    }

    inline void return_v(const uint256_t _offset, const uint256_t _size)
    {
      const auto offset = convert_down<uint64_t>(_offset);
      const auto size = convert_down<uint64_t>(_size);

      auto retdata = copy_from_mem(offset, size);
      // ctxt->return_value = 1;
      // ctxt->return_data = retdata;

#ifdef ENABLE_FUZZING
      eevm::fuzz::dump_return(ctxt->get_pc(), eevm::Opcode::RETURN, ctxt.get());
#endif

      // invoke caller's return handler
      ctxt->rh(retdata);
    }

    void revert()
    {
      const auto offset = ctxt->s.pop();
      const auto size = ctxt->s.pop();
      revert_v(offset, size);
    }

    inline void revert_v(const uint256_t _offset, const uint256_t _size)
    {
      const auto offset = convert_down<uint64_t>(_offset);
      const auto size = convert_down<uint64_t>(_size);

      auto retdata = copy_from_mem(offset, size);
      // ctxt->return_value = 0;
      // ctxt->return_data = retdata;

      // invoke caller's return handler
      ctxt->rh(retdata);

      ctxt->error = std::make_unique<Exception>(
        Exception::Type::reverted,
        fmt::format(
          "revert() called by {} at call depth {}",
          eevm::to_hex_string(ctxt->acc.get_address()),
          ctxts->size()));
      ctxt->stop_exec_now = true;
      
      ctxt->eh(*ctxt->error);
    }

    inline void invalid_v()
    {
      ctxt->error = std::make_unique<Exception>(
        Exception::Type::illegalInstruction, "INVALID instruction encountered");
      ctxt->stop_exec_now = true;
      ctxt->return_value = 0;
      ctxt->return_data.clear();
      ctxt->eh(*ctxt->error);
    }

    void returndatasize()
    {
      ctxt->s.push(ctxt->return_data.size());
    }

    inline uint256_t returndatasize_v()
    {
      return (ctxt->return_data.size());
    }

    void returndatacopy()
    {
      const auto memOff = ctxt->s.pop64();
      const auto retdataOff = ctxt->s.pop64();
      const auto size = ctxt->s.pop64();

      copy_mem_raw(memOff, retdataOff, size, ctxt->mem, ctxt->return_data, 0);
    }

    inline void returndatacopy_v(
      const uint256_t _memOff,
      const uint256_t _retdataOff,
      const uint256_t _size)
    {
      const auto memOff = convert_down<uint64_t>(_memOff);
      const auto retdataOff = convert_down<uint64_t>(_retdataOff);
      const auto size = convert_down<uint64_t>(_size);
      copy_mem_raw(memOff, retdataOff, size, ctxt->mem, ctxt->return_data, 0);
    }

    void stop()
    {
      // (1) save halt handler
      auto hh = ctxt->hh;
      // (2) pop current context
      pop_context();
      // (3) invoke halt handler
      hh();
    }

    inline void stop_v()
    {
      ctxt->return_value = 1;
      ctxt->return_data = {};
      ctxt->hh();
    }

    void selfdestruct()
    {
      if (ctxt->static_flag)
      {
        throw Exception(
          ET::staticViolation, "Call to CREATE during STATICCALL.");
      }
      selfdestruct_v(pop_addr(ctxt->s));
    }

    inline void selfdestruct_v(uint256_t _addr)
    {
      if (ctxt->static_flag)
      {
        ctxt->stop_exec_now = true;
        ctxt->error = std::make_unique<Exception>(
          ET::staticViolation, "Call to CREATE during STATICCALL.");
        return;
      }

      const auto addr = to_addr(_addr);
      auto recipient = gs->get(addr);

      ctxt->acc.pay_to(recipient.acc, ctxt->acc.get_balance());
      tx->selfdestruct_list.push_back(
        std::make_pair(ctxt->acc.get_address(), addr));

      stop_v();
    }

    void create()
    {
      if (ctxt->static_flag)
      {
        throw Exception(
          ET::staticViolation, "Call to CREATE during STATICCALL.");
      }

      const auto contractValue = ctxt->s.pop();
      const auto offset = ctxt->s.pop64();
      const auto size = ctxt->s.pop64();
      auto initCode = copy_from_mem(offset, size);

      const auto newAddress =
        generate_address(ctxt->acc.get_address(), ctxt->acc.get_nonce());

      // For contract accounts, the nonce counts the number of
      // contract-creations by this account
      // TODO: Work out why this fails the test cases
      // ctxt->acc.increment_nonce();

      decltype(auto) newAcc = gs->create(newAddress, contractValue, {});

      // In contract creation, the transaction value is an endowment for the
      // newly created account
      ctxt->acc.pay_to(newAcc.acc, contractValue);

      auto parentContext = ctxt;
      auto rh = [&newAcc, parentContext](vector<uint8_t> output) {
        newAcc.acc.set_code(move(output));
        parentContext->s.push(newAcc.acc.get_address());
      };
      auto hh = [parentContext]() { parentContext->s.push(0); };
      auto eh = [parentContext](const Exception&) { parentContext->s.push(0); };

      // create new context for init code execution
      push_context(
        ctxt->acc.get_address(),
        newAcc,
        {},
        std::move(initCode),
        0,
        rh,
        hh,
        eh);
    }

    void call()
    {
      const auto op = get_op();
      ctxt->s.pop(); // gas limit not used
      const auto addr = pop_addr(ctxt->s);
      const auto value =
        (op == DELEGATECALL || op == STATICCALL) ? 0 : ctxt->s.pop();
      const auto offIn = ctxt->s.pop64();
      const auto sizeIn = ctxt->s.pop64();
      const auto offOut = ctxt->s.pop64();
      const auto sizeOut = ctxt->s.pop64();

      if (addr >= 1 && addr <= 8)
      {
        // TODO: implement native extensions
        throw Exception(
          ET::notImplemented,
          "Precompiled contracts/native extensions are not implemented.");
      }

      auto r = check_on_call(addr, value, op);
      if (r != 1)
      {
        ctxt->s.push(r);
        return;
      }

      decltype(auto) callee = gs->get(addr);
      if (value != 0)
      {
        ctxt->acc.pay_to(callee.acc, value);
      }
      if (!callee.acc.has_code())
      {
        ctxt->s.push(1);
        return;
      }

      prepare_mem_access(offOut, sizeOut);
      auto input = copy_from_mem(offIn, sizeIn);

      auto parentContext = ctxt;
      auto rh =
        [offOut, sizeOut, parentContext](const vector<uint8_t>& output) {
          parentContext->return_value = 1;
          parentContext->return_data = output;
          copy_mem_raw(offOut, 0, sizeOut, parentContext->mem, output);
          parentContext->s.push(1);
        };
      auto hh = [parentContext]() {
        parentContext->return_value = 1;
        parentContext->s.push(1);
      };
      auto he = [parentContext](const Exception&) {
        parentContext->return_value = 0;
        parentContext->s.push(0);
      };

      switch (op)
      {
        case Opcode::CALL:
          push_context(
            ctxt->acc.get_address(),
            callee,
            move(input),
            callee.acc.get_code_ref(),
            value,
            rh,
            hh,
            he,
            ctxt->static_flag);
          break;
        case Opcode::STATICCALL:
          push_context(
            ctxt->acc.get_address(),
            callee,
            move(input),
            callee.acc.get_code_ref(),
            0,
            rh,
            hh,
            he,
            true /* set static flag */);
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
            he,
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
            he,
            ctxt->static_flag);
          break;
        default:
          throw UnexpectedState("Unknown call opcode.");
      }
    }

    uint64_t check_on_call(Address addr, uint256_t value, Opcode op);
  };

  class SpecializedProcessor : public ProcessorImplementation
  {
  public:
    using ProcessorImplementation::ProcessorImplementation;

    virtual ~SpecializedProcessor(){};

    virtual void dispatch() = 0;
    // {
    //   throw Exception(ET::notImplemented, "This is an abstract class.");
    // };

#define EVM2CPP_HAS_DUPLICATE_METHOD 1
    virtual std::unique_ptr<SpecializedProcessor> duplicate() = 0;
    // {
    //   throw Exception(ET::notImplemented, "This is an abstract class.");
    // };

    virtual const Code& bytecode() = 0;
    virtual const Code& constructor_bytecode() = 0;
    virtual const Code& constructor_args() = 0;
    virtual const std::string& name() = 0;

    void prepare(
      std::shared_ptr<eevm::SimpleGlobalState> _gs,
      std::shared_ptr<Transaction> _tx,
      Trace* _tr)
    {
      gs = _gs;
      tx = _tx;
      tr = _tr;
      ctxts = std::make_shared<vector<std::shared_ptr<Context>>>();
      ctxt = nullptr;
    }

    void prepareNested(
      std::shared_ptr<eevm::SimpleGlobalState> _gs,
      std::shared_ptr<Transaction> _tx,
      Trace* _tr,
      std::shared_ptr<vector<std::shared_ptr<Context>>> _ctxts)
    {
      gs = _gs;
      tx = _tx;
      tr = _tr;
      ctxts = _ctxts;
      if (ctxts->empty())
      {
        ctxt = nullptr;
      }
      else
      {
        ctxt = ctxts->back();
      }
    }

    void unprepare()
    {
      gs = nullptr;
      tx = nullptr;
      tr = nullptr;
      ctxts = nullptr;
      ctxt = nullptr;
    }

    void on_bb_start(Context::PcType pc)
    {
      if (ctxt)
      {
        ctxt->set_pc(pc);

        if (ctxt->stop_exec_now)
        {
          if (ctxt->error)
          {
            throw *ctxt->error;
          }
          else
          {
            throw std::runtime_error(
              "Context with stop_exec_now set, but no reason in "
              "ctxt->error!!!");
          }
        }
      }
      else
      {
        throw Exception(
          ET::illegalInstruction,
          "Fatal: Execution of BB " + to_string(pc) + " without ctxt!!!");
      }

      if (tr)
      {
        tr->add(
          ctxt->get_pc(),
          get_op(),
          get_call_depth(),
          ctxt->acc.get_address(),
          ctxt->s);
      }
    }

    ExecResult run(
      const Address& caller,
      AccountState callee,
      vector<uint8_t> input, // Take a copy here, then move it into context
      const uint256_t& call_value)
    {
      if (!ctxts)
      {
        ctxts = std::make_shared<std::vector<std::shared_ptr<Context>>>();
      }
      // create the first context
      ExecResult result;
      auto rh = [&result](vector<uint8_t> output_) {
        result.er = ExitReason::returned;
        result.output = move(output_);
      };
      auto hh = [&result]() { result.er = ExitReason::halted; };
      auto eh = [&result](const Exception& ex_) {
        result.er = ExitReason::threw;
        result.ex = ex_.type;
        result.exmsg = ex_.what();
      };

      push_context(
        caller,
        callee,
        move(input),
        callee.acc.get_code_ref(),
        call_value,
        rh,
        hh,
        eh);

      try
      {
        dispatch();
      }
      catch (Exception& ex)
      {
        result.last_pc = ctxt->get_pc();
        auto eh = ctxt->eh;
        pop_context();
        eh(ex);
      }

      if (ctxt)
      {
        result.last_pc = ctxt->get_pc();

        if (ctxt->error)
        {
          result.last_pc = ctxt->get_pc();
          auto eh = ctxt->eh;
          auto err = move(ctxt->error);
          pop_context();
          eh(*err);
        }
        else
        {
          // halt outer context if it did not do so itself
          stop();
        }
      }

      // clean-up
      if (tx != nullptr)
      {
        for (const auto& addr : tx->selfdestruct_list)
        {
          gs->remove(addr.first);
        }
      }

      return result;
    }

    ExecResult runNested()
    {
      ExecResult result;
      if (!ctxts)
      {
        ctxts = std::make_shared<std::vector<std::shared_ptr<Context>>>();
      }

      try
      {
        dispatch();
      }
      catch (Exception& ex)
      {
        result.last_pc = ctxt->get_pc();
        ctxt->eh(ex);
      }

      if (ctxt)
      {
        result.last_pc = ctxt->get_pc();

        if (ctxt->error)
        {
          result.last_pc = ctxt->get_pc();
          auto eh = ctxt->eh;
          auto err = move(ctxt->error);
          eh(*err);
        }
        else
        {
          // halt outer context if it did not do so itself
          stop();
        }
      }

      // clean-up
      if (tx != nullptr)
      {
        for (const auto& addr : tx->selfdestruct_list)
          gs->remove(addr.first);
      }

      return result;
    }

    void create()
    {
      // TODO: can we somehow support the CREATE instruction? fall back to the
      // interpreter or simply use `do_call` to mock the "return" value of the
      // CREATE instruction? We could CREATE at a fixed address in our harness?
      throw Exception(
        ET::notImplemented,
        "Specialized Executor cannot CREATE new contracts!");
    }

    inline uint256_t create_v(
      const uint256_t x, const uint256_t y, const uint256_t z)
    {
      throw Exception(
        ET::notImplemented,
        "Specialized Executor cannot CREATE new contracts!");
    }

    inline uint256_t create2_v(
      const uint256_t x0,
      const uint256_t x1,
      const uint256_t x2,
      const uint256_t x3)
    {
      throw Exception(
        ET::notImplemented,
        "Specialized Executor cannot CREATE2 new contracts!");
    }

    inline uint256_t call_v(
      const uint256_t gaslimit,
      const uint256_t addr,
      const uint256_t value,
      const uint256_t offIn,
      const uint256_t sizeIn,
      const uint256_t offOut,
      const uint256_t sizeOut)
    {
      return do_call(
        CALL, addr, gaslimit, value, offIn, sizeIn, offOut, sizeOut);
    }

    inline uint256_t callcode_v(
      const uint256_t gaslimit,
      const uint256_t addr,
      const uint256_t value,
      const uint256_t offIn,
      const uint256_t sizeIn,
      const uint256_t offOut,
      const uint256_t sizeOut)
    {
      return do_call(
        CALLCODE, addr, gaslimit, value, offIn, sizeIn, offOut, sizeOut);
    }

    inline uint256_t delegatecall_v(
      const uint256_t gaslimit,
      const uint256_t addr,
      const uint256_t offIn,
      const uint256_t sizeIn,
      const uint256_t offOut,
      const uint256_t sizeOut)
    {
      return do_call(
        DELEGATECALL, addr, gaslimit, 0, offIn, sizeIn, offOut, sizeOut);
    }

    inline uint256_t staticcall_v(
      const uint256_t gaslimit,
      const uint256_t addr,
      const uint256_t offIn,
      const uint256_t sizeIn,
      const uint256_t offOut,
      const uint256_t sizeOut)
    {
      return do_call(
        STATICCALL, addr, gaslimit, 0, offIn, sizeIn, offOut, sizeOut);
    }

    uint256_t do_call(
      const Opcode op,
      const uint256_t _addr,
      const uint256_t gaslimit,
      const uint256_t value,
      const uint256_t offIn,
      const uint256_t sizeIn,
      const uint256_t offOut,
      const uint256_t sizeOut);
  };
} // namespace eevm
