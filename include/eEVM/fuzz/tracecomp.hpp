#pragma once
#include "eEVM/bigint.h"
#include "eEVM/opcode.h"

#include <algorithm> // std::min

#ifdef __AFL_COMPILER

// when using AFL++ LTO mode, we can get a unique coverage map index for every
// call to this function.
extern "C"
{
  uint8_t* __afl_get_coverage_pointer(uint32_t id);
  uint8_t* __afl_get_coverage_array(uint32_t id, size_t count);
}

// the following inline hooks add explicit comparison progress to the uint256
// comparison operators. The idea is that with these hooks, AFL++ can
// distinguish better when parts of a comparison are solved or not.

inline int __eq_compare_ctx(const uint256_t a, const uint256_t b, uint8_t* ctxt)
{
  if ((a.lo.lo == 0 && b.lo.lo == 0) || a.lo.lo == b.lo.lo)
  {
    if (a.lo.lo != 0)
    {
      ctxt[0] <<= 1;
      ctxt[0] |= 1;
    }
    if ((a.lo.hi == 0 && b.lo.hi == 0) || a.lo.hi == b.lo.hi)
    {
      if (a.lo.hi != 0)
      {
        ctxt[1] <<= 1;
        ctxt[1] |= 1;
      }
      if ((a.hi.lo == 0 && b.hi.lo == 0) || a.hi.lo == b.hi.lo)
      {
        if (a.hi.lo != 0)
        {
          ctxt[2] <<= 1;
          ctxt[2] |= 1;
        }
        if ((a.hi.hi == 0 && b.hi.hi == 0) || a.hi.hi == b.hi.hi)
        {
          if (a.hi.hi != 0)
          {
            ctxt[3] <<= 1;
            ctxt[3] |= 1;
          }
          return 1;
        }
        else
        {
          return 0;
        }
      }
      else
      {
        return 0;
      }
    }
    else
    {
      return 0;
    }
  }
  return 0;
}

inline int __lt_compare_ctx(const uint256_t a, const uint256_t b, uint8_t* ctxt)
{
  if (a.hi.hi < b.hi.hi)
  {
    return 1;
  }

  if (a.hi.hi == b.hi.hi)
  {
    if (a.hi.hi != 0)
    {
      ctxt[0] <<= 1;
      ctxt[0] |= 1;
    }

    if (a.hi.lo < b.hi.lo)
    {
      return 1;
    }
    else if (a.hi.lo == b.hi.lo)
    {
      if (a.hi.lo != 0)
      {
        ctxt[1] <<= 1;
        ctxt[1] |= 1;
      }

      if (a.lo.hi < b.lo.hi)
      {
        return 1;
      }
      else if (a.lo.hi == b.lo.hi)
      {
        if (a.lo.hi != 0)
        {
          ctxt[2] <<= 1;
          ctxt[2] |= 1;
        }
        if (a.lo.lo < b.lo.lo)
        {
          ctxt[3] <<= 1;
          ctxt[3] |= 1;
          return 1;
        }

        return 0;
      }
      else
      {
        return 0;
      }
    }
    else
    {
      return 0;
    }
  }

  return 0;
}

inline int __gt_compare_ctx(const uint256_t a, const uint256_t b, uint8_t* ctxt)
{
  if (a.hi.hi > b.hi.hi)
  {
    return 1;
  }

  if (a.hi.hi == b.hi.hi)
  {
    if (a.hi.hi != 0)
    {
      ctxt[0] <<= 1;
      ctxt[0] |= 1;
    }

    if (a.hi.lo > b.hi.lo)
    {
      return 1;
    }
    else if (a.hi.lo == b.hi.lo)
    {
      if (a.hi.lo != 0)
      {
        ctxt[1] <<= 1;
        ctxt[1] |= 1;
      }

      if (a.lo.hi > b.lo.hi)
      {
        return 1;
      }
      else if (a.lo.hi == b.lo.hi)
      {
        if (a.lo.hi != 0)
        {
          ctxt[2] <<= 1;
          ctxt[2] |= 1;
        }
        if (a.lo.lo > b.lo.lo)
        {
          ctxt[3] <<= 1;
          ctxt[3] |= 1;
          return 1;
        }

        return 0;
      }
      else
      {
        return 0;
      }
    }
    else
    {
      return 0;
    }
  }

  return 0;
}

inline int __slt_compare_ctx(
  const uint256_t a, const uint256_t b, uint8_t* ctxt)
{
  if (a == b)
    return 0;

  const auto negative_a = (a >> 255) ? true : false;
  const auto negative_b = (b >> 255) ? true : false;

  if (negative_a == negative_b)
  {
    return __lt_compare_ctx(a, b, ctxt);
  }
  else
  {
    ctxt[4] <<= 1;
    ctxt[4] |= 1;
    if (negative_a)
    { // implied here (!negative_b)
      ctxt[5] <<= 1;
      ctxt[5] |= 1;
      return 1;
    }
    else
    {
      return 0;
    }
  }

  return 0;
}

inline int __sgt_compare_ctx(
  const uint256_t a, const uint256_t b, uint8_t* ctxt)
{
  if (a == b)
    return 0;

  const auto negative_a = (a >> 255) ? true : false;
  const auto negative_b = (b >> 255) ? true : false;

  if (negative_a == negative_b)
  {
    return __gt_compare_ctx(a, b, ctxt);
  }
  else
  {
    ctxt[4] <<= 1;
    ctxt[4] |= 1;
    if (!negative_a)
    { // implied here negative_b
      ctxt[5] <<= 1;
      ctxt[5] |= 1;
      return 1;
    }
    else
    {
      return 0;
    }
  }

  return 0;
}

inline void __force_afl_cmp_cov(
  const uint8_t opcode, const uint256_t a, const uint256_t b, uint8_t* ctxt)
{
  switch (opcode)
  {
    case eevm::Opcode::EQ:
      __eq_compare_ctx(a, b, ctxt);
      break;
    case eevm::Opcode::LT:
      __lt_compare_ctx(a, b, ctxt);
      break;
    case eevm::Opcode::SLT:
      __slt_compare_ctx(a, b, ctxt);
      break;
    case eevm::Opcode::GT:
      __gt_compare_ctx(a, b, ctxt);
      break;
    case eevm::Opcode::SGT:
      __sgt_compare_ctx(a, b, ctxt);
      break;
    default:
      break;
  }
}

// place hooks on the comparison opcode handlers

#  define eq_v(a, b) \
    this->eq_v(a, b); \
    { \
      uint8_t* __AFL_CTX = __afl_get_coverage_array(0, 4); \
      *__afl_get_coverage_pointer(0) = __eq_compare_ctx(a, b, __AFL_CTX); \
    };

#  define lt_v(a, b) \
    this->lt_v(a, b); \
    { \
      uint8_t* __AFL_CTX = __afl_get_coverage_array(0, 4); \
      *__afl_get_coverage_pointer(0) = __lt_compare_ctx(a, b, __AFL_CTX); \
    };

#  define gt_v(a, b) \
    this->gt_v(a, b); \
    { \
      uint8_t* __AFL_CTX = __afl_get_coverage_array(0, 4); \
      *__afl_get_coverage_pointer(0) = __gt_compare_ctx(a, b, __AFL_CTX); \
    };

#  define slt_v(a, b) \
    this->slt_v(a, b); \
    { \
      uint8_t* __AFL_CTX = __afl_get_coverage_array(0, 6); \
      *__afl_get_coverage_pointer(0) = __slt_compare_ctx(a, b, __AFL_CTX); \
    };

#  define sgt_v(a, b) \
    this->sgt_v(a, b); \
    { \
      uint8_t* __AFL_CTX = __afl_get_coverage_array(0, 6); \
      *__afl_get_coverage_pointer(0) = __sgt_compare_ctx(a, b, __AFL_CTX); \
    };

// the idea of this hook is to make AFL++ notice that a basic block is executed
// at a different level in the call stack. This should be useful to detect
// reentrancy issues faster, because it allows to distinguish different ways of
// calling a function of a contract. However, we only distinguish the first 8
// call-depths. This should be enough.
#  define MAX_CALL_DEPTH_TO_STORE_IN_AFL_COV ((uint32_t)7)
#  define on_bb_start(pc) \
    this->on_bb_start(pc); \
    { \
      uint32_t sz = ctxts->size(); \
      uint8_t x = (uint8_t)std::min(sz, MAX_CALL_DEPTH_TO_STORE_IN_AFL_COV); \
      uint8_t* __AFL_CTX = __afl_get_coverage_array(0, 8); \
      __AFL_CTX[x] += 1; \
    }

#endif

#ifdef ENABLE_FUZZING

#  include "eEVM/fuzz/tracing.hpp"

// helper macro for evm2cpp generated contracts.
#  ifndef TRACE_COMP
#    define TRACE_COMP(opcode, arg0, arg1) \
      eevm::fuzz::dump_compare(ctxt->get_pc(), opcode, arg0, arg1);
#  endif
#else // not ENABLE_FUZZING
#  define TRACE_COMP(opcode, arg0, arg1) ;
#endif // ENABLE_FUZZING
