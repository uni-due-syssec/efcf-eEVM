#pragma once

#include "eEVM/processor.h"
#include "eEVM/opcode.h"

namespace eevm
{
  namespace fuzz
  {
    void dump_compare(
      const uint64_t pc,
      const eevm::Opcode opcode,
      const uint256_t& a,
      const uint256_t& b);
    void dump_return(
      const uint64_t pc, const eevm::Opcode opcode, const eevm::Context* ctxt);
  }
}
