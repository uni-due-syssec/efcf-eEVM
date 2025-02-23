// auto-generated by evm2cpp

#include "eEVM/evm2cpp/contracts/nop.h"

#include "eEVM/fuzz/tracecomp.hpp"

// this is generated code and we might have emitted some variables/labels that
// are not actually used anymore
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-label"

const eevm::Code _contract_bytecode = {
  0x00, /* [0'0x0] STOP */
  0x00, /* [1'0x1] STOP */
  0x00, /* [2'0x2] STOP */
  0x00, /* [3'0x3] STOP */
  0x00, /* [4'0x4] STOP */
  0x00, /* [5'0x5] STOP */
  0x00, /* [6'0x6] STOP */
  0x00, /* [7'0x7] STOP */
  0x00, /* [8'0x8] STOP */
  0x00, /* [9'0x9] STOP */
  0x00, /* [10'0xa] STOP */
};

const eevm::Code& eevm::EVM2CPP_nop::bytecode()
{
  return _contract_bytecode;
}

const std::string eevm::EVM2CPP_nop::_contract_name = "nop";
[[maybe_unused]] const eevm::DerivedRegister<eevm::EVM2CPP_nop>
  eevm::EVM2CPP_nop::reg{};
const std::string& eevm::EVM2CPP_nop::name()
{
  return _contract_name;
}

// interned globals

// code
void eevm::EVM2CPP_nop::dispatch()
{
  static void* _JUMP_TABLE_ARR[] = {
    &&_evm_start,

    &&__invld,
    &&__invld,
    &&__invld,
    &&__invld,
    &&__invld,
    &&__invld,
    &&__invld,
    &&__invld,
    &&__invld,
    &&__invld,

  };

  goto _evm_start;

__invld:
  throw Exception(ET::illegalInstruction, "EVM-level invalid jump target");

#define JUMP(target) \
  { \
    uint64_t _jump_target = static_cast<uint64_t>(target); \
    if (_jump_target < (std::size(_JUMP_TABLE_ARR))) \
    { \
      goto* _JUMP_TABLE_ARR[_jump_target]; \
    } \
    else \
    { \
      goto __invld; \
    } \
  }

_evm_start:
pc_0 : { /* <============ */
  on_bb_start(0);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_1 : { /* <============ */
  on_bb_start(1);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_2 : { /* <============ */
  on_bb_start(2);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_3 : { /* <============ */
  on_bb_start(3);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_4 : { /* <============ */
  on_bb_start(4);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_5 : { /* <============ */
  on_bb_start(5);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_6 : { /* <============ */
  on_bb_start(6);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_7 : { /* <============ */
  on_bb_start(7);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_8 : { /* <============ */
  on_bb_start(8);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_9 : { /* <============ */
  on_bb_start(9);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
pc_a : { /* <============ */
  on_bb_start(10);
  /* STOP */
  stop_v();
  goto exit_label;

  /* BB finalizer */
  /* no stack sets */
  /* no pops at end */
  /* no BB returns */
}
exit_label:
  return;
}

const eevm::Code _constructor_bytecode = {};

const eevm::Code& eevm::EVM2CPP_nop::constructor_bytecode()
{
  return _constructor_bytecode;
}

// TODO: update this if you want constructor arguments.
const eevm::Code _constructor_args = {};

const eevm::Code& eevm::EVM2CPP_nop::constructor_args()
{
  return _constructor_args;
}
