#pragma once
#include "eEVM/bigint.h"
#include "eEVM/simple/simpleaccount.h"
#include "eEVM/simple/simpleglobalstate.h"
#include "eEVM/simple/simplestorage.h"

namespace eevm
{
  bool dump_simplestate_msgpack(
    eevm::SimpleGlobalState* gs, const std::string& fname);
  bool load_simplestate_msgpack(
    const std::string& path, eevm::SimpleGlobalState* state);
}
