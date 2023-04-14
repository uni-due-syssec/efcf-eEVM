// auto-generated by evm2cpp

#pragma once

#include "eEVM/SpecializedProcessorFactory.h"

using namespace intx;

namespace eevm
{
  class EVM2CPP_asserter : public SpecializedProcessor
  {
    using SpecializedProcessor::SpecializedProcessor;

  private:
    static const std::string _contract_name;
    static const DerivedRegister<EVM2CPP_asserter> reg;

  public:
    void dispatch() override;
    const Code& bytecode() override;
    const Code& constructor_bytecode() override;
    const Code& constructor_args() override;
    const std::string& name() override;

    std::unique_ptr<SpecializedProcessor> duplicate() override
    {
      return std::make_unique<EVM2CPP_asserter>();
    };
  };
}
