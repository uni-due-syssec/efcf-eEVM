// Copyright (c) Microsoft Corporation. All rights reserved.
// Copyright (c) Michael Rodler. All rights reserved.
// Licensed under the MIT License.

#include "eEVM/evm2cpp/contracts.h"
#include "eEVM/evm2cpp/contracts/crowdsale.h"
#include "eEVM/opcode.h"
#include "eEVM/processor.h"
#include "eEVM/simple/simpleglobalstate.h"

#include <fmt/format_header_only.h>
#include <fstream>
#include <iostream>

static inline int char2int(char input)
{
  if (input >= '0' && input <= '9')
    return input - '0';
  if (input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if (input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  throw std::invalid_argument("Invalid input string");
}

int main(int argc, char** argv)
{
  // srand(time(NULL));

  // Create random addresses for sender and contract
  std::vector<uint8_t> raw_address(20);
  std::generate(
    raw_address.begin(), raw_address.end(), []() { return rand(); });
  const eevm::Address sender =
    eevm::from_big_endian(raw_address.data(), raw_address.size());

  std::generate(
    raw_address.begin(), raw_address.end(), []() { return rand(); });
  const eevm::Address to =
    eevm::from_big_endian(raw_address.data(), raw_address.size());

  std::vector<uint8_t> input_bytes = {};

  if (argc == 3 && std::string(argv[1]) == "-f")
  {
    ifstream input_file(argv[1]);
    if (!input_file)
    {
      std::cerr << "failed to open file: " << argv[1] << " # " << std::endl;
      return -1;
    }
    std::istream_iterator<uint8_t> start(input_file), end;
    std::vector<uint8_t> r(start, end);
  }
  else if (argc == 2)
  {
    char* x = argv[1];
    while (x[0] != '\0' && x[1] != 0)
    {
      uint8_t b = char2int(x[0]) * 16 + char2int(x[1]);
      x += 2;
      input_bytes.push_back(b);
    }
  }

  std::cout << "Constructing global state" << std::endl;
  std::cout << "input bytes: " << eevm::to_hex_string(input_bytes) << std::endl;
  std::cout << "from: " << eevm::to_hex_string(sender) << std::endl;
  std::cout << "to: " << eevm::to_hex_string(to) << std::endl;

  // Create global state
  eevm::SimpleGlobalState gs;

  // Create code
  const eevm::Code code = eevm::EVM2CPP_crowdsale::bytecode();
  std::cout << "bytecode: " << eevm::to_hex_string(code) << std::endl;

  // Deploy contract to global state
  const eevm::AccountState contract = gs.create(to, 0, code);

  // Create transaction
  eevm::NullLogHandler ignore;
  eevm::Transaction tx(sender, ignore);

  // Create processor
  eevm::Processor p(gs);

  // Create Trace
  eevm::Trace tr;

  std::cout << "Running specialized code" << std::endl;

  // Execute code. All execution is associated with a transaction. This
  // transaction is called by sender, executing the code in contract
  const eevm::ExecResult e = p.runSpecialized<eevm::EVM2CPP_crowdsale>(
    tx, /* transaction*/
    sender, /* caller */
    contract, /* AccounState of contract */
    input_bytes, /* input as bytes */
    0 /* call value */,
    &tr /* record trace*/);

  std::cout << "EVM Code done" << std::endl;

  std::cout << fmt::format("return code: {}", (size_t)e.er) << std::endl
            << "Exception: " << e.exmsg << std::endl
            << "last PC: " << e.last_pc << std::endl;

  // Create string from response data, and print it
  if (e.output.size() > 0 && e.output.data() != nullptr)
  {
    // const std::string response(reinterpret_cast<const
    // char*>(e.output.data()));
    std::cout << "output: " << eevm::to_hex_string(e.output) << std::endl;
  }
  else
  {
    std::cout << "output: None" << std::endl;
  }

  // Check the response
  if (e.er != eevm::ExitReason::returned)
  {
    tr.print_last_n(std::cout, 10);
    return 1;
  }

  return 0;
}
