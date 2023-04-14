#pragma once

#include "eEVM/address.h"
#include "eEVM/bigint.h"

namespace eevm::fuzz
{
  using namespace intx;

  const uint8_t NUM_SENDER = 6;
  // we pre-define a certain set of sender addresses, these are all considered
  // untrusted users or attackers.
  constexpr eevm::Address tx_sender[NUM_SENDER] = {
    0xc04689c0c5d48cec7275152b3026b53f6f78d03d_u256,
    0xc1af1d7e20374a20d4d3914c1a1b0ddfef99cc61_u256,
    0xc2018c3f08417e77b94fb541fed2bf1e09093edd_u256,
    0xc3cf2af7ea37d6d9d0a23bdf84c71e8c099d03c2_u256,
    0xc4b803ea8bc30894cc4672a9159ca000d377d9a3_u256,
    0xc5442b23ea5ca66c3441e62bf6456f010646ae94_u256,
  };
  // address of the contract, i.e., the receiver of transactions
  inline eevm::Address tx_receiver =
    0xdeadbeefc5d48cec7275152b3026b53f6f78d03d_u256;
  // the address of the "owner" or creator of the contract, the fuzzer may
  // choose to create transactions originating from this address.
  constexpr eevm::Address contract_creator =
    0xcc079239d48f83be71dbbd18487f4acc279ee929_u256;
  // the collaborator is an existing address (with code)
  constexpr eevm::Address contract_collaborator =
    0xcf7c6611373327e75f8ef1beef8227afb89816dd_u256;

  constexpr eevm::Address default_tx_origin = 
    0xe0af163ebeab9bb2968fee294a22ca4fe2fa3a06_u256;
}
