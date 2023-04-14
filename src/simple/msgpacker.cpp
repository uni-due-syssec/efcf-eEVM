#include "eEVM/simple/msgpacker.h"

#include "eEVM/account.h"
#include "eEVM/bigint.h"
#include "eEVM/block.h"
#include "eEVM/util.h"
#include "mpack.h"
#include "mpack/src/mpack/mpack.h"

#include <cstdint>

/* mpack schema
 * [
 *  number u64,
 *  difficulty u64,
 *  gas_limit u64,
 *  timestamp u64,
 *  coinbase u256,
 *  # accounts
 *  {
 *    address u256 : [
 *      balance u256,
 *      nonce u64,
 *      code bytes,
 *      # storage
 *      {
 *        key u256 : value u256,
 *        ...
 *      }
 *    ]
 *    ...
 *  }
 * ]
 *
 */

uint256_t mpack_expect_u256(mpack_reader_t* reader)
{
  mpack_expect_bin_size(reader, 32);
  const uint8_t* data =
    reinterpret_cast<const uint8_t*>(mpack_read_bytes_inplace(reader, 32));
  uint256_t res = 0;
  if (data != nullptr) [[likely]]
    res = eevm::from_big_endian(data);
  mpack_done_bin(reader);
  return res;
}

void mpack_write_u256(mpack_writer_t* writer, const uint256_t& value)
{
  uint8_t buf[32];
  eevm::to_big_endian(value, &buf[0]);
  mpack_write_bin(writer, reinterpret_cast<char*>(&buf[0]), 32);
}

eevm::Code mpack_expect_code(mpack_reader_t* reader)
{
  size_t len = mpack_expect_bin(reader);
  eevm::Code code;
  code.resize(len);
  mpack_read_bytes(reader, reinterpret_cast<char*>(code.data()), len);
  mpack_done_bin(reader);
  return code;
}

void mpack_write_code(mpack_writer_t* writer, const eevm::Code& code)
{
  if (code.size() > 0) {
    mpack_write_bin(
      writer, reinterpret_cast<const char*>(code.data()), code.size());
  } else {
    mpack_write_bin(writer, nullptr, 0);
  }
}

bool eevm::load_simplestate_msgpack(
  const std::string& path, eevm::SimpleGlobalState* state)
{
  // Initialize a reader from a file
  mpack_reader_t reader;
  mpack_reader_init_file(&reader, path.c_str());
  if (mpack_reader_error(&reader) != mpack_ok)
  {
    return false;
  }

  mpack_expect_array_match(&reader, 6);
  // read the block header
  eevm::Block b;
  b.number = mpack_expect_u64(&reader);
  b.difficulty = mpack_expect_u64(&reader);
  b.gas_limit = mpack_expect_u64(&reader);
  b.timestamp = mpack_expect_u64(&reader);
  b.coinbase = mpack_expect_u256(&reader);
  state->set_current_block(b);

  // read the accounts
  size_t num_accounts = mpack_expect_map(&reader);
  for (size_t acct_idx = 0;
       acct_idx < num_accounts && mpack_reader_error(&reader) == mpack_ok;
       acct_idx++)
  {
    uint256_t address = mpack_expect_u256(&reader);
    if (mpack_reader_error(&reader) == mpack_ok)
    {
      mpack_expect_array_match(&reader, 4);
      if (mpack_reader_error(&reader) != mpack_ok)
        std::cerr << "[mpacker] failed to read account array for" << eevm::to_hex_string(address) << std::endl;

      uint256_t balance = mpack_expect_u256(&reader);
      eevm::Account::Nonce nonce = mpack_expect_u64(&reader);
      eevm::Code code = mpack_expect_code(&reader);
      if (mpack_reader_error(&reader) != mpack_ok)
        std::cerr << "[mpacker] failed to read code for " << eevm::to_hex_string(address) << std::endl;

      auto acct = state->create(address, balance, code, nonce);

      // storage
      size_t num_storage = mpack_expect_map(&reader);
      size_t stor_idx = 0;
      for (;
           stor_idx < num_storage && mpack_reader_error(&reader) == mpack_ok;
           stor_idx++)
      {
        uint256_t k = mpack_expect_u256(&reader);
        if (mpack_reader_error(&reader) != mpack_ok)
          std::cerr << "[mpacker] failed to read storage key for " << eevm::to_hex_string(address) << " after " << stor_idx << " expected " << num_storage << std::endl;
        uint256_t v = mpack_expect_u256(&reader);
        if (mpack_reader_error(&reader) != mpack_ok)
          std::cerr << "[mpacker] failed to read storage value for " << eevm::to_hex_string(address) << " after " << stor_idx << " expected " << num_storage << std::endl;
        if (v != 0)
        {
          acct.st.store(k, v);
        }
      }
      if (mpack_reader_error(&reader) != mpack_ok)
        std::cerr << "[mpacker] failed to read storage for " << eevm::to_hex_string(address) << " after " << stor_idx << " expected " << num_storage << std::endl;
      mpack_done_map(&reader);
      // storage done

      mpack_done_array(&reader);
      // account data done
    }
  }
  if (mpack_reader_error(&reader) != mpack_ok)
    std::cerr << "[mpacker] failed at reading the accounts map" << std::endl;
  // accounts done
  mpack_done_map(&reader);

  // done with the top level array
  mpack_done_array(&reader);
  if (mpack_reader_error(&reader) != mpack_ok)
    std::cerr << "[mpacker] failed at the end?" << std::endl;

  mpack_error_t error = mpack_reader_destroy(&reader);
  return error == mpack_ok;
}

bool eevm::dump_simplestate_msgpack(
  eevm::SimpleGlobalState* gs, const std::string& fname)
{
  mpack_writer_t writer;
  mpack_writer_init_filename(&writer, fname.c_str());

  auto block = gs->get_current_block();
  mpack_start_array(&writer, 6);

  // write the block header
  mpack_write(&writer, block.number);
  mpack_write(&writer, block.difficulty);
  mpack_write(&writer, block.gas_limit);
  mpack_write(&writer, block.timestamp);
  mpack_write_u256(&writer, block.coinbase);

  // write the accounts
  mpack_start_map(&writer, gs->num_accounts());

  for (auto& acct : gs->accounts)
  {
    // write the key, which is the account address
    mpack_write_u256(&writer, acct.first);
    // write the value, aka the account data array
    mpack_start_array(&writer, 4);
    mpack_write_u256(&writer, acct.second.first.get_balance());
    mpack_write_u64(&writer, acct.second.first.get_nonce());
    mpack_write_code(&writer, acct.second.first.get_code());

    // start writing storage map
    auto& storage = acct.second.second;
    size_t st_size = storage.size();
    mpack_start_map(&writer, st_size);
    for (auto& kv : storage.s)
    {
      mpack_write_u256(&writer, kv.first);
      mpack_write_u256(&writer, kv.second);
    }
    // if we have a backing store; also dump it's contents
    if (storage.b)
    {
      for (auto& kv : storage.b->s)
      {
        if (!storage.s.count(kv.first))
        {
          mpack_write_u256(&writer, kv.first);
          mpack_write_u256(&writer, kv.second);
        }
      }
    }
    // finish storage map
    mpack_finish_map(&writer);

    // finish account data array
    mpack_finish_array(&writer);
  }

  // finish accounts map
  mpack_finish_map(&writer);

  // finish top-level array
  mpack_finish_array(&writer);

  return mpack_writer_destroy(&writer) == mpack_ok;
}
