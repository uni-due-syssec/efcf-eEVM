//
// Original License:
//===- FuzzedDataProvider.h - Utility header for fuzz targets ---*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//

#pragma once

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

class EthFuzzDataProvider
{
private:
  EthFuzzDataProvider(const EthFuzzDataProvider&) = delete;
  EthFuzzDataProvider& operator=(const EthFuzzDataProvider&) = delete;

  const uint8_t* const base_ptr_;
  const uint8_t* data_ptr_;
  size_t remaining_bytes_;

  void CopyAndAdvance(void* destination, size_t num_bytes);
  void Advance(size_t num_bytes);
  void Withdraw(size_t num_bytes);

  template <typename T>
  std::vector<T> ConsumeBytes(size_t size, size_t num_bytes);

public:
  EthFuzzDataProvider(const uint8_t* data, size_t size) :
    base_ptr_(data), data_ptr_(data), remaining_bytes_(size)
  {}
  ~EthFuzzDataProvider() = default;

  template <typename T>
  std::optional<T> ConsumeType();
  template <typename T>
  std::optional<std::vector<T>> ConsumeBytesExact(size_t num_bytes);
  template <typename T>
  std::vector<T> ConsumeBytes(size_t num_bytes);
  template <typename T>
  std::vector<T> ConsumeRemainingBytes();

  template <typename T>
  bool UnConsumeType(T arg);

  bool UnConsumeBytes(size_t num);

  // Reports the remaining bytes available for fuzzed input.
  size_t remaining_bytes()
  {
    return remaining_bytes_;
  }
};

// Private methods.
inline void EthFuzzDataProvider::CopyAndAdvance(
  void* destination, size_t num_bytes)
{
  std::memcpy(destination, data_ptr_, num_bytes);
  Advance(num_bytes);
}

inline void EthFuzzDataProvider::Advance(size_t num_bytes)
{
  if (num_bytes > remaining_bytes_)
    abort();

  data_ptr_ += num_bytes;
  remaining_bytes_ -= num_bytes;
}

inline void EthFuzzDataProvider::Withdraw(size_t num_bytes)
{
  data_ptr_ -= num_bytes;
  std::ptrdiff_t diff = data_ptr_ - base_ptr_;
  if (diff < 0)
  {
    abort();
  }
  remaining_bytes_ += num_bytes;
}

template <typename T>
std::vector<T> EthFuzzDataProvider::ConsumeBytes(size_t size, size_t num_bytes)
{
  static_assert(sizeof(T) == sizeof(uint8_t), "Incompatible data type.");

  // The point of using the size-based constructor below is to increase the
  // odds of having a vector object with capacity being equal to the length.
  // That part is always implementation specific, but at least both libc++ and
  // libstdc++ allocate the requested number of bytes in that constructor,
  // which seems to be a natural choice for other implementations as well.
  // To increase the odds even more, we also call |shrink_to_fit| below.
  std::vector<T> result(size);
  if (size == 0)
  {
    if (num_bytes != 0)
      abort();
    return result;
  }

  CopyAndAdvance(result.data(), num_bytes);

  // Even though |shrink_to_fit| is also implementation specific, we expect it
  // to provide an additional assurance in case vector's constructor allocated
  // a buffer which is larger than the actual amount of data we put inside it.
  result.shrink_to_fit();
  return result;
}

// Returns a std::vector containing |num_bytes| of input data. If fewer than
// |num_bytes| of data remain, returns a shorter std::vector containing all
// of the data that's left. Can be used with any byte sized type, such as
// char, unsigned char, uint8_t, etc.
template <typename T>
std::vector<T> EthFuzzDataProvider::ConsumeBytes(size_t num_bytes)
{
  num_bytes = std::min(num_bytes, remaining_bytes_);
  return ConsumeBytes<T>(num_bytes, num_bytes);
}

// Returns a std::vector containing all remaining bytes of the input data.
template <typename T>
std::vector<T> EthFuzzDataProvider::ConsumeRemainingBytes()
{
  return ConsumeBytes<T>(remaining_bytes_);
}

template <typename T>
std::optional<std::vector<T>> EthFuzzDataProvider::ConsumeBytesExact(
  size_t num_bytes)
{
  if (num_bytes <= remaining_bytes_)
  {
    return std::optional<std::vector<T>>{ConsumeBytes<T>(num_bytes, num_bytes)};
  }
  else
  {
    return std::nullopt;
  }
}

template <typename T>
std::optional<T> EthFuzzDataProvider::ConsumeType()
{
  static_assert(std::is_pod<T>::value, "Type T must be POD");

  if (sizeof(T) <= remaining_bytes_)
  {
    T t;
    CopyAndAdvance(&t, sizeof(T));
    return std::optional<T>{t};
  }
  else
  {
    return std::nullopt;
  }
}

template <typename T>
bool EthFuzzDataProvider::UnConsumeType(T arg)
{
  static_assert(std::is_pod<T>::value, "Type T must be POD");
  Withdraw(sizeof(arg));
  return true;
}

inline bool EthFuzzDataProvider::UnConsumeBytes(size_t num)
{
  Withdraw(num);
  return true;
}
