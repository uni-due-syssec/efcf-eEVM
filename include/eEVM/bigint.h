// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include <intx/intx.hpp>
#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>

using uint256_t = intx::uint256;
using uint512_t = intx::uint512;

namespace intx
{
  // ostream operator allows easy printing. This should be contributed directly
  // to intx
  template <unsigned N>
  std::ostream& operator<<(std::ostream& o, const uint<N>& n)
  {
    const auto fmt_flags = o.flags();
    const auto basefield = fmt_flags & std::ostream::basefield;
    const auto showbase = fmt_flags & std::ostream::showbase;

    switch (basefield)
    {
      case (std::ostream::hex): {
        if (showbase)
        {
          o << "0x";
        }
        o << to_string(n, 16);
        break;
      }

      case (std::ostream::oct): {
        if (showbase)
        {
          o << "0";
        }
        o << to_string(n, 8);
        break;
      }

      default: {
        o << to_string(n, 10);
        break;
      }
    }
    return o;
  }

  // to/from json converters
  template <unsigned N>
  void to_json(nlohmann::json& j, const uint<N>& n)
  {
    std::stringstream ss;
    ss << "0x" << to_string(n, 16);
    j = ss.str();
  }

  template <unsigned N>
  void from_json(const nlohmann::json& j, uint<N>& n)
  {
    if (!j.is_string())
    {
      throw std::runtime_error(
        "intx numbers can only be parsed from hex-string");
    }

    const auto s = j.get<std::string>();
    n = from_string<uint<N>>(s);
  }
}

namespace eevm {
  struct Uint256Hasher
  {
    std::size_t operator()(uint256_t const& k) const
    {
      using std::hash;
      using std::size_t;

      // https://www.boost.org/doc/libs/1_55_0/doc/html/hash/reference.html#boost.hash_combine
      size_t seed = 0;
      seed ^=
        hash<uint64_t>{}(k.hi.hi) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
      seed ^=
        hash<uint64_t>{}(k.hi.lo) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
      seed ^=
        hash<uint64_t>{}(k.lo.hi) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
      seed ^=
        hash<uint64_t>{}(k.lo.lo) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

      return seed;
    }
  };
}

#include <parallel_hashmap/phmap_utils.h> // minimal header providing phmap::HashState()

namespace std
{
  // inject specialization of std::hash for into namespace std
  // ---------------------------------------------------------
  template <>
  struct hash<uint256_t>
  {
    std::size_t operator()(uint256_t const& u) const
    {
      return phmap::HashState().combine(0, u.hi.hi, u.hi.lo, u.lo.hi, u.lo.lo);
    }
  };
}


