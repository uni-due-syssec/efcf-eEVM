// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "eEVM/bigint.h"
#include "eEVM/storage.h"

#include <map>
#include <nlohmann/json.hpp>
#include <parallel_hashmap/phmap.h>
#include <unordered_map>

namespace eevm
{
  // opaque forward declaration
  class SimpleGlobalState;

  /**
   * Simple implementation of Storage
   */
  class SimpleStorage : public Storage
  {
    // using Map = std::map<uint256_t, uint256_t>;
    // using Map = std::unordered_map<uint256_t, uint256_t, Uint256Hasher>;
    using Map = phmap::flat_hash_map<uint256_t, uint256_t>;
    Map s;
    // const Map* b = nullptr;
    const SimpleStorage* b = nullptr;

  public:
    SimpleStorage() = default;
    SimpleStorage(const SimpleStorage& obj) : s(obj.s), b(obj.b)
    {
#if 0
      std::cerr << "cloning SimpleStorage(b[";
      if (obj.b) {
        std::cerr << obj.b->s.size() << ", b?" << (int)(obj.b->b != nullptr);
      } else {
        std::cerr << "(nullptr)";
      }
      std::cerr << "], s[" << obj.s.size() << "])" << std::endl;
#endif
    }
    SimpleStorage(const nlohmann::json& j);

    void remove_backing_store()
    {
      for (auto a : b->s)
      {
        if (!s.count(a.first))
        {
          s[a.first] = a.second;
        }
      }
      b = nullptr;
    }

    void set_backing_store(const SimpleStorage* obj)
    {
      if (b != nullptr)
      {
        remove_backing_store();
      }
      b = obj;
    }

    bool has_backing_store() const {
      return b != nullptr;
    }

    size_t size() const override {
      if (b == nullptr) 
        return s.size();
      else 
        return s.size() + b->size();
    }

    void store(const uint256_t& key, const uint256_t& value) override;
    uint256_t load(const uint256_t& key) const override;
    bool exists(const uint256_t& key) const;
    bool remove(const uint256_t& key) override;

    bool operator==(const SimpleStorage& that) const;

    friend void to_json(nlohmann::json&, const SimpleStorage&);
    friend void from_json(const nlohmann::json&, SimpleStorage&);
    
    friend bool dump_simplestate_msgpack(
      eevm::SimpleGlobalState* gs, const std::string& fname);
  };

  void to_json(nlohmann::json& j, const SimpleStorage& s);
  void from_json(const nlohmann::json& j, SimpleStorage& s);
} // namespace eevm
