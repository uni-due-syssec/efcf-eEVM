#pragma once

#include "processor-impl.h"

namespace eevm
{
  /**
   * Creates a new instance of a SpecializedProcessor, used during self-registration.
   *
   * @tparam T name of the contract, used to call its constructor
   * @return a pointer to the SpecializedProcessor instance
   */
  template<typename T>
  SpecializedProcessor* createT() { return new T{}; }


  /**
   * This factory is used to generate instances of SpecializedProcessors. The
   * processors first register themselves by storing pointers to their constructors.
   * After initialization, the SpecializedProcessors are accessed by pointers.
   */
  class SpecializedProcessorFactory
  {

  private:

    /// Pointer to a heap allocated vector that stores function pointers to constructors of SpecializedProcessors.
    inline static std::vector<SpecializedProcessor*(*)()>* sp_constructor_list;

    /// List of pointers to initialized SpecializedProcessors
    inline static std::vector<SpecializedProcessor*> specialized_processors;

  public:

    /**
     * Returns the size of the vector that stores the function pointers.
     */
    static int getListSize() { return static_cast<int>(sp_constructor_list->size()); }

    /**
     * Getter for the vector that holds the instances of SpecializedProcessors.
     *
     * @return vector as reference
     */
    static std::vector<SpecializedProcessor*>& getSpecializedProcessors() { return specialized_processors; }

    /**
     * Creates a SpecializedProcessor which function pointer to its constructor
     * is stored at a given index in the corresponding vector.
     *
     * @param n the index where the function pointer is located
     * @return a pointer to an instance of the created SpecializedProcessor
     */
    static SpecializedProcessor* createInstance(int n)
    {
      auto i{0};
      for (const auto& it : *sp_constructor_list) {
        if (i == n)
          return it();
        ++i;
      }
      return nullptr;
    }

  protected:

    /**
     * Getter for the vector that holds the function pointers.
     *
     * @return a pointer to the vector of constructor function pointers
     */
    static std::vector<SpecializedProcessor*(*)()>* getList()
    {
      if(!sp_constructor_list)
        sp_constructor_list = new std::vector<SpecializedProcessor*(*)()>{};
      return sp_constructor_list;
    }
  };


  /**
   * This class is used to automatically register SpecializedProcessors in the
   * factory.
   *
   * @tparam T SpecializedProcessor
   */
  template<typename T>
  class DerivedRegister : SpecializedProcessorFactory
  {
  public:

    /**
     * Constructor that registers its SpecializedProcessor. Has to be called in
     * static context.
     */
    explicit DerivedRegister() {
      getList()->emplace_back(&createT<T>);
    }
  };
}
