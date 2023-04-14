# Future Improvements

Some notes on things to improve in the future:

### Performance

* [ ] Update the vendored intx library in `./3rdparty`
* [x] Integrate mimalloc as default allocator via cmake; preloading shows some
      performance gains.
* [x] Disable some of the de-optimizations in the intx library - they might not
      be necessary anymore due to the opcode hooks in `tracecomp.hpp` -
      non-EVM intx operators would gain performance (e.g., in the balances
      oracle).
* [x] Blockchain state snapshotting and access is not as fast as it could be
      for large imported states. Maybe use some of the actual Trie
      implementation from other Ethereum clients?  Maybe use some other map
      implementation instead of STL (e.g., swisstable)?
        * We switched to a swisstable-based hashmap implementation and added a
          backing store mode to global state.


### Fuzzing

* [x] Disable loading autodict - mostly useless because we do the same with
      evm2cpp one abstraction level higher and more accurate.


### Features

* [x] Change the fuzzcase format to also include a byte-sized receiver selector
      -> this would allow the fuzzer to choose the "to" field of a transaction.
      Adapt the harness to select from a list of receivers.
      ~~Additionally, the mutator must be adapted accordingly to support mutating for
      multiple contracts at once.~~ also done
* [ ] Implement the crypto operations available through the special
      pre-compiled smart contracts. Should allow properly executing some of the
      more exotic contracts.
