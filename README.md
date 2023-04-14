# eEVM/evm2cpp Fuzzing Harness

This is a fork of the Microsoft Research *Enclave EVM* adapted to:

* Provide the means to be specialized by the *evm2cpp* transpiler
* Provide a generic multi transaction fuzzing harness to fuzz smart contracts
* ~~Provide a differential testing harness between *evm2cpp*-specialized code and
  the generic EVM interpreter.~~ (the code is still there, but a bit outdated)

See the <a href="README.original.md">the original README.md</a> for details on the original project.

## Building

For easier handling, we provide a shell wrapper script to quickly build the
project (using `cmake` and `ninja` in the Background)

```
$ ./quick-build.sh
```

## Specialized Contracts

*evm2cpp* will specialize parts of the eEVM to a single contract, s.t., they can be run within the eEVM
framework. Transpiled EVM smart contracts will be placed in the directory
`./contracts` and additional header file in `./include/eEVM/evm2cpp/contracts`.
For fuzzing purposes we also write the ABI and a fuzzer-dictionary to
`./fuzz/abi/` and `./fuzz/dict/`, respectively.

Currently there are a couple of contracts, which are already transpiled, in this
repository:

* `nop` - does nothing
* `crowdsale` - contract vulnerable due to lack of access control 
* `harvey_baz` - showcases property-based fuzzing
* `Bank` - showcases multi-contract support; contract vulnerable to delegated reentrancy

For use with other contracts see the *evm2cpp* repository on how to translate a
contract to C++.


## Fuzzing Harness code

* <a href="./fuzz/multitx/main.cpp">`fuzz/multitx/main.cpp`</a> for the main fuzzing harness code
* <a href="./include/eEVM/fuzz/fuzzcase.hpp">`include/eEVM/fuzz/fuzzcase.hpp`</a> for the input format parser. This must be kept in sync with the parser/emitter of [the custom mutator](https://git.uni-due.de/uni-due-syssec/projects/smart-contract-fuzzing/ethmutator/-/blob/master/ethmutator/src/serializer.rs).


## Fuzzing

First we need to build the fuzzing harness and select the specialized smart
contract we want to use, e.g.,:

```
$ ./quick-build.sh afuzz crowdsale
```

...builds the harness with the compiler wrapper provided by *AFL++* and
selects the *crowdsale* contract for fuzzing.

Since you need to rebuild the whole project whenever you change the contract,
the quick-build scripts write fuzzing builds to `./fuzz/build/`.


### Launching a Fuzzer

In principal one can simply run a stock AFL++ on the `fuzz_multitx` harness binary.
However, for efficient fuzzing you will want to utilize our custom mutator, the evm2cpp-generated dictionary etc.
Take a loot at the script <a href="./fuzz/launch-aflfuzz.sh">`fuzz/launch-aflfuzz.sh`</a>, which launches a
one or more AFL++ instances on a given contract (control the number of AFL
instances with `FUZZ_CORES` environment variables).

For experimentation with the fuzzer we have some other scripts that allow easy
testing of the fuzzer in different configurations using tmux/tmuxp. There are
several options that control with what features the fuzzer is launched.

```
$ ./fuzz/interactive-aflfuzz.sh \
    --fuzzing-time 3600 --cores 8 \
    --bench-until-crash \
    crowdsale
```

There are multiple options that can be set via the environment variable for the
headless `./fuzz/launch-aflfuzz.sh` (and to some extent also the
`./fuzz/launch-libfuzzer.sh` script).


* `FUZZ_CORES` - number of cores to utilize for fuzzing
* `FUZZ_PLOT` - if set to 1 automatically run `afl-plot`
* `FUZZ_EVMCOV` - compute EVM-level basic block coverage after fuzzing.
* `IGNORE_ABI` - whether the ABI is ignored even if it can be auto-located
* `ABI_PATH` - override the path to the contract ABI(s)
* `FUZZ_PRINT_ENV_CONFIG` - set to `1` to print environment variables set
  before launching the fuzzer. Useful for debugging the launcher script.
* ...and several others. Just check the launcher scripts.

### Controlling the Fuzzing Harness

The fuzzing harness can be controlled with a variety of environment variables.

*Controlling the harness behavior at fuzz-time*

* `EVM_ALLOW_CREATOR_TX` - the creator of the contract (i.e., commonly the
  "owner" of the smart contract) will also issue transactions. Beware of false
  alarms here because the creator *will* do something stupid (i.e., transfer
  ownership of the contract to the attacker).
* `EVM_NO_INITIAL_ETHER` - by default the fuzzer is allowed to give the target
  contract an initial ether balance, mostly to simulate that there have been
  prior uses of the contract. Since forced ether sends are a thing this should
  not really be a problem for somewhat decent real world contracts. However, in
  some contrived example this could lead to a false alarms, so this is
  configurable.
* `EVM_ALLOW_INDIRECT_ETHER_TRANSFERS` - (*this is now the default!*) only report a bug if the sum of all
  the ether balances of the fuzzer-controlled accounts is bigger than the
  initial amount. Use this if your contract is "bank-like" and allows to
  transfer ether between accounts somehow. Token contracts that have a built-in
  exchange of Token to ether are a good candidate for this. In general this
  could miss some bugs and likely has a longer "time-to-bug". However, this
  setting should yield less false alarms for certain contracts.
* `EVM_IGNORE_LEAKING` - do not report a bug when leaking ether is discovered.
  This is useful for some token contracts, which have functionality to allow
  sending ether to an arbitrary address.
* `EVM_REPORT_DOS_SELFDESTRUCT` - report also Denial-of-Service (DoS)
  selfdestruct calls - i.e., the attacker cannot gain ether, but simply destroys
  the contract.
* `EVM_MOCK_ALL_CALLS` - Usually when calling a non-existing external address,
  the fuzzing harness will simply signal an error to the calling contract. When
  this flag is set, all external calls will be mocked by the fuzzer (this can
  easily lead to false positives when the contract expects a contract with a
  particular behavior at a fixed address).
* `EVM_NO_ABORT` - set to avoid any calls to `abort()` in the fuzzing harness
  -> no detected bugs, but useful for code coverage measurements
* `EVM_DISABLE_DETECTOR` - set to disable the built-in bug oracles, e.g., if
  you only want property-based fuzzing.
* `EVM_PROPERTY_PATH` - enable property-based fuzzing if set; must be a path to
  a file in the `.signatures` format output by the solidity compiler.
* `EVM_REPORT_EVENTS` - report a bug when one of multiple specific events are
  encountered during execution (e.g., the `AssertionFailed()` event).
* `EVM_REPORT_EVENTS_ONLY_TARGET` - whether to report a bug on all event
  occurrences or just on the ones produced by the main contract
* `EVM_LOG_TOPICS_PATH` - path to a file containing the hashes and names of the
  log topics to search for in the report events bug oracle.
* `EVM_REPORT_SOL_PANIC` - enable a bug oracle that checks for Solidity
  `Panic(uint256)` errors as return values to `revert`

*Change the way the initial state is constructred*

* `EVM_CREATE_TX_INPUT` - override the input given to the contract constructor
  call, including the constructor code.
* `EVM_CREATE_TX_ARGS` - override only the constructor arguments, not the
  constructor code.
* `EVM_TARGET_ADDRESS` - string that specifies the address of the target
  contract.
* `EVM_LOAD_STATE` - file path to a global state initializer json file. See
  `./fuzz/state.load.example.json` for an example of the file format.
* `EVM_TARGET_MULTIPLE_ADDRESSES` - enable multi-target fuzzing. This means the
  fuzzing harness will choose a receiver for each transaction based on this
  list. Also probably want to set `EVM_LOAD_STATE` to load a useful set of
  contracts.
    * **Important** you have to ensure the first target in this list matches
      `EVM_TARGET_ADDRESS` and is referring to your target contract.
      Otherwise the harness will execute unexpected code. You won't notice
      except for poor fuzzing results.
    * **Important** you need to set `ABI_PATH` such that it is a
      comma-separated list of paths to the contract ABIs in the same order as
      the target address list. Otherwise, the custom mutator will become
      confused. You won't notice except for poor fuzzing results.
    * What if your target creates new contracts in its constructor and you want
      to fuzz them? You don't know the address upfront, which you would need to
      pass in the address list. You can execute your fuzzing harness and let it
      dump its initial/end states to obtain the addresses that are present in
      the state (or locate the newly created contracts in the debug output of
      the harness). Then you can switch to multi-target fuzzing, as the address
      of the newly created contract should be deterministic.
  
*Debugging and evaluation*

* `EVM_DEBUG_PRINT` - enable verbose printing to stdout
* `EVM_COVERAGE_FILE` - save a simple EVM coverage format to this
  file (contains basic block addresses separated by newline).
* `EVM_DUMP_STATE` - e.g., `"./state"` - will dump the blockchain state at the
  beginning to `"./state.init.json"` and also all bug triggering states to
  `"./state.bug.json"`.

  
  
  
## Gotchas and False Alarms

Due to limitations of the current fuzzing harness there are several things that
do not work or will result in immediate false alarms.

* Hangs/timeouts are used to signal something unsupported was called.
* If your contract is intended to give out free ether, the fuzzing harness
  considers this a bug.
* Creating new contracts at runtime: this does not work due to the
  ahead-of-time compiled nature of the fuzzing harness.
* Creating new contracts in the constructor: this works.
  However, if the code of the newly created contract was not previously
  translated with evm2cpp the fuzzer will not use the code of the newly created
  contract, but will instead "replace" them with a simulated attacker
  contract... This often leads to unintended behavior in the main contract.
* The intended possibility to transfer ether via the contract. The fuzzing
  harness might report a potential bug if it is possible to transfer ether
  indirectly via the contract under test. *Update:* This problem is mitigated now by
  making `EVM_ALLOW_INDIRECT_ETHER_TRANSFERS=1` the default.
* Hardcoded payable addresses (e.g., in the constructor). Since the
  fuzzing harness does not know about this address it will assume it to be
  unknown and report many bugs if the contract attempts to send ether there.
  *Update* This problem is mitigated now because `EVM_IGNORE_LEAKING=1` is now
  the default.
* ~~Library or proxy contracts do not work (i.e., `DELEGATECALL`)~~ Library and
  proxy contracts work if you translate the code of all contracts and use the 
  state loading feature.


## Example Inputs

Let's take the `crowdsale` contract for example. We have the attack against the
crowdsale contract, which was generated by the fuzzer. We are using the
*ethmutator* utility functions here.

```
# first convert from the yaml to the binary representation
$ efuzzcasetranscoder fuzz/example_inputs/crowdsale_attack.yml \
    fuzz/example_inputs/crowdsale_attack.bin

# then we can use the analyzer to parse and analyse the input according to the
#crowdsale abi
$ efuzzcaseanalyzer -a fuzz/abi/crowdsale.abi \
    fuzz/example_inputs/crowdsale_attack.bin
    
# we can run this input with the fuzzing harness. First, we have to build 
# the crowdsale contract.
$ ./quick-build.sh afuzz crowdsale

# then we can launch the fuzzing harness for the crowdsale contract with the
# attack input
$ env EVM_DEBUG_PRINT=1 \
    ./fuzz/build/afuzz/crowdsale/fuzz_multitx \
    fuzz/example_inputs/crowdsale_attack.bin
```

