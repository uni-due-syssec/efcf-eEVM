pragma solidity ^0.7;

// Originally published at: https://github.com/uni-due-syssec/eth-reentrancy-attack-patterns/blob/master/delegated.sol

// The Bank contract uses a dynamic library contract SafeSending, which
// handles parts of the business logic. In this case the SafeSending library is
// a minimalistic library that simply performs an external call.
//
// This obfuscates the unsafe use of CALL behind a DELEGATECALL instruction. In
// a more realistic scenario the library would implement something more
// sophisticated.

contract SafeSending {
    function send(address to, uint256 amount) public {
        // external call, control goes back to attacker
        to.call{value: amount}("");
    }
}

contract Bank {
    mapping (address => uint) public balances;
    address owner;
    SafeSending safesender;

    constructor(SafeSending _safesender) {
        owner = msg.sender;
        safesender = _safesender;
    }

    function updateSafeSender(SafeSending _new) public {
        if (msg.sender == owner) {
            safesender = _new;
        }
    }
    
    function getBalance(address who) public view returns(uint) {
        return balances[who];
    }

    function donate(address to) payable public {
        balances[to] += msg.value;
    }

    function withdraw(uint amount) public {
        if (balances[msg.sender] >= amount) {
            // instead of using send, transfer or call here, transfer is passed
            // to the library contract, which handles sending Ether.
            _libsend(msg.sender, amount);
            // state update after the DELEGATECALL
            balances[msg.sender] -= amount;
        }
    }

    function _libsend(address to, uint256 amount) internal {
        // call send function of the Library contract with DELEGATECALL
        address(safesender).delegatecall(abi.encodeWithSignature("send(address,uint256)", to, amount));
    }
}
