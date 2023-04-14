pragma solidity 0.8;


contract asserter {

    event AssertionFailed(string msg);
    event AssertionFailed(uint);
    event AssertionFailed();
    event RandomEvent();
    event Panic(uint256);

    function random_event() public {
        emit RandomEvent();
    }

    function panic_event() public {
        emit Panic(0x11);
    }

    function underflow(uint i) public returns(uint) {
        require(i != 0);
        uint x = 0;
        x = x - i;
        return x;
    }

    function builtin_assert(bool x) public returns(bool) {
        assert(false);
        return x;
    }

    function event_with_string(bool x) public {
        emit AssertionFailed("bar");
        revert();
    }
    
    function event_only(bool x) public {
        emit AssertionFailed();
        revert();
    }

    function event_with_code(bool x) public {
        emit AssertionFailed(0x42);
        revert();
    }
}
