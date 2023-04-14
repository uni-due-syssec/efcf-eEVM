pragma solidity 0.7.6;

contract crowdsale {
    uint256 goal = 10000 * 10**18;
    uint256 raised = 0;
    uint256 public closeTime;
    address payable public owner;
    mapping(address => uint256) public deposits;

    uint256 public constant PHASE_ACTIVE = 0;
    uint256 public constant PHASE_SUCCESS = 1;
    uint256 public constant PHASE_REFUND = 2;
    uint256 public constant PHASE_STOPPED = 3;

    uint256 public phase;

    constructor() {
        closeTime = block.timestamp + 30 days;
        owner = msg.sender;
        phase = PHASE_ACTIVE;
    }

    function invest() public payable {
        require(block.timestamp < closeTime);
        require(phase == PHASE_ACTIVE && raised < goal);
        deposits[msg.sender] += msg.value;
        raised += msg.value;
    }

    function setPhase(uint256 newPhase) public {
        require(block.timestamp >= closeTime);
        require(
            (newPhase == PHASE_SUCCESS && raised >= goal) ||
            (newPhase == PHASE_REFUND && raised < goal) ||
            (newPhase == PHASE_STOPPED && raised == 0)
        );
        phase = newPhase;
    }

    function setOwner(address payable newOwner) public {
        // require(msg.sender == owner);
        owner = newOwner;
    }

    function withdraw() public {
        require(phase == PHASE_SUCCESS);
        owner.transfer(address(this).balance);
        phase = PHASE_STOPPED;
    }

    function refund() public {
        require(phase == PHASE_REFUND);
        uint256 amount = deposits[msg.sender];
        assert(raised >= amount);
        raised -= amount;
        msg.sender.transfer(amount);
        deposits[msg.sender] = 0;
    }

    function stop() public {
        require(block.timestamp >= closeTime && raised == 0);
        phase = PHASE_STOPPED;
    }

    function isActive() public view returns(bool) {
        return phase == PHASE_ACTIVE;
    }

    function echidna_oracle() public view returns (bool) {
        return !(owner == msg.sender && phase == PHASE_SUCCESS);
    }
}
