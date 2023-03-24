const identityManagerContract = `// SPDX-License-Identifier: Unlicensed

pragma solidity ^0.8.17;

// The following contract is vulnerable on purpose: DO NOT COPY AND USE IT ON MAINNET!
contract IdentityManager {
    mapping(address => string) private identities;
    mapping(address => bool) private privileged;

    constructor() {
        privileged[msg.sender] = true;
    }

    function setMyIdentity(string memory name) public {
        identities[msg.sender] = name;
    }

    function setIdentityFor(address addr, string memory name) public {
        requirePrivileges(msg.sender);
        identities[addr] = name;
    }

    function setPrivileged(address addr) public {
        requirePrivileges(msg.sender);
        privileged[addr] = true;
    }

    function requirePrivileges(address addr) public view {
        require(privileged[addr]);
    }

    function getIdentity(address id) public view returns(string memory) {
        return identities[id];
    }
}`

const gateContract = `// SPDX-License-Identifier: Unlicensed

pragma solidity ^0.8.17;

// The following contract is vulnerable on purpose: DO NOT COPY AND USE IT ON MAINNET!
contract Gate {
    address public idManager;
    uint8[] private password;
    bool public gateLocked = true;

    constructor(address _idManager, uint8[] memory _password) {
        idManager = _idManager;
        password = _password;
    }

    function letMeIn(string memory _password) public returns(string memory) {
        (bool success, bytes memory result) = idManager.call(abi.encodeWithSignature("getIdentity(address)", msg.sender));
        require(success);
        string memory name = abi.decode(result, (string));
        bytes memory passbytes = bytes(_password);

        // user must be registered with a name
        require(bytes(name).length > 0 && passbytes.length == password.length);

        // user must be privileged
        idManager.call(abi.encodeWithSignature("requirePrivileges(address)", msg.sender));
        
        // user must know our secret password
        for (uint256 i = 0; i < password.length; i++) {
            require(password[i] == uint8(passbytes[i]));
        }

        gateLocked = false;
        return string.concat("Welcome, ", name);
    }
}`

export const Gate = {
    name: "Gate",
    description: "As you arrive at the outpost, you find that the main entrance at the front is completely guarded, but as you walk around the area, you find a small hidden service door that leads straight into the outpost.\nOnly problem, this one is armored and doesn't seem to allow you to pass... Find your way in!",
    checkable: true,
    contracts: [identityManagerContract, gateContract],
}