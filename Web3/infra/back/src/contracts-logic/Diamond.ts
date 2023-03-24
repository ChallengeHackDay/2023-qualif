import hre from "hardhat"
import { BigNumber, Contract } from "ethers"

export async function check(contract: Contract) {
    try {
        const balance = await contract.balanceOf(contract.address)
        return BigNumber.from(0).eq(balance)
    }
    catch {
        return false
    }
}

export async function deploy() {
    try {
        const factory = await hre.ethers.getContractFactory("Diamond")
        const contract = await factory.deploy()
        await contract.deployed()
        return contract.address    
    }
    catch (err) {
        console.log(err)
        return null
    }
}

export const checkable = true
export const flag = "Well done, the diamond corporation is currently running into an economic crisis. Here is your reward: HACKDAY{4ll_d14m0nds_succ3ssfully_st0l3n}"