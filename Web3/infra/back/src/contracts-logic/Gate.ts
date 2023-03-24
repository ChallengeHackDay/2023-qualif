import hre from "hardhat"
import { Contract } from "ethers"

export async function check(contract: Contract) {
    try {
        const locked = await contract.gateLocked()
        return !locked;
    }
    catch {
        return false;
    }
}

export async function deploy() {
    try {
        const identityManagerFactory = await hre.ethers.getContractFactory("IdentityManager")
        const identityManager = await identityManagerFactory.deploy()
        await identityManager.deployed()
        
        const gateFactory = await hre.ethers.getContractFactory("Gate")
        const gate = await gateFactory.deploy(identityManager.address, [..."sh1ny st4rdu5t 1n th3 n1ght sk1es"].map(c => c.charCodeAt(0)))
        await gate.deployed()
        return gate.address    
    }
    catch (err) {
        console.error(err)
        return null
    }
}

export const checkable = true
export const flag = "The gate opens with a loud sound. On the panel behind it, is written the following: HACKDAY{w3lc0m3_t0_0ur_h34dqu4rt3rs_m4t3}"