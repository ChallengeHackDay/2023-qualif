import { HardhatUserConfig } from "hardhat/config"
import "@nomicfoundation/hardhat-toolbox"
import "@nomiclabs/hardhat-ethers"
import dotenv from "dotenv"

dotenv.config()

if (process.env.FAUCET_PRIVATE_KEY === undefined) {
    throw new Error("Please set the `FAUCET_PRIVATE_KEY` variable in the `.env` file")
}

if (process.env.SESSION_SECRET === undefined) {
    throw new Error("Please set the `SESSION_SECRET` variable in the `.env` file")
}

require("@openzeppelin/hardhat-upgrades")

const config: HardhatUserConfig = {
    solidity: "0.8.17",
    networks: {
        hardhat: {},
        hackday: {
            url: "http://node:8545",
            chainId: 23,
            accounts: [process.env.FAUCET_PRIVATE_KEY]
        }
    },
    defaultNetwork: "hackday"
}

export default config