import { FastifyInstance } from "fastify"
import { BigNumber } from "ethers"
import hre from "hardhat"

type FaucetRequest = { address: string | undefined }

enum FaucetResultCodes {
    OK = "OK",
    UNCHANGED = "UNCHANGED",
    CHAIN_NOT_AVAILABLE = "CHAIN_NOT_AVAILABLE",
    TRANSACTION_FAILED = "TRANSACTION_FAILED",
    PENDING = "PENDING"
}

const pending: string[] = []

export function addRoute(server: FastifyInstance) {
    server.post("/faucet", async (req, rep) => {
        const { address } = req.body as FaucetRequest

        let faucet

        if (address) {
            try {
                const accounts = await hre.ethers.getSigners()
                faucet = accounts[0]
            }
            catch {
                return rep.status(200).send({ result: FaucetResultCodes.CHAIN_NOT_AVAILABLE })
            }

            let destBalance

            try {
                destBalance = await hre.ethers.provider.getBalance(address)
            }
            catch {
                return rep.status(200).send({ result: FaucetResultCodes.TRANSACTION_FAILED })
            }
            
            if (pending.includes(address)) {
                return rep.status(200).send({ result: FaucetResultCodes.PENDING })
            }

            const fiveEther = hre.ethers.utils.parseEther("5.0")

            if (BigNumber.from(fiveEther).gt(destBalance)) {
                let result = FaucetResultCodes.OK

                try {
                    pending.push(address)
                    const transaction = await faucet.sendTransaction({ to: address, value: fiveEther })
                    await transaction.wait()
                    console.log(`Faucet sent 5 HDY to ${address}`)
                }
                catch {
                    result = FaucetResultCodes.TRANSACTION_FAILED
                }
                pending.splice(pending.indexOf(address), 1)
                return rep.status(200).send({ result })
            }
            else {
                console.log(`No need to send HDY to ${address} because it already has ${hre.ethers.utils.formatEther(destBalance)} HDY`)
                return rep.status(200).send({ result: FaucetResultCodes.UNCHANGED })
            }
        }
        return rep.status(400).send()
    })
}