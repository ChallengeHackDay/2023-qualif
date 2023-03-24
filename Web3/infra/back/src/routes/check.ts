import fs from "fs"
import path from "path"
import { FastifyInstance } from "fastify"
import hre from "hardhat"
import { Contract } from "ethers"

type DeployRequest = { contractName: string | undefined }
const challenges = fs.readdirSync(path.join(__dirname, "..", "contracts-logic")).map(file => file.split(".").slice(0, file.split(".").length - 1).join("."))

type Challenge = {
    check: ((contract: Contract) => Promise<boolean>) | undefined
    checkable: boolean
    flag: string | undefined
}

export function addRoute(server: FastifyInstance) {
    server.post("/check", async (req, rep) => {
        const { contractName } = req.body as DeployRequest

        if (contractName === undefined || !challenges.includes(contractName))
            return rep.status(400).send()

        if (req.session.get(contractName) === undefined)
            return rep.status(200).send({ locked: true })

        try {
            const signer = (await hre.ethers.getSigners())[0]
            const contract = await hre.ethers.getContractAt(contractName, req.session.get(contractName), signer)

            const { check, checkable, flag }: Challenge = await import(path.join(__dirname, "..", "contracts-logic", `${contractName}.js`))

            if (!checkable || !check || !flag) {
                return rep.status(400).send()
            }

            const flagged = await check(contract)

            return rep.status(200).send(flagged ? { locked: false, flag } : { locked: true })
        }
        catch (err) {
            console.error(err)
            return rep.status(500).send()
        }
    })
}