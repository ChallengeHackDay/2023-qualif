import fs from "fs"
import path from "path"
import { FastifyInstance } from "fastify"

type DeployRequest = { contractName: string | undefined }
type Challenge = { deploy: () => Promise<string | null> }
const challenges = fs.readdirSync(path.join(__dirname, "..", "contracts-logic")).map(file => file.split(".").slice(0, file.split(".").length - 1).join("."))

export function addRoute(server: FastifyInstance) {
    server.post("/deploy", async (req, rep) => {
        const { contractName } = req.body as DeployRequest

        if (contractName === undefined || !challenges.includes(contractName))
            return rep.status(400).send()

        if (req.session.get(contractName) !== undefined)
            return rep.status(200).send({ address: req.session.get(contractName) })
        
        const { deploy }: Challenge = await import(path.join(__dirname, "..", "contracts-logic", `${contractName}.js`))
        const address = await deploy()

        if (address) {
            req.session.set(contractName, address)
            return rep.status(200).send({ address })
        }
        else {
            return rep.status(503).send()
        }
    })
}