import hre from "hardhat"
import { getContractAddress } from "@ethersproject/address"
import metadata from "./metadata.json"

export async function deploy() {
    try {
        const filesManagerDeployerFactory = await hre.ethers.getContractFactory("FilesManagerDeployer")
        const filesManagerDeployer = await filesManagerDeployerFactory.deploy()
        await filesManagerDeployer.deployed()

        const elsaTransaction = await filesManagerDeployer.createNewFileManagerFor("Elsa METEORA")
        const yugoTransaction = await filesManagerDeployer.createNewFileManagerFor("Yugo SUPERNOVA")
        const vivyTransaction = await filesManagerDeployer.createNewFileManagerFor("Vivy PULSAR")

        await elsaTransaction.wait()
        await yugoTransaction.wait()
        await vivyTransaction.wait()

        const filesManagerFactory = await hre.ethers.getContractFactory("FilesManager")

        for (const [i, links] of [metadata.xenoblade, metadata.anime, metadata.genshin].entries()) {
            const address = getContractAddress({
                from: filesManagerDeployer.address,
                nonce: i + 1
            })

            const contract = filesManagerFactory.attach(address)

            for (const link of links) {
                await contract.mintNewToken(link)
            }
        }

        return filesManagerDeployer.address
    }
    catch (err) {
        console.error(err)
        return null
    }
}

export const checkable = false