import fs from "fs"
import path from "path"
import fastify from "fastify"
import cors from "@fastify/cors"
import session from "@fastify/session"
import cookie from "@fastify/cookie"
import hre from "hardhat"
import "@nomiclabs/hardhat-ethers"

async function main() {
    await hre.run("compile")
    const server = fastify()
    await server.register(cors, { origin: true, credentials: true })
    await server.register(cookie)
    await server.register(session, {
        secret: process.env.SESSION_SECRET as string,
        cookie: { secure: false }
    })

    for (const route of fs.readdirSync(path.join(__dirname, "routes"))) {
        const { addRoute } = await import(path.join(__dirname, "routes", route))
        addRoute(server)
    }

    server.listen({ host: "0.0.0.0", port: 8080 }, (err, address) => {
        if (err) {
            console.error(err)
            process.exit(1)
        }
        console.log(`Server listening at ${address}`)
    })
}

main()