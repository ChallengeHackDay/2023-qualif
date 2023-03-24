const { getContractAddress } = require("@ethersproject/address")

const deployerAddress = ""

for (let i = 1; i <= 3; i++) {
    const deployedAddress = getContractAddress({
        from: deployerAddress,
        nonce: i
    })

    console.log(`Contract number ${i} is deployed at ${deployedAddress}`)
}