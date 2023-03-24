# Web3 - Gate, Disclosure and Diamond

## Setup everything

First of all, you should add all of the following needed files.

In this folder, at the root of the project:
- a `validator_private_key.txt` should be filled with the hexadecimal private key of the validator node, it should be the private key associated to the public key of the account in the file `genesis.json`
- a `validator_password.txt` should contain a password that will be used to protect the validator wallet, it doesn't matter what it is but keep it secret and strong
- a `.env` should have the content `WS_SECRET=<SECRET>` where once again `<SECRET>` should be replaced with anything strong that will remain secret

And in the `back` folder:
- a `.env` with the following variables, with the `FAUCET_PRIVATE_KEY` that must be equal to the one in the `validator_private_key.txt` you filled just before and `SESSION_SECRET` that can be again anything as long as it's secret.
```
FAUCET_PRIVATE_KEY=<THE_KEY>
SESSION_SECRET=<SOME_SECRET>
```

Finally, the last thing you have to do is edit the file `config.json` in the `front` folder and put your server IP address or domain name in it instead of `localhost`.

## Start the containers

Just start everything with `sudo docker compose up -d`. It can take a minute to get everything started.

⚠️ **Important**: after starting everything with the previous command, run the command `docker compose logs linker` and make sure that the output is the following:

```
addPeer result: true
peerCount: 1
```

If you get anything else, a problem occured and you should restart the containers with `sudo docker compose up --force-recreate` until you get this output. The challenges will be broken if for example the peerCount is 0, because it would mean the node and the validator did not connect successfully.

Also, please check that the IPFS node is reachable by the public IPFS gateways. You can do so by trying to access this following URL : `https://ipfs.io/ipfs/QmZuQnZMQHSq4VKoz4bCPtfbWvTVB2NsM6cTD9PUTMvCtw`. If it displays the Hackday logo, then everything is fine and working as expected. Otherwise, if the page loads for a long time before timing out with a 504 error, it means there's an issue with the IPFS node that isn't accessible.

## Services exposed

4 services are exposed:

- the website used to read the challenges, deploy them and check them for the flag is accessible on port `80`
- the backend used by this website, that handles the interaction with the blockchain for the deployments, faucet, and all the stuff is available by default on port `8080`
- the JSON-RPC endpoint of the blockchain is by default on port `8545`
- the IPFS node hosting the metadata and images associated to the NFTs is by default on port `4001` and `4001/udp`
- the monitor service to see the state of the connected nodes and overall blockchain events is by default on port `33333`

If you wish to change any of these ports, feel free to edit the service `ports` mapping in the file `docker-compose.yml`. But please note that the JSON-RPC endpoint should better stay on port 8545 which is a default for JSON-RPC endpoints to avoid any issue, and that the IPFS node port mustn't be changed in order to be found by the other nodes of the IPFS network. Also, if you change the backend port, you must edit the `config.json` in the `front` folder as seen in the setup section to match the new port.