geth --exec admin.nodeInfo.enode attach /app/node/node | cut -d '"' -f 2 > node_enode
sed -i 's/127.0.0.1/node/g' node_enode
echo -n "addPeer result: "
geth --exec "admin.addPeer('$(cat node_enode)')" attach /app/validator/validator
echo -n "peerCount: "
geth --exec net.peerCount attach /app/node/node