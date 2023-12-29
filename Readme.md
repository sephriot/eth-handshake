# eth-handshake

A really simple programme to demonstrate Ethereum node connection establishment.
Connection steps are:
1. Establish network connection with node e.g. TCP stream.
2. Exchange encryption keys
3. Exchange Hello message
4. Exchange Status message
After these 4 steps are executed successfully you can send and receive messages from Ethereum node such as [Geth](https://github.com/ethereum/go-ethereum).

## Testing

You can test whether this application works on your own.
Exemple steps to test are:
1. Download a blockchain node application. e.g. [Geth](https://github.com/ethereum/go-ethereum)
2. Run the node with high level of logs verbosity and disable nodes discovery (less noise in logs).
3. Example command for `geth` would be
```
./geth --mainnet --verbosity 5 --nodiscover
```
4. Copy `enode` connection string from node's logs
5. Run the `eth-handshake` app with connection string as first argument
e.g. 
```
./eth-handshake enode://63c310dd920adca1b8682a195557f8ca3ab824b49a9d977003d2c9efbbaec1d4bd3f838ae80676f6349eaea59e8f3db85544f4ecd1a550323f90b6ee55282a18@127.0.0.1:30303
```
6. Take a look at blockchain node logs to see that connection was established successfully
e.g.
```
TRACE[12-30|00:37:06.643] Accepted connection                      addr=127.0.0.1:41544 
DEBUG[12-30|00:37:06.648] Adding p2p peer                          peercount=1 id=25cf1736e8c2fac3 conn=inbound addr=127.0.0.1:41544 name=Geth/v1.13.8-unstabl...
TRACE[12-30|00:37:06.648] Starting protocol eth/68                 id=25cf1736e8c2fac3 conn=inbound
TRACE[12-30|00:37:06.648] Starting protocol snap/1                 id=25cf1736e8c2fac3 conn=inbound
DEBUG[12-30|00:37:06.650] Ethereum peer connected                  id=25cf1736e8c2fac3 conn=inbound name=Geth/v1.13.8-unstabl...
TRACE[12-30|00:37:06.650] Registering sync peer                    peer=25cf1736
```
